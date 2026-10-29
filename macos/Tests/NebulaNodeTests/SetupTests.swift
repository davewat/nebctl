import Foundation
import Testing
@testable import NebulaNode

/// Walks the wizard the way a person would, against a real nebctl working
/// under a scratch root (NEBCTL_ROOT), so nothing on this Mac changes.
/// Needs Go, and nebula and nebula-cert in /usr/local/bin to copy from.
@MainActor @Suite(.serialized) // each test points NEBCTL_ROOT, process-wide, at its own root
struct SetupTests {
    let root: URL
    let certs: URL

    init() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("nebnode-\(UUID().uuidString)")
        root = tmp.appendingPathComponent("root")
        certs = tmp.appendingPathComponent("certs")
        let bin = root.appendingPathComponent("usr/local/bin")
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: certs, withIntermediateDirectories: true)
        for tool in ["nebula", "nebula-cert"] {
            try FileManager.default.copyItem(atPath: "/usr/local/bin/\(tool)", toPath: bin.appendingPathComponent(tool).path)
        }
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let nebctl = tmp.appendingPathComponent("nebctl").path
        try sh("/usr/bin/env", ["go", "build", "-o", nebctl, "."], in: repo)
        let cert = bin.appendingPathComponent("nebula-cert").path
        try sh(cert, ["ca", "-name", "test", "-out-crt", "ca.crt", "-out-key", "ca.key"], in: certs)
        try sh(cert, ["sign", "-ca-crt", "ca.crt", "-ca-key", "ca.key", "-name", "mac01.nebula.example.com",
                      "-networks", "10.42.0.5/24", "-out-crt", "mac01.crt", "-out-key", "mac01.key"], in: certs)
        setenv("NEBCTL_BIN", nebctl, 1)
        setenv("NEBCTL_ROOT", root.path, 1)
    }

    @Test func nodeFromCertFiles() async throws {
        let s = Setup()
        await s.refresh()
        #expect(s.error == nil)
        #expect(s.state?.host == nil)
        s.start()
        #expect(s.step == .cert) // nebula is already in the root

        s.certSource = .files
        s.caPath = certs.appendingPathComponent("ca.crt").path
        s.crtPath = certs.appendingPathComponent("mac01.crt").path
        s.keyPath = certs.appendingPathComponent("ca.key").path // the wrong key
        await s.certNext()
        #expect(s.error?.contains("does not belong") == true)
        #expect(s.step == .cert)

        s.keyPath = certs.appendingPathComponent("mac01.key").path
        await s.certNext()
        #expect(s.error == nil)
        #expect(s.step == .lighthouses)
        #expect(s.newCert?.name == "mac01.nebula.example.com")
        #expect(s.lighthouses.count == 1) // one blank to fill in

        s.lighthouses[0].nebulaIp = "10.42.0"
        await s.lighthousesNext()
        #expect(s.fieldErrors["lighthouses.0.nebula_ip"] != nil)
        #expect(s.fieldErrors["lighthouses.0.endpoints"] != nil)
        #expect(s.step == .lighthouses)

        s.lighthouses[0].nebulaIp = "10.42.0.1"
        s.lighthouses[0].endpoint = "lh.example.com"
        s.lighthouses[0].dns = true
        await s.lighthousesNext()
        #expect(s.step == .firewall)

        s.firewall = .pingSSH
        s.extraPorts = "tcp/x"
        await s.firewallNext()
        #expect(s.fieldErrors["extra_ports"] != nil)
        s.extraPorts = "tcp/443"
        await s.firewallNext()
        // Files carry no domain, so there is no DNS question.
        #expect(s.step == .review)

        await s.apply()
        #expect(s.error == nil)
        #expect(s.step == .done)
        #expect(s.log.contains("Try it: ping 10.42.0.1"))
        let h = try #require(s.state?.host)
        #expect(h.name == "mac01.nebula.example.com")
        #expect(h.lighthouses?.first?.endpoints == ["lh.example.com:4242"])
        #expect(h.inbound?.map(\.label) == ["ping from any host", "tcp/22 from any host", "tcp/443 from any host"])

        // Changing the setup keeps the cert and rules by default.
        s.start()
        #expect(s.certSource == .keep)
        #expect(s.firewall == .keep)
        await s.certNext()
        #expect(s.lighthouses.map(\.nebulaIp) == ["10.42.0.1"])
    }

    @Test func nodeFromBundleWithDNS() async throws {
        let s = Setup()
        await s.refresh()
        s.start()
        s.certSource = .bundle
        s.bundleText = try bundle(domain: "nebula.example.com", lighthouse: [
            "name": "lh.nebula.example.com", "nebula_ip": "10.42.0.1",
            "endpoints": ["203.0.113.9:4242"], "relay": true, "dns": true,
        ])
        await s.certNext()
        #expect(s.error == nil)
        #expect(s.inspected?.key == "included")
        #expect(s.lighthouses.map(\.label) == ["10.42.0.1 at 203.0.113.9:4242 (relay, DNS)"])
        await s.lighthousesNext()
        await s.firewallNext()
        #expect(s.step == .dns)
        #expect(s.domain == "nebula.example.com")
        #expect(s.dnsServers == ["10.42.0.1"])
        s.step = .review
        await s.apply()
        #expect(s.error == nil)
        #expect(s.state?.host?.resolve == true)
        let resolver = try String(contentsOf: root.appendingPathComponent("etc/resolver/nebula.example.com"), encoding: .utf8)
        #expect(resolver.contains("nameserver 10.42.0.1"))
    }

    @Test func request() async throws {
        let s = Setup()
        await s.refresh()
        s.start()
        s.certSource = .request
        s.requestName = "mac02"
        await s.makeRequest()
        #expect(s.error == nil)
        #expect(s.requestText.hasPrefix("-----BEGIN NEBCTL REQUEST-----"))
        #expect(s.state?.pendingRequest == true)
    }

    @Test func consoleStartsAndStops() async throws {
        let url = try await Nebctl.startConsole()
        #expect(url.host == "127.0.0.1")
        #expect(url.query?.contains("embedded=1") == true)

        // The link signs in once and lands on the console page.
        let cfg = URLSessionConfiguration.ephemeral
        let jar = try #require(cfg.httpCookieStorage)
        let session = URLSession(configuration: cfg)
        let (data, resp) = try await session.data(from: url)
        #expect((resp as? HTTPURLResponse)?.statusCode == 200)
        #expect(String(decoding: data, as: UTF8.self).contains("<html"))
        let cookies = jar.cookies(for: url) ?? []
        #expect(cookies.contains { $0.name == "nebctl_session" })

        Nebctl.stopConsole(at: url, cookies: cookies)
        var stopped = false
        for _ in 0..<20 {
            try await Task.sleep(nanoseconds: 250_000_000)
            if (try? await URLSession(configuration: .ephemeral).data(from: url)) == nil { stopped = true; break }
        }
        #expect(stopped)
    }

    /// A bundle as `nebctl ca sign` prints it: gzipped JSON, base64, armoured.
    private func bundle(domain: String, lighthouse: [String: Any]) throws -> String {
        func read(_ f: String) throws -> String { try String(contentsOf: certs.appendingPathComponent(f), encoding: .utf8) }
        let json = try JSONSerialization.data(withJSONObject: [
            "v": 1, "name": "mac01.nebula.example.com", "ca_crt": try read("ca.crt"),
            "host_crt": try read("mac01.crt"), "host_key": try read("mac01.key"),
            "lighthouses": [lighthouse], "domain": domain,
        ] as [String: Any])
        let raw = certs.appendingPathComponent("bundle.json")
        try json.write(to: raw)
        try sh("/usr/bin/gzip", ["-f", "bundle.json"], in: certs)
        let gz = try Data(contentsOf: certs.appendingPathComponent("bundle.json.gz"))
        return "-----BEGIN NEBCTL BUNDLE-----\n" + gz.base64EncodedString(options: .lineLength64Characters)
            + "\n-----END NEBCTL BUNDLE-----\n"
    }

    @discardableResult
    private func sh(_ exe: String, _ args: [String], in dir: URL) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = args
        p.currentDirectoryURL = dir
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let text = String(decoding: data, as: UTF8.self)
        if p.terminationStatus != 0 { throw NebctlError(message: "\(exe) \(args): \(text)") }
        return text
    }
}
