import AppKit
import Foundation
import Observation

/// The node setup, step by step, as `sudo nebctl node` asks it: install
/// nebula, get a cert, the lighthouses, the firewall, DNS, then apply.
@MainActor @Observable
final class Setup {
    enum Step: Int, CaseIterable {
        case status, install, cert, lighthouses, firewall, dns, review, done
    }

    enum CertSource: String, CaseIterable, Identifiable {
        case keep, bundle, request, files
        var id: String { rawValue }
        var label: String {
            switch self {
            case .keep: "Keep it"
            case .bundle: "Paste a bundle made on the CA host (nebctl ca sign)"
            case .request: "Keep the private key here: make a request for the CA host to sign"
            case .files: "Import cert files I already have (ca.crt, this Mac's .crt and .key)"
            }
        }
    }

    enum Firewall: String, CaseIterable, Identifiable {
        case keep, pingSSH = "ping-ssh", ping, all
        var id: String { rawValue }
        var label: String {
            switch self {
            case .keep: "Keep these rules"
            case .pingSSH: "Ping and SSH (recommended)"
            case .ping: "Ping only"
            case .all: "Everything"
            }
        }
    }

    var step: Step = .status
    var state: AppState?
    var busy: String? // what is running, shown with a spinner
    var error: String?

    // Certificate
    var certSource: CertSource = .bundle
    var bundleText = ""
    var caPath = ""
    var crtPath = ""
    var keyPath = ""
    var requestName = ""
    var requestIP = ""
    var reuseKey = true
    var requestText = ""
    var inspected: Inspected?

    // Lighthouses, firewall, DNS
    var lighthouses: [Lighthouse] = []
    var fieldErrors: [String: String] = [:]
    var firewall: Firewall = .pingSSH
    var extraPorts = ""
    var resolve = true

    var log = ""

    // MARK: Status

    func refresh() async {
        await run("Reading this Mac's setup…") {
            self.state = try await Nebctl.state()
        }
    }

    func service(_ action: String) async {
        await run("Asking nebula to \(action)…") {
            _ = try await Nebctl.service(action)
            self.state = try await Nebctl.state()
        }
    }

    // MARK: Steps

    func start() {
        error = nil
        guard let state else { return }
        if let cert = state.cert, cert.daysLeft > 0 {
            certSource = .keep
        } else {
            certSource = .bundle
        }
        bundleText = ""
        requestText = ""
        inspected = nil
        reuseKey = true
        requestName = String(state.hostname.split(separator: ".").first ?? "").lowercased()
        firewall = (state.host?.inbound?.isEmpty == false) ? .keep : .pingSSH
        extraPorts = ""
        resolve = state.host?.resolve ?? true
        step = state.nebula == nil ? .install : .cert
    }

    func installNebula() async {
        await run("Installing nebula…") {
            self.log = try await Nebctl.install()
            self.state = try await Nebctl.state()
            self.step = .cert
        }
    }

    func makeRequest() async {
        await run("Making this Mac's key and request…") {
            self.requestText = try await Nebctl.request(
                name: self.requestName.trimmingCharacters(in: .whitespaces),
                ip: self.requestIP.trimmingCharacters(in: .whitespaces),
                newKey: !self.reuseKey)
            self.state = try await Nebctl.state()
        }
    }

    /// Checks the cert's source and moves on to the lighthouses.
    func certNext() async {
        await run("Checking the cert…") {
            switch self.certSource {
            case .keep:
                self.inspected = nil
            case .bundle, .request:
                self.inspected = try await Nebctl.inspect(bundle: self.bundleText)
            case .files:
                self.inspected = try await Nebctl.inspect(ca: self.caPath, crt: self.crtPath, key: self.keyPath)
            }
            // As nebctl does: the bundle's lighthouses, else the ones set up before.
            if let from = self.inspected?.lighthouses, !from.isEmpty {
                self.lighthouses = from
            } else if let before = self.state?.host?.lighthouses, !before.isEmpty {
                self.lighthouses = before
            } else if self.lighthouses.isEmpty {
                self.lighthouses = [Lighthouse()]
            }
            self.fieldErrors = [:]
            self.step = .lighthouses
        }
    }

    func lighthousesNext() async {
        await checkThen(prefix: "lighthouses") { self.step = .firewall }
    }

    func firewallNext() async {
        await checkThen(prefix: "extra_ports") {
            self.step = self.dnsServers.isEmpty || self.domain == nil ? .review : .dns
        }
    }

    func apply() async {
        await run("Setting up nebula…") {
            self.log = try await Nebctl.apply(self.plan)
            self.state = try await Nebctl.state()
            self.step = .done
        }
    }

    func back() {
        error = nil
        switch step {
        case .install, .cert: step = .status
        case .lighthouses: step = .cert
        case .firewall: step = .lighthouses
        case .dns: step = .firewall
        case .review: step = dnsServers.isEmpty || domain == nil ? .firewall : .dns
        case .status, .done: step = .status
        }
    }

    // MARK: Derived

    var plan: Plan {
        var cert = Plan.Cert(source: certSource.rawValue)
        switch certSource {
        case .keep: break
        case .bundle, .request:
            cert.source = "bundle"
            cert.bundle = bundleText
        case .files:
            cert.ca = caPath
            cert.crt = crtPath
            cert.key = keyPath
        }
        return Plan(cert: cert, lighthouses: lighthouses, firewall: firewall.rawValue,
                    extraPorts: firewall == .all || firewall == .keep ? "" : extraPorts,
                    resolve: resolve && domain != nil && !dnsServers.isEmpty)
    }

    /// The network's Nebula-only domain, from the bundle or the setup before.
    var domain: String? {
        let d = inspected?.domain ?? (certSource == .keep ? state?.host?.domain : nil) ?? state?.host?.domain
        return (d?.isEmpty ?? true) ? nil : d
    }

    var dnsServers: [String] { lighthouses.filter { $0.dns == true }.map(\.nebulaIp) }

    /// The cert this Mac will have once applied.
    var newCert: CertInfo? { inspected?.cert ?? (certSource == .keep ? state?.cert : nil) }

    var currentRules: [Rule] { state?.host?.inbound ?? [] }

    // MARK: Helpers

    private func checkThen(prefix: String, _ next: @escaping () -> Void) async {
        await run("Checking…") {
            let errs = try await Nebctl.check(self.plan).filter { $0.key.hasPrefix(prefix) }
            self.fieldErrors = errs
            if errs.isEmpty { next() }
        }
    }

    private func run(_ what: String, _ body: @escaping () async throws -> Void) async {
        busy = what
        error = nil
        defer { busy = nil }
        do {
            try await body()
        } catch {
            self.error = error.localizedDescription
        }
    }

    static func chooseFile(_ title: String) -> String? {
        let p = NSOpenPanel()
        p.title = title
        p.canChooseFiles = true
        p.canChooseDirectories = false
        p.allowsMultipleSelection = false
        p.showsHiddenFiles = true
        return p.runModal() == .OK ? p.url?.path : nil
    }

    static func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}
