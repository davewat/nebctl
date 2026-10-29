import Foundation

struct NebctlError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

/// Runs the nebctl inside the app. Reads run as the user; changes run as
/// root through macOS's administrator password prompt.
enum Nebctl {
    /// The bundled nebctl; NEBCTL_BIN overrides it while developing.
    static var binary: String {
        if let p = ProcessInfo.processInfo.environment["NEBCTL_BIN"] { return p }
        return Bundle.main.url(forResource: "nebctl", withExtension: nil)?.path ?? "/usr/local/bin/nebctl"
    }

    /// With NEBCTL_ROOT set, nebctl works under that directory and needs
    /// no admin rights: for trying the app without touching this Mac.
    static var testRoot: String? { ProcessInfo.processInfo.environment["NEBCTL_ROOT"] }

    static func run(_ args: [String], stdin: String? = nil) async throws -> String {
        try await Task.detached {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: binary)
            p.arguments = args
            let out = Pipe(), err = Pipe(), inp = Pipe()
            p.standardOutput = out
            p.standardError = err
            p.standardInput = inp
            try p.run()
            if let stdin { inp.fileHandleForWriting.write(Data(stdin.utf8)) }
            try? inp.fileHandleForWriting.close()
            // Read both pipes at once so neither fills and stalls nebctl.
            let errTask = Task.detached { err.fileHandleForReading.readDataToEndOfFile() }
            let outData = out.fileHandleForReading.readDataToEndOfFile()
            let errData = await errTask.value
            p.waitUntilExit()
            if p.terminationStatus != 0 {
                throw NebctlError(message: clean(String(decoding: errData, as: UTF8.self)))
            }
            return String(decoding: outData, as: UTF8.self)
        }.value
    }

    private static let adminQueue = DispatchQueue(label: "net.nebctl.node.admin")

    /// Runs nebctl as root. macOS asks for an administrator's password, and
    /// doesn't ask again for a few minutes.
    static func runAsAdmin(_ args: [String], why: String) async throws -> String {
        if testRoot != nil { return try await run(args) }
        return try await shellAsAdmin(([binary] + args).map(shellQuote).joined(separator: " "), why: why)
    }

    /// Runs a shell command line as root, through the password prompt.
    private static func shellAsAdmin(_ cmd: String, why: String) async throws -> String {
        let source = "do shell script \"\(escape(cmd))\" with prompt \"\(escape(why))\" with administrator privileges without altering line endings"
        return try await withCheckedThrowingContinuation { cont in
            adminQueue.async {
                var info: NSDictionary?
                let result = NSAppleScript(source: source)?.executeAndReturnError(&info)
                if let info {
                    if (info[NSAppleScript.errorNumber] as? Int) == -128 {
                        cont.resume(throwing: NebctlError(message: "Cancelled: nothing was changed."))
                    } else {
                        let msg = info[NSAppleScript.errorMessage] as? String ?? "nebctl failed"
                        cont.resume(throwing: NebctlError(message: clean(msg)))
                    }
                    return
                }
                cont.resume(returning: result?.stringValue ?? "")
            }
        }
    }

    static func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return try d.decode(type, from: Data(json.utf8))
    }

    // MARK: The commands the app uses

    static func state() async throws -> AppState {
        try decode(AppState.self, try await run(["app", "state"]))
    }

    static func inspect(bundle: String) async throws -> Inspected {
        try decode(Inspected.self, try await run(["app", "inspect", "-in", "-"], stdin: bundle))
    }

    static func inspect(ca: String, crt: String, key: String) async throws -> Inspected {
        try decode(Inspected.self, try await run(["app", "inspect", "-ca", ca, "-crt", crt, "-key", key]))
    }

    /// What is wrong with the plan, by field (see `nebctl app check`).
    static func check(_ plan: Plan) async throws -> [String: String] {
        try await withPlanFile(plan) { path in
            struct Result: Decodable { var errors: [String: String] }
            // Plain keys: the field names are the answer here.
            return try JSONDecoder().decode(Result.self, from: Data(try await run(["app", "check", "-in", path]).utf8)).errors
        }
    }

    static func install() async throws -> String {
        try await runAsAdmin(["install"], why: "Nebula Node wants to install nebula into /usr/local/bin.")
    }

    static func request(name: String, ip: String, newKey: Bool) async throws -> String {
        var args = ["app", "request", "-name", name, "-ip", ip]
        if newKey { args.append("-new") }
        struct Result: Decodable { var request: String }
        let out = try await runAsAdmin(args, why: "Nebula Node wants to make this Mac's Nebula key in /etc/nebula.")
        return try decode(Result.self, out).request
    }

    static func apply(_ plan: Plan) async throws -> String {
        try await withPlanFile(plan) { path in
            try await runAsAdmin(["app", "node", "-in", path], why: "Nebula Node wants to set up nebula on this Mac.")
        }
    }

    /// Starts `nebctl web` as root in the background, stopping when this app
    /// quits, and returns its one-time link for the console window.
    static func startConsole() async throws -> URL {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("nebctl-console-\(UUID().uuidString).url")
        let args = ["web", "-no-open", "-port", "0", "-url-file", file.path,
                    "-url-owner", String(getuid()), "-parent-pid", String(getpid())]
        if testRoot != nil {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: binary)
            p.arguments = args
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            try p.run()
        } else {
            // Output to /dev/null so the prompt's shell returns while the console runs on.
            let cmd = ([binary] + args).map(shellQuote).joined(separator: " ") + " >/dev/null 2>&1 &"
            _ = try await shellAsAdmin(cmd, why: "Nebula Node wants to start the admin console. It runs nebctl as root and answers only on this Mac.")
        }
        for _ in 0..<60 {
            if let text = try? String(contentsOf: file, encoding: .utf8),
               let url = URL(string: text.trimmingCharacters(in: .whitespacesAndNewlines) + "&embedded=1") {
                try? FileManager.default.removeItem(at: file)
                return url
            }
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        throw NebctlError(message: "The admin console didn't start within 15 seconds.")
    }

    /// Asks a running console to stop, with the session the window signed in with.
    static func stopConsole(at url: URL, cookies: [HTTPCookie]) {
        guard let session = cookies.first(where: { $0.name == "nebctl_session" }),
              var parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return }
        parts.path = "/api/quit"
        parts.query = nil
        guard let quit = parts.url else { return }
        var req = URLRequest(url: quit)
        req.httpMethod = "POST"
        req.setValue("1", forHTTPHeaderField: "X-Nebctl")
        req.setValue("nebctl_session=\(session.value)", forHTTPHeaderField: "Cookie")
        URLSession.shared.dataTask(with: req).resume()
    }

    static func service(_ action: String) async throws -> String {
        try await runAsAdmin(["service", action], why: "Nebula Node wants to \(action) nebula.")
    }

    /// The plan can hold a private key: it goes in a file only this user
    /// (and root) can read, removed straight after.
    private static func withPlanFile<T>(_ plan: Plan, _ body: (String) async throws -> T) async throws -> T {
        let e = JSONEncoder()
        e.keyEncodingStrategy = .convertToSnakeCase
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("nebctl-plan-\(UUID().uuidString).json")
        FileManager.default.createFile(atPath: url.path, contents: try e.encode(plan), attributes: [.posixPermissions: 0o600])
        defer { try? FileManager.default.removeItem(at: url) }
        return try await body(url.path)
    }

    private static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }

    private static func clean(_ s: String) -> String {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.hasPrefix("error: ") ? String(t.dropFirst(7)) : t
    }
}
