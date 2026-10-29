import Foundation

// Mirrors of what `nebctl app ...` prints (snake_case keys).

struct AppState: Decodable {
    var nebctl: String
    var nebula: String?
    var host: HostSetup?
    var cert: CertInfo?
    var ca: String?
    var haveCa: Bool
    var pendingRequest: Bool
    var service: String
    var hostname: String
    var configDir: String
}

struct HostSetup: Decodable {
    var role: String
    var name: String
    var nebulaIp: String
    var lighthouses: [Lighthouse]?
    var inbound: [Rule]?
    var domain: String?
    var resolve: Bool?
}

struct CertInfo: Decodable {
    var name: String
    var networks: [String]
    var groups: [String]?
    var notAfter: String
    var daysLeft: Int

    var address: String { networks.joined(separator: ", ") }
    var expires: String { String(notAfter.prefix(10)) }
}

struct Inspected: Decodable {
    var cert: CertInfo
    var ca: String
    var lighthouses: [Lighthouse]?
    var domain: String?
    var key: String // included, waiting or file
}

struct Lighthouse: Codable, Identifiable, Hashable {
    var id = UUID()
    var name: String?
    var nebulaIp: String = ""
    var endpoints: [String] = []
    var relay: Bool? = true
    var dns: Bool? = false

    enum CodingKeys: String, CodingKey { case name, nebulaIp, endpoints, relay, dns }

    /// The editor shows one public address per lighthouse, as nebctl asks.
    var endpoint: String {
        get { endpoints.first ?? "" }
        set { endpoints = newValue.isEmpty ? [] : [newValue] + endpoints.dropFirst() }
    }

    var label: String {
        var roles: [String] = []
        if relay == true { roles.append("relay") }
        if dns == true { roles.append("DNS") }
        let s = nebulaIp + " at " + endpoints.joined(separator: ", ")
        return roles.isEmpty ? s : s + " (" + roles.joined(separator: ", ") + ")"
    }
}

struct Rule: Decodable, Hashable {
    var port: String
    var proto: String
    var host: String?
    var group: String?

    var label: String {
        var who = "any host"
        if let group, !group.isEmpty { who = "group " + group }
        else if let host, !host.isEmpty, host != "any" { who = host }
        return proto == "icmp" ? "ping from \(who)" : "\(proto)/\(port) from \(who)"
    }
}

/// The answers `nebctl app node` takes.
struct Plan: Encodable {
    struct Cert: Encodable {
        var source: String // keep, bundle or files
        var bundle: String?
        var ca: String?
        var crt: String?
        var key: String?
    }
    var cert: Cert
    var lighthouses: [Lighthouse]
    var firewall: String // keep, ping-ssh, ping or all
    var extraPorts: String
    var resolve: Bool
}
