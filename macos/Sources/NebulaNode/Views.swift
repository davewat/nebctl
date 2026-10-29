import SwiftUI

struct ContentView: View {
    @Bindable var setup: Setup

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    page
                    if let error = setup.error {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .textSelection(.enabled)
                    }
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            footer.padding(16)
        }
        .frame(minWidth: 620, minHeight: 560)
        .disabled(setup.busy != nil)
        .task { await setup.refresh() }
    }

    @ViewBuilder private var page: some View {
        switch setup.step {
        case .status: StatusPage(setup: setup)
        case .install: InstallPage(setup: setup)
        case .cert: CertPage(setup: setup)
        case .lighthouses: LighthousesPage(setup: setup)
        case .firewall: FirewallPage(setup: setup)
        case .dns: DNSPage(setup: setup)
        case .review: ReviewPage(setup: setup)
        case .done: DonePage(setup: setup)
        }
    }

    private var footer: some View {
        HStack {
            if let busy = setup.busy {
                ProgressView().controlSize(.small)
                Text(busy).foregroundStyle(.secondary)
            }
            Spacer()
            if setup.step != .status && setup.step != .done {
                Button("Back") { setup.back() }
            }
            next
        }
    }

    @ViewBuilder private var next: some View {
        switch setup.step {
        case .status:
            Button(setup.state?.host == nil ? "Set Up This Mac as a Node…" : "Change Setup…") { setup.start() }
                .keyboardShortcut(.defaultAction)
                .disabled(setup.state == nil)
        case .install:
            Button("Install Nebula") { Task { await setup.installNebula() } }
                .keyboardShortcut(.defaultAction)
        case .cert:
            Button("Continue") { Task { await setup.certNext() } }
                .keyboardShortcut(.defaultAction)
                .disabled(!certReady)
        case .lighthouses:
            Button("Continue") { Task { await setup.lighthousesNext() } }
                .keyboardShortcut(.defaultAction)
        case .firewall:
            Button("Continue") { Task { await setup.firewallNext() } }
                .keyboardShortcut(.defaultAction)
        case .dns:
            Button("Continue") { setup.step = .review }
                .keyboardShortcut(.defaultAction)
        case .review:
            Button("Set Up Nebula") { Task { await setup.apply() } }
                .keyboardShortcut(.defaultAction)
        case .done:
            Button("Done") { setup.step = .status }
                .keyboardShortcut(.defaultAction)
        }
    }

    private var certReady: Bool {
        switch setup.certSource {
        case .keep: setup.state?.cert != nil
        case .bundle: !setup.bundleText.isEmpty
        case .request: !setup.requestText.isEmpty && !setup.bundleText.isEmpty
        case .files: !setup.caPath.isEmpty && !setup.crtPath.isEmpty && !setup.keyPath.isEmpty
        }
    }
}

// MARK: - Pages

struct PageTitle: View {
    let title: String
    let subtitle: String
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.title2.bold())
            Text(LocalizedStringKey(subtitle)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
}

struct Row: View {
    let label: String
    let value: String
    var body: some View {
        GridRow {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            Text(value).textSelection(.enabled)
        }
    }
}

struct StatusPage: View {
    let setup: Setup
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        PageTitle(title: "Nebula on this Mac",
                  subtitle: "Join this Mac to a Nebula network as a node, the same way `sudo nebctl node` does.")
        if let s = setup.state {
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                Row(label: "Nebula", value: s.nebula.map { "\($0) in /usr/local/bin" } ?? "not installed")
                if let h = s.host {
                    Row(label: "This Mac", value: "\(h.role) \(h.name), \(h.nebulaIp)")
                    ForEach(Array((h.lighthouses ?? []).enumerated()), id: \.offset) { i, l in
                        Row(label: i == 0 ? "Lighthouses" : "", value: l.label)
                    }
                    Row(label: "Inbound", value: (h.inbound ?? []).map(\.label).joined(separator: "; "))
                    if let d = h.domain, !d.isEmpty {
                        Row(label: "Names", value: h.resolve == true ? "*.\(d) looked up over Nebula" : "*.\(d) not looked up here")
                    }
                } else {
                    Row(label: "This Mac", value: "not set up yet")
                }
                if let c = s.cert {
                    Row(label: "Cert", value: "\(c.name), expires \(c.expires)" + (c.daysLeft < 30 ? " (\(c.daysLeft) days left: renew it)" : ""))
                }
                if let ca = s.ca { Row(label: "CA", value: ca) }
                Row(label: "Service", value: s.service)
            }
            if s.host?.role == "lighthouse" {
                Text("This Mac is a lighthouse. Setting it up as a node makes it check in with another lighthouse instead.")
                    .foregroundStyle(.secondary)
            }
            if s.host != nil {
                HStack {
                    Button("Start") { Task { await setup.service("start") } }
                    Button("Stop") { Task { await setup.service("stop") } }
                    Button("Restart") { Task { await setup.service("restart") } }
                    Button("Refresh") { Task { await setup.refresh() } }
                }
            }
            if s.host != nil {
                Divider().padding(.vertical, 4)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Admin console").font(.headline)
                    Text("See who's connected, sign and revoke certs, change the firewall and logging, and manage the lighthouse over SSH.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Open Admin Console") {
                        Task { await setup.openConsole { openWindow(id: "console") } }
                    }
                }
            }
            if Nebctl.testRoot != nil {
                Text("Test mode: nebctl works under \(Nebctl.testRoot!) (NEBCTL_ROOT), not on this Mac.")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
    }
}

struct InstallPage: View {
    let setup: Setup
    var body: some View {
        PageTitle(title: "Install Nebula",
                  subtitle: "Nebula isn't installed in /usr/local/bin. This downloads the latest release from github.com/slackhq/nebula and checks it against the release's checksums. macOS asks for an administrator's password.")
        if !setup.log.isEmpty { LogView(text: setup.log) }
    }
}

struct CertPage: View {
    @Bindable var setup: Setup

    var body: some View {
        PageTitle(title: "Certificate",
                  subtitle: "Every Nebula host has a cert signed by the network's CA. It holds this Mac's name and Nebula address.")
        if let c = setup.state?.cert {
            Text("This Mac has a cert for **\(c.name)** (\(c.address)), valid until \(c.expires).")
        }
        Picker("How should this Mac get its certificate?", selection: $setup.certSource) {
            ForEach(Setup.CertSource.allCases.filter { $0 != .keep || setup.state?.cert != nil }) {
                Text($0.label).tag($0)
            }
        }
        .pickerStyle(.radioGroup)
        if setup.state?.haveCa == true {
            Text("This Mac holds the CA. To sign its own cert with it, run `sudo nebctl node` in Terminal.")
                .font(.callout).foregroundStyle(.secondary)
        }

        switch setup.certSource {
        case .keep:
            EmptyView()
        case .bundle:
            if setup.state?.pendingRequest == true {
                Text("A key from an earlier request is waiting here, so a bundle answering it works too.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            PasteField(title: "On the CA host run `sudo nebctl ca sign`, then paste the bundle, from its BEGIN line to its END line:",
                       text: $setup.bundleText)
        case .request:
            RequestSection(setup: setup)
        case .files:
            FilePicker(title: "CA cert (ca.crt)", path: $setup.caPath)
            FilePicker(title: "This Mac's cert (.crt)", path: $setup.crtPath)
            FilePicker(title: "This Mac's key (.key)", path: $setup.keyPath)
        }
    }
}

struct RequestSection: View {
    @Bindable var setup: Setup

    var body: some View {
        Form {
            TextField("Name for this Mac's cert", text: $setup.requestName)
            TextField("Nebula address you want", text: $setup.requestIP, prompt: Text("blank lets the CA host choose"))
            if setup.state?.pendingRequest == true {
                Toggle("Reuse the key from an earlier request", isOn: $setup.reuseKey)
            }
        }
        Button(setup.requestText.isEmpty ? "Make Request" : "Make It Again") { Task { await setup.makeRequest() } }
            .disabled(setup.requestName.isEmpty)
        if !setup.requestText.isEmpty {
            Text("On the CA host run `sudo nebctl ca sign-request` and paste this. It holds no secrets, so chat or email is fine. The private key stays in /etc/nebula/pending.key.")
                .fixedSize(horizontal: false, vertical: true)
            LogView(text: setup.requestText)
            Button("Copy Request") { Setup.copy(setup.requestText) }
            PasteField(title: "Paste the bundle the CA host gives back:", text: $setup.bundleText)
        }
    }
}

struct LighthousesPage: View {
    @Bindable var setup: Setup

    var body: some View {
        PageTitle(title: "Lighthouses",
                  subtitle: "This Mac checks in with these to find the other hosts.")
        if let c = setup.newCert {
            Text("The cert is for **\(c.name)** (\(c.address)), valid until \(c.expires)" + (setup.inspected.map { ", signed by \($0.ca)." } ?? "."))
        }
        if let e = setup.fieldErrors["lighthouses"] { FieldError(text: e) }
        ForEach($setup.lighthouses) { $l in
            let i = setup.lighthouses.firstIndex(where: { $0.id == l.id }) ?? 0
            GroupBox {
                Form {
                    if let name = l.name, !name.isEmpty { LabeledContent("Name", value: name) }
                    TextField("Nebula address", text: $l.nebulaIp, prompt: Text("e.g. 10.42.0.1"))
                    if let e = setup.fieldErrors["lighthouses.\(i).nebula_ip"] { FieldError(text: e) }
                    TextField("Public IP or DNS name", text: $l.endpoint, prompt: Text("host or host:port (port 4242 if left off)"))
                    if let e = setup.fieldErrors["lighthouses.\(i).endpoints"] { FieldError(text: e) }
                    Toggle("Relays for hosts that can't connect directly", isOn: Binding($l.relay, false))
                    Toggle("Answers DNS for Nebula host names", isOn: Binding($l.dns, false))
                }
                HStack {
                    Spacer()
                    Button("Remove", role: .destructive) { setup.lighthouses.removeAll { $0.id == l.id } }
                }
            }
        }
        Button("Add Lighthouse") { setup.lighthouses.append(Lighthouse()) }
    }
}

struct FirewallPage: View {
    @Bindable var setup: Setup

    var body: some View {
        PageTitle(title: "Firewall",
                  subtitle: "What may other Nebula hosts reach on this Mac? This is Nebula's own firewall; it doesn't change macOS's.")
        if !setup.currentRules.isEmpty {
            Text("Now: " + setup.currentRules.map(\.label).joined(separator: "; "))
        }
        Picker("Allow", selection: $setup.firewall) {
            ForEach(Setup.Firewall.allCases.filter { $0 != .keep || !setup.currentRules.isEmpty }) {
                Text($0.label).tag($0)
            }
        }
        .pickerStyle(.radioGroup)
        if setup.firewall == .pingSSH || setup.firewall == .ping {
            TextField("Other ports to open", text: $setup.extraPorts, prompt: Text("e.g. tcp/443, udp/53, tcp/8000-8100 (blank for none)"))
            if let e = setup.fieldErrors["extra_ports"] { FieldError(text: e) }
        }
        if setup.firewall == .all {
            Text("Any Nebula host can then reach every port here.").foregroundStyle(.orange)
        }
    }
}

struct DNSPage: View {
    @Bindable var setup: Setup

    var body: some View {
        PageTitle(title: "Names over Nebula",
                  subtitle: "Find Nebula hosts by name, e.g. ssh fe01.\(setup.domain ?? ""). Only names under that domain go to the lighthouses; every other lookup works as before.")
        Toggle("Look up *.\(setup.domain ?? "") through \(setup.dnsServers.joined(separator: ", "))", isOn: $setup.resolve)
    }
}

struct ReviewPage: View {
    let setup: Setup

    var body: some View {
        PageTitle(title: "Ready to Set Up",
                  subtitle: "nebctl checks the config with `nebula -test` before using it, then starts nebula at boot. macOS asks for an administrator's password.")
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
            if let c = setup.newCert {
                Row(label: "Cert", value: "\(c.name), \(c.address), until \(c.expires)")
            } else {
                Row(label: "Cert", value: "from the files you chose")
            }
            ForEach(Array(setup.lighthouses.enumerated()), id: \.offset) { i, l in
                Row(label: i == 0 ? "Lighthouses" : "", value: l.label)
            }
            Row(label: "Inbound", value: inbound)
            if let d = setup.domain {
                Row(label: "Names", value: setup.plan.resolve ? "*.\(d) through \(setup.dnsServers.joined(separator: ", "))" : "*.\(d) not looked up here")
            }
        }
    }

    private var inbound: String {
        switch setup.firewall {
        case .keep: return setup.currentRules.map(\.label).joined(separator: "; ")
        case .all: return "everything from any host"
        case .pingSSH, .ping:
            var s = setup.firewall == .ping ? "ping" : "ping, tcp/22"
            let extra = setup.extraPorts.trimmingCharacters(in: .whitespaces)
            if !extra.isEmpty { s += ", " + extra }
            return s + " from any host"
        }
    }
}

struct DonePage: View {
    let setup: Setup

    var body: some View {
        PageTitle(title: "Nebula Is Running",
                  subtitle: "It starts again at boot. Try it from Terminal with the commands below.")
        LogView(text: setup.log)
    }
}

// MARK: - Pieces

struct FieldError: View {
    let text: String
    var body: some View { Text(text).font(.callout).foregroundStyle(.red) }
}

struct LogView: View {
    let text: String
    var body: some View {
        Text(text.trimmingCharacters(in: .whitespacesAndNewlines))
            .font(.system(.callout, design: .monospaced))
            .textSelection(.enabled)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
    }
}

struct PasteField: View {
    let title: String
    @Binding var text: String
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(LocalizedStringKey(title)).fixedSize(horizontal: false, vertical: true)
            TextEditor(text: $text)
                .font(.system(.callout, design: .monospaced))
                .frame(minHeight: 140)
                .overlay(RoundedRectangle(cornerRadius: 4).stroke(.separator))
            HStack {
                Button("Paste") { text = NSPasteboard.general.string(forType: .string) ?? text }
                if !text.isEmpty { Button("Clear") { text = "" } }
            }
        }
    }
}

struct FilePicker: View {
    let title: String
    @Binding var path: String
    var body: some View {
        HStack {
            Text(title).frame(width: 170, alignment: .leading)
            Text(path.isEmpty ? "none chosen" : path)
                .foregroundStyle(path.isEmpty ? .secondary : .primary)
                .lineLimit(1).truncationMode(.middle)
            Spacer()
            Button("Choose…") { if let p = Setup.chooseFile(title) { path = p } }
        }
    }
}

extension Binding where Value == Bool {
    /// A toggle for an optional Bool, nil reading as `def`.
    init(_ source: Binding<Bool?>, _ def: Bool) {
        self.init(get: { source.wrappedValue ?? def }, set: { source.wrappedValue = $0 })
    }
}
