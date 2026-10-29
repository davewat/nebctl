import AppKit
import SwiftUI

@main
struct NebulaNodeApp: App {
    @NSApplicationDelegateAdaptor private var delegate: AppDelegate
    @State private var setup = Setup()

    var body: some Scene {
        Window("Nebula Node", id: "main") {
            ContentView(setup: setup)
        }
        .windowResizability(.contentMinSize)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Run straight from `swift run` too, not only as an .app.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
