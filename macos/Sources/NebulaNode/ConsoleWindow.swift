import AppKit
import SwiftUI
import WebKit

/// The admin console (nebctl web) in its own window. Links that leave the
/// console, and its "Open in browser" button, open in the default browser.
struct ConsoleView: View {
    let setup: Setup

    var body: some View {
        if let url = setup.consoleURL {
            ConsoleWebView(url: url) { setup.consoleURL = nil }
                .frame(minWidth: 960, minHeight: 640)
        } else {
            VStack(spacing: 12) {
                Text("The admin console isn't running.").font(.title3)
                Text("Open it from the Nebula Node window.").foregroundStyle(.secondary)
            }
            .frame(minWidth: 480, minHeight: 240)
        }
    }
}

struct ConsoleWebView: NSViewRepresentable {
    let url: URL
    let closed: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(url: url, closed: closed) }

    func makeNSView(context: Context) -> WKWebView {
        let web = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())
        web.uiDelegate = context.coordinator
        web.navigationDelegate = context.coordinator
        web.setValue(false, forKey: "drawsBackground") // no white flash before the dark page
        web.load(URLRequest(url: url))
        return web
    }

    func updateNSView(_ web: WKWebView, context: Context) {}

    /// Closing the window stops the console; it also stops when the app quits.
    static func dismantleNSView(_ web: WKWebView, coordinator: Coordinator) {
        let url = coordinator.url
        web.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
            Nebctl.stopConsole(at: url, cookies: cookies)
        }
        coordinator.closed()
    }

    final class Coordinator: NSObject, WKUIDelegate, WKNavigationDelegate {
        let url: URL
        let closed: () -> Void
        init(url: URL, closed: @escaping () -> Void) { self.url = url; self.closed = closed }

        // window.open(...) and target=_blank: the default browser.
        func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                     for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
            if let u = action.request.url { NSWorkspace.shared.open(u) }
            return nil
        }

        // Anything off this machine's console: the default browser.
        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            if let u = action.request.url, let host = u.host, host != "127.0.0.1", host != "localhost" {
                NSWorkspace.shared.open(u)
                decisionHandler(.cancel)
                return
            }
            decisionHandler(.allow)
        }
    }
}
