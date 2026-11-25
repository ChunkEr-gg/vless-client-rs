import SwiftUI

@main
struct VlessApp: App {
    @StateObject private var proxy = ProxyController()

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                Form {
                    Section("Profile") {
                        SecureField("VLESS share link", text: $proxy.link)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .disabled(proxy.running || proxy.busy)
                    }
                    Section {
                        Button(proxy.running ? "Stop proxy" : "Start proxy") {
                            proxy.toggle()
                        }
                        .disabled(proxy.busy || (!proxy.running && proxy.link.isEmpty))
                        Text(proxy.status)
                    }
                }
                .navigationTitle("VLESS Client")
            }
        }
    }
}

@MainActor
final class ProxyController: ObservableObject {
    @Published var link = ""
    @Published var running = false
    @Published var busy = false
    @Published var status = "Disconnected"

    func toggle() {
        guard !busy else { return }
        busy = true
        let stopping = running
        let profile = link
        Task {
            let result = await Task.detached {
                if stopping {
                    vless_proxy_stop()
                    return Int32(0)
                }
                return profile.withCString { vless_proxy_start($0, 2080) }
            }.value
            running = !stopping && (result == VLESS_START_OK || result == VLESS_START_ALREADY_RUNNING)
            if running {
                status = "HTTP and SOCKS5 proxy at 127.0.0.1:2080"
            } else if stopping {
                status = "Disconnected"
            } else {
                status = result == VLESS_START_INVALID_PROFILE ? "Invalid VLESS share link" : "Could not start the proxy"
            }
            busy = false
        }
    }
}
