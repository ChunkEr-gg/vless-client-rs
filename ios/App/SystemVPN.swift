import NetworkExtension
import SwiftUI

@MainActor
final class SystemVPN: ObservableObject {
    @Published private(set) var active = false
    @Published private(set) var busy = false
    @Published private(set) var message: String?
    private let providerID = (Bundle.main.bundleIdentifier ?? "io.vless.client") + ".tunnel"
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    init() {
        Task {
            do {
                if manager == nil, let existing = try await loadManager() { observe(existing) }
            } catch { message = error.localizedDescription }
        }
    }

    deinit {
        if let observer { NotificationCenter.default.removeObserver(observer) }
    }

    private func loadManager() async throws -> NETunnelProviderManager? {
        try await NETunnelProviderManager.loadAllFromPreferences().first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerID
        }
    }

    private func observe(_ value: NETunnelProviderManager) {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        manager = value
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: value.connection,
                                                           queue: .main) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        refresh()
    }

    private func refresh() {
        let status = manager?.connection.status ?? .invalid
        active = [.connecting, .connected, .reasserting, .disconnecting].contains(status)
        switch status {
        case .connected: message = "VPN connected"
        case .connecting, .reasserting: message = "VPN connecting…"
        case .disconnecting: message = "VPN disconnecting…"
        default: message = nil
        }
    }

    func toggle(_ profile: SavedProfile) {
        guard !busy else { return }
        if active { manager?.connection.stopVPNTunnel(); return }
        busy = true
        Task {
            defer { busy = false }
            do {
                let existing = try await loadManager()
                let value = existing ?? NETunnelProviderManager()
                let config = NETunnelProviderProtocol()
                config.providerBundleIdentifier = providerID
                config.serverAddress = URLComponents(string: profile.link)?.host ?? profile.endpoint
                config.providerConfiguration = ["profile": profile.link]
                value.protocolConfiguration = config
                value.localizedDescription = "VLESS · " + profile.name
                value.isEnabled = true
                try await value.saveToPreferences()
                try await value.loadFromPreferences()
                observe(value)
                try value.connection.startVPNTunnel()
                refresh()
            } catch { message = error.localizedDescription }
        }
    }
}
