import SwiftUI

@main
struct VlessApp: App {
    @StateObject private var proxy = ProxyController()

    var body: some Scene {
        WindowGroup {
            ProfilesScreen(proxy: proxy)
        }
    }
}

@MainActor
final class ProxyController: ObservableObject {
    @Published private(set) var profiles: [SavedProfile] = []
    @Published var selection: String?
    @Published var notice: String?
    var active: SavedProfile? { profiles.first { $0.link == selection } ?? profiles.first }
    private static func storage() throws -> URL {
        let dir = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                              appropriateFor: nil, create: true)
        var privateDir = dir.appendingPathComponent("Profiles", isDirectory: true)
        try FileManager.default.createDirectory(at: privateDir, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try privateDir.setResourceValues(values)
        return privateDir.appendingPathComponent("library.json")
    }
    init() {
        do {
            let file = try Self.storage()
            if FileManager.default.fileExists(atPath: file.path) {
                profiles = try JSONDecoder().decode([SavedProfile].self, from: Data(contentsOf: file))
            }
        } catch { notice = "Could not load saved profiles." }
    }
    private func save(_ next: [SavedProfile]) throws {
        try JSONEncoder().encode(next).write(to: Self.storage(), options: [.atomic, .completeFileProtection])
        profiles = next
    }
    func add(_ value: String) -> Bool {
        guard !value.utf8.contains(0), let raw = value.withCString({ vless_profiles_import($0) }) else {
            notice = "Enter valid VLESS links or a VLESS subscription."; return false
        }
        defer { vless_profiles_free(raw) }
        do {
            let incoming = try JSONDecoder().decode([SavedProfile].self, from: Data(String(cString: raw).utf8))
            var next = profiles
            for entry in incoming where !next.contains(where: { $0.link == entry.link }) { next.append(entry) }
            guard next.count <= 128 else { notice = "Save up to 128 profiles."; return false }
            try save(next)
            selection = incoming.first?.link
            notice = incoming.flatMap(\.warnings).first
            return true
        } catch { notice = "Could not save profiles."; return false }
    }
    func remove(_ entry: SavedProfile) {
        guard !running && !busy else { return }
        do { try save(profiles.filter { $0.link != entry.link }) }
        catch { notice = "Could not remove profile." }
    }
    @Published var running = false
    @Published var busy = false
    @Published var status = "Disconnected"

    func toggle() {
        guard !busy else { return }
        busy = true
        let stopping = running
        let profile = active?.link ?? ""
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
