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
    private struct Library: Codable {
        var profiles: [SavedProfile]
        var selection: String?
    }
    @Published private(set) var selection: String?
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
                let data = try Data(contentsOf: file)
                let decoder = JSONDecoder()
                if let library = try? decoder.decode(Library.self, from: data) {
                    profiles = library.profiles
                    selection = library.selection
                } else {
                    profiles = try decoder.decode([SavedProfile].self, from: data)
                }
            }
        } catch { notice = "Could not load saved profiles." }
    }
    private func save(_ next: [SavedProfile], selected: String?) throws {
        let selectedLink = next.first { $0.link == selected }?.link ?? next.first?.link
        let library = Library(profiles: next, selection: selectedLink)
        try JSONEncoder().encode(library).write(to: Self.storage(), options: [.atomic, .completeFileProtection])
        profiles = next
        selection = selectedLink
    }
    func select(_ entry: SavedProfile) {
        guard !running && !busy && entry.link != selection else { return }
        do { try save(profiles, selected: entry.link) }
        catch { notice = "Could not save the selected profile." }
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
            try save(next, selected: incoming.first?.link)
            notice = incoming.flatMap(\.warnings).first
            return true
        } catch { notice = "Could not save profiles."; return false }
    }
    func move(_ entry: SavedProfile, by offset: Int) {
        guard !running, !busy, let index = profiles.firstIndex(where: { $0.id == entry.id }),
              profiles.indices.contains(index + offset) else { return }
        var next = profiles
        next.swapAt(index, index + offset)
        do { try save(next, selected: active?.link) }
        catch { notice = "Could not save the profile order." }
    }
    func remove(_ entry: SavedProfile) {
        guard !running && !busy else { return }
        do { try save(profiles.filter { $0.link != entry.link }, selected: selection) }
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
