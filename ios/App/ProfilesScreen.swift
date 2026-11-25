import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct SavedProfile: Codable, Identifiable {
    let name, endpoint, security, link: String
    let warnings: [String]
    var id: String { link }
}

struct ProfilesScreen: View {
    @ObservedObject var proxy: ProxyController
    @StateObject private var vpn = SystemVPN()
    @State private var query = ""
    @State private var importing = false
    @State private var choosingFile = false
    @State private var testing = false
    @State private var input = ""
    @State private var subscriptionURL: URL?
    private let maxImportBytes = 1_048_576
    private let ink = Color(white: 0.07)
    private let accent = Color(red: 1, green: 0.21, blue: 0.09)

    var body: some View {
        let filter = query.trimmingCharacters(in: .whitespacesAndNewlines)
        let matches = proxy.profiles.filter {
            filter.isEmpty || [$0.name, $0.endpoint, $0.security].joined(separator: " ").localizedCaseInsensitiveContains(filter)
        }
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text("Profiles").font(.largeTitle.bold())
                    Spacer()
                    Button("+ Import links") { input = ""; importing = true }
                        .buttonStyle(.borderedProminent).tint(ink)
                        .disabled(proxy.running || proxy.busy || vpn.active || vpn.busy)
                }
                HStack {
                    Image(systemName: "magnifyingglass")
                    TextField("Search profiles", text: $query)
                }
                .padding(12).background(.white, in: RoundedRectangle(cornerRadius: 10))
                if !filter.isEmpty && matches.isEmpty {
                    Text("No matching profiles").foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity)
                }
                ForEach(matches) { item in
                    Button {
                        proxy.select(item)
                    } label: {
                        HStack {
                            Image(systemName: "server.rack")
                            VStack(alignment: .leading) {
                                Text(item.name).bold()
                                Text(item.endpoint).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(item.security).font(.caption)
                        }
                        .padding(12).background(proxy.active?.link == item.link ? Color(white: 0.87) : .clear,
                                                in: RoundedRectangle(cornerRadius: 12))
                        .contentShape(Rectangle())
                    }
                    .accessibilityIdentifier("saved-profile-row")
                    .buttonStyle(.plain).disabled(proxy.running || proxy.busy || vpn.active || vpn.busy)
                    .contextMenu {
                        ShareLink(item: item.link) { Label("Share profile", systemImage: "square.and.arrow.up") }
                        if filter.isEmpty {
                            Button("Move up") { proxy.move(item, by: -1) }
                                .disabled(item.id == proxy.profiles.first?.id)
                            Button("Move down") { proxy.move(item, by: 1) }
                                .disabled(item.id == proxy.profiles.last?.id)
                        }
                        Button("Remove profile", role: .destructive) { proxy.remove(item) }
                    }
                }
                VStack(alignment: .leading, spacing: 14) {
                    Label(vpn.active ? (vpn.message ?? "VPN active") : proxy.running ? "Proxy listening" : proxy.busy ? "Working…" : "Proxy offline",
                          systemImage: "circle.fill")
                        .font(.caption.bold()).foregroundStyle(proxy.running || vpn.active ? accent : Color.gray)
                    Text(proxy.active?.name ?? "No profile selected").font(.title.bold())
                        .accessibilityIdentifier("selected-profile-name")
                    if let profile = proxy.active {
                        Text(profile.security).foregroundStyle(.secondary)
                        Text(profile.endpoint).font(.body.monospacedDigit())
                        if proxy.running {
                            Button("Connection tests") { testing = true }.buttonStyle(.bordered)
                            HStack {
                                Text(proxy.status).font(.footnote.monospaced())
                                Spacer()
                                Button {
                                    UIPasteboard.general.string = "127.0.0.1:2080"
                                } label: {
                                    Image(systemName: "square.on.square")
                                }.accessibilityLabel("Copy proxy address")
                            }
                        } else if proxy.status != "Disconnected" {
                            Text(proxy.status).font(.footnote)
                        }
                        Button(proxy.running ? "Stop proxy" : "Start proxy") { proxy.toggle() }
                            .buttonStyle(.borderedProminent).tint(proxy.running ? Color(white: 0.2) : accent)
                            .disabled(proxy.busy || vpn.active || vpn.busy)
                        Button(vpn.active ? "Disconnect VPN" : "Connect VPN") { vpn.toggle(profile) }
                            .buttonStyle(.bordered).disabled(proxy.running || proxy.busy || vpn.busy)
                        if !vpn.active, let message = vpn.message { Text(message).font(.footnote) }
                    }
                }
                .padding(22).frame(maxWidth: .infinity, alignment: .leading)
                .foregroundStyle(.white)
                .background {
                    Canvas { ctx, size in
                        for y in stride(from: 10.0, to: size.height, by: 14) {
                            for x in stride(from: 10.0, to: size.width, by: 14) {
                                ctx.fill(Path(ellipseIn: CGRect(x: x, y: y, width: 1.5, height: 1.5)), with: .color(.white.opacity(0.12)))
                            }
                        }
                    }.background(ink)
                }.clipShape(RoundedRectangle(cornerRadius: 20))
                if let notice = proxy.notice { Text(notice).font(.footnote) }
            }.padding(18)
        }
        .background(Color(white: 0.92)).preferredColorScheme(.light)
        .onOpenURL { url in
            guard url.scheme?.lowercased() == "vless" else { return }
            guard !proxy.running, !proxy.busy, !vpn.active, !vpn.busy else {
                proxy.notice = "Disconnect before importing profiles."
                return
            }
            guard url.absoluteString.utf8.count <= maxImportBytes else {
                proxy.notice = "Share up to 1 MiB of VLESS links."
                return
            }
            proxy.notice = nil
            input = url.absoluteString
            importing = true
        }
        .sheet(isPresented: $importing, onDismiss: { subscriptionURL = nil }) {
            VStack(alignment: .leading, spacing: 16) {
                Text("Import links").font(.title2.bold())
                SecureField("VLESS link or HTTPS subscription URL", text: $input)
                    .accessibilityIdentifier("VLESS share link")
                    .textInputAutocapitalization(.never).autocorrectionDisabled().textFieldStyle(.roundedBorder)
                    .disabled(subscriptionURL != nil)
                Button("Choose file…") { choosingFile = true }.disabled(subscriptionURL != nil)
                if subscriptionURL != nil {
                    ProgressView("Downloading subscription…")
                }
                if let notice = proxy.notice { Text(notice).font(.footnote) }
                HStack {
                    Button("Import", action: importInput)
                        .buttonStyle(.borderedProminent).tint(ink)
                        .disabled(subscriptionURL != nil)
                    Button("Cancel") { importing = false }.buttonStyle(.bordered)
                }
            }.padding(22).presentationDetents([.medium])
                .task(id: subscriptionURL) { [subscriptionURL] in
                    if let url = subscriptionURL { await importSubscription(url) }
                }
                .fileImporter(isPresented: $choosingFile, allowedContentTypes: [.data]) { result in
                    do {
                        let url = try result.get()
                        let scoped = url.startAccessingSecurityScopedResource()
                        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                        let file = try FileHandle(forReadingFrom: url)
                        defer { try? file.close() }
                        let data = try file.read(upToCount: maxImportBytes + 1) ?? Data()
                        guard data.count <= maxImportBytes, let text = String(data: data, encoding: .utf8) else {
                            proxy.notice = "Choose a UTF-8 text file up to 1 MiB."
                            return
                        }
                        input = text
                        proxy.notice = nil
                    } catch let error as NSError {
                        if error.domain != NSCocoaErrorDomain || error.code != NSUserCancelledError {
                            proxy.notice = "Could not read the selected file."
                        }
                    }
                }
        }
        .sheet(isPresented: $testing) { ConnectionTestsView(profile: proxy.active?.name ?? "") }
    }

    private func importInput() {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.utf8.count <= maxImportBytes else {
            proxy.notice = "Import up to 1 MiB of VLESS links."
            return
        }
        if let url = URL(string: value), url.scheme?.lowercased() == "https", url.host != nil {
            proxy.notice = nil
            subscriptionURL = url
        } else {
            saveImport(value)
        }
    }

    private func saveImport(_ value: String) {
        if proxy.add(value) {
            input = ""
            importing = false
        }
    }

    @MainActor
    private func importSubscription(_ url: URL) async {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30
        let session = URLSession(configuration: config)
        defer {
            session.invalidateAndCancel()
            if !Task.isCancelled && subscriptionURL == url { subscriptionURL = nil }
        }
        do {
            let (bytes, response) = try await session.bytes(from: url, delegate: HTTPSSubscriptionRedirects())
            try Task.checkCancellation()
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
                  http.url?.scheme?.lowercased() == "https" else {
                proxy.notice = "Could not download the subscription."
                return
            }
            guard http.expectedContentLength <= Int64(maxImportBytes) else {
                proxy.notice = "Import up to 1 MiB of VLESS links."
                return
            }
            var data = Data()
            for try await byte in bytes {
                guard data.count < maxImportBytes else {
                    proxy.notice = "Import up to 1 MiB of VLESS links."
                    return
                }
                data.append(byte)
            }
            try Task.checkCancellation()
            guard importing, subscriptionURL == url else { return }
            guard let text = String(data: data, encoding: .utf8) else {
                proxy.notice = "The subscription must contain UTF-8 text."
                return
            }
            saveImport(text)
        } catch {
            if !Task.isCancelled && importing && subscriptionURL == url {
                proxy.notice = "Could not download the subscription."
            }
        }
    }
}

private final class HTTPSSubscriptionRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? {
        request.url?.scheme?.lowercased() == "https" ? request : nil
    }
}
