import Network
import SwiftUI

struct ConnectionTestsView: View {
    let profile: String
    @Environment(\.dismiss) var dismiss
    @State private var tab = "Ping"
    @State private var url = "https://example.com/"
    @State private var result = ""
    @State private var task: Task<Void, Never>?
    private let tabs = ["Ping", "Speed", "URL", "Country"]
    private let hints = ["Ping":"Time to the first HTTPS response byte from Cloudflare.",
                         "Speed":"Download 5 MB from Cloudflare through this profile.",
                         "URL":"Check the HTTP status of an HTTPS URL.",
                         "Country":"Look up the proxy’s exit country with Cloudflare."]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Connection tests").font(.title2.bold())
            Text(profile).foregroundStyle(.secondary)
            Picker("Test", selection: $tab) {
                ForEach(tabs, id: \.self) { Text($0) }
            }.pickerStyle(.segmented).disabled(task != nil).onChange(of: tab) { _ in result = "" }
            Text(hints[tab] ?? "").foregroundStyle(.secondary)
            if tab == "URL" {
                TextField("HTTPS URL", text: $url).textInputAutocapitalization(.never)
                    .autocorrectionDisabled().textFieldStyle(.roundedBorder)
            }
            if !result.isEmpty { Text(result) }
            HStack {
                Button(task == nil ? "Run test" : "Cancel test") {
                    if let task { task.cancel() }
                    else {
                        result = "Running…"
                        task = Task {
                            do { result = try await measure() }
                            catch { result = Task.isCancelled ? "Cancelled" : error.localizedDescription }
                            task = nil
                        }
                    }
                }.buttonStyle(.borderedProminent).tint(.black)
                Button("Close") { dismiss() }.buttonStyle(.bordered)
            }
        }.padding(22).presentationDetents([.medium]).onDisappear { task?.cancel() }
    }

    private func measure() async throws -> String {
        let config = URLSessionConfiguration.ephemeral
        if #available(iOS 17, *) {
            config.proxyConfigurations = [ProxyConfiguration(socksv5Proxy: .hostPort(host: "127.0.0.1", port: 2080))]
        } else {
            config.connectionProxyDictionary = ["SOCKSEnable": 1, "SOCKSProxy": "127.0.0.1", "SOCKSPort": 2080]
        }
        config.timeoutIntervalForResource = 25
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        let target = tab == "URL" ? url : tab == "Speed" ? "https://speed.cloudflare.com/__down?bytes=5000000" : "https://www.cloudflare.com/cdn-cgi/trace"
        guard let endpoint = URL(string: target), endpoint.scheme?.lowercased() == "https", endpoint.host != nil else { throw URLError(.badURL) }
        var request = URLRequest(url: endpoint)
        if tab == "URL" { request.httpMethod = "HEAD" }
        let start = ProcessInfo.processInfo.systemUptime
        if tab == "Ping" {
            let (bytes, response) = try await session.bytes(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            var iterator = bytes.makeAsyncIterator()
            guard try await iterator.next() != nil else { throw URLError(.zeroByteResource) }
            return String(format: "%.0f ms to first byte", (ProcessInfo.processInfo.systemUptime - start) * 1000)
        }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        if tab == "URL" { return "HTTP \(http.statusCode)" }
        guard http.statusCode == 200 else { throw URLError(.badServerResponse) }
        if tab == "Speed" {
            guard data.count == 5_000_000 else { throw URLError(.cannotDecodeContentData) }
            return String(format: "%.1f Mbps download", 40 / (ProcessInfo.processInfo.systemUptime - start))
        }
        guard let country = String(decoding: data, as: UTF8.self).split(separator: "\n")
            .first(where: { $0.hasPrefix("loc=") && $0.count == 6 }) else { throw URLError(.cannotDecodeContentData) }
        return "Exit country · \(country.dropFirst(4))"
    }
}
