import SwiftUI

struct SavedProfile: Codable, Identifiable {
    let name, endpoint, security, link: String
    let warnings: [String]
    var id: String { link }
}

struct ProfilesScreen: View {
    @ObservedObject var proxy: ProxyController
    @State private var query = ""
    @State private var importing = false
    @State private var testing = false
    @State private var input = ""
    private let ink = Color(white: 0.07)
    private let accent = Color(red: 1, green: 0.21, blue: 0.09)

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text("Profiles").font(.largeTitle.bold())
                    Spacer()
                    Button("+ Import links") { input = ""; importing = true }
                        .buttonStyle(.borderedProminent).tint(ink)
                        .disabled(proxy.running || proxy.busy)
                }
                HStack {
                    Image(systemName: "magnifyingglass")
                    TextField("Search profiles", text: $query)
                }
                .padding(12).background(.white, in: RoundedRectangle(cornerRadius: 10))
                ForEach(proxy.profiles.filter {
                    query.isEmpty || [$0.name, $0.endpoint, $0.security].joined(separator: " ").localizedCaseInsensitiveContains(query)
                }) { item in
                    Button {
                        proxy.selection = item.link
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
                    }
                    .buttonStyle(.plain).disabled(proxy.running || proxy.busy)
                    .contextMenu { Button("Remove profile", role: .destructive) { proxy.remove(item) } }
                }
                VStack(alignment: .leading, spacing: 14) {
                    Label(proxy.running ? "Proxy listening" : proxy.busy ? "Working…" : "Proxy offline",
                          systemImage: "circle.fill")
                        .font(.caption.bold()).foregroundStyle(proxy.running ? accent : Color.gray)
                    Text(proxy.active?.name ?? "No profile selected").font(.title.bold())
                    if let profile = proxy.active {
                        Text(profile.security).foregroundStyle(.secondary)
                        Text(profile.endpoint).font(.body.monospacedDigit())
                        if proxy.running {
                            Button("Connection tests") { testing = true }.buttonStyle(.bordered)
                            Text(proxy.status).font(.footnote.monospaced())
                        } else if proxy.status != "Disconnected" {
                            Text(proxy.status).font(.footnote)
                        }
                        Button(proxy.running ? "Stop proxy" : "Start proxy") { proxy.toggle() }
                            .buttonStyle(.borderedProminent).tint(proxy.running ? Color(white: 0.2) : accent)
                            .disabled(proxy.busy)
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
        .sheet(isPresented: $importing) {
            VStack(alignment: .leading, spacing: 16) {
                Text("Import links").font(.title2.bold())
                SecureField("VLESS share link", text: $input)
                    .textInputAutocapitalization(.never).autocorrectionDisabled().textFieldStyle(.roundedBorder)
                if let notice = proxy.notice { Text(notice).font(.footnote) }
                HStack {
                    Button("Import") { if proxy.add(input) { input = ""; importing = false } }
                        .buttonStyle(.borderedProminent).tint(ink)
                    Button("Cancel") { importing = false }.buttonStyle(.bordered)
                }
            }.padding(22).presentationDetents([.medium])
        }
        .sheet(isPresented: $testing) { ConnectionTestsView(profile: proxy.active?.name ?? "") }
    }
}
