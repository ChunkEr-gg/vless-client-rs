import Darwin
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let queue = DispatchQueue(label: "io.vless.client.packet-flow")
    private var reader: DispatchSourceRead?
    private var generation: UInt = 0

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let config = protocolConfiguration as? NETunnelProviderProtocol,
              let link = config.providerConfiguration?["profile"] as? String else {
            completionHandler(POSIXError(.EINVAL))
            return
        }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: config.serverAddress ?? "127.0.0.1")
        settings.mtu = 1400
        let ipv4 = NEIPv4Settings(addresses: ["172.29.255.1"], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = [.default()]
        settings.ipv4Settings = ipv4
        let ipv6 = NEIPv6Settings(addresses: ["fd73:726b::1"], networkPrefixLengths: [126])
        ipv6.includedRoutes = [.default()]
        settings.ipv6Settings = ipv6
        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1"])
        setTunnelNetworkSettings(settings) { error in
            self.queue.async {
                if let error { completionHandler(error); return }
                do {
                    try self.attach(link)
                    completionHandler(nil)
                } catch { completionHandler(error) }
            }
        }
    }

    private func attach(_ link: String) throws {
        var sockets = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0 else { throw POSIXError(.ENOBUFS) }
        let fd = sockets[0]
        defer { close(sockets[1]) }
        guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
              link.withCString({ vless_packet_start($0, sockets[1]) }) == 0 else {
            close(fd)
            throw POSIXError(.EIO)
        }
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        reader = source
        source.setEventHandler { [weak self] in self?.readEnginePackets(fd) }
        source.setCancelHandler { close(fd) }
        source.resume()
        readSystemPackets(fd, generation: generation)
    }

    private func readSystemPackets(_ fd: Int32, generation: UInt) {
        packetFlow.readPackets { packets, _ in
            self.queue.async {
                guard self.reader != nil, self.generation == generation else { return }
                for packet in packets {
                    _ = packet.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
                }
                self.readSystemPackets(fd, generation: generation)
            }
        }
    }

    private func readEnginePackets(_ fd: Int32) {
        var packets = [Data]()
        var families = [NSNumber]()
        var buffer = [UInt8](repeating: 0, count: 2048)
        for _ in 0..<64 {
            let count = buffer.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
            guard count > 0 else { break }
            let version = buffer[0] >> 4
            guard version == 4 || version == 6 else { continue }
            packets.append(Data(buffer.prefix(count)))
            families.append(NSNumber(value: version == 4 ? AF_INET : AF_INET6))
        }
        if !packets.isEmpty { packetFlow.writePackets(packets, withProtocols: families) }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async {
            self.generation &+= 1
            self.reader?.cancel()
            self.reader = nil
            vless_proxy_stop()
            completionHandler()
        }
    }
}
