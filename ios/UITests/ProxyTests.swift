import Darwin
import XCTest

final class ProxyTests: XCTestCase {
    func testStartNegotiateSocksAndStop() throws {
        let app = XCUIApplication()
        app.launch()
        app.buttons["+ Import links"].tap()
        let field = app.secureTextFields["VLESS share link"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap()
        field.typeText("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:19443?security=tls&sni=example.com")
        app.buttons["Import"].tap()
        app.buttons["Start proxy"].tap()
        XCTAssertTrue(app.staticTexts["HTTP and SOCKS5 proxy at 127.0.0.1:2080"].waitForExistence(timeout: 10))
        try negotiateSocks()
        app.buttons["Connection tests"].tap()
        XCTAssertTrue(app.buttons["Country"].waitForExistence(timeout: 5))
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "Profiles connection tests"
        screenshot.lifetime = .keepAlways
        add(screenshot)
        app.buttons["Close"].tap()
        app.buttons["Stop proxy"].tap()
        XCTAssertTrue(app.staticTexts["Proxy offline"].waitForExistence(timeout: 10))
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { close(fd) }
        XCTAssertEqual(connectToProxy(fd), -1)
        XCTAssertEqual(errno, ECONNREFUSED)
    }

    private func connectToProxy(_ fd: Int32) -> Int32 {
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(2080).bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        return withUnsafePointer(to: &address) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }

    private func negotiateSocks() throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.ENFILE) }
        defer { close(fd) }
        guard connectToProxy(fd) == 0 else { throw POSIXError(.ECONNREFUSED) }
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        XCTAssertEqual(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)), 0)
        let greeting: [UInt8] = [5, 1, 0]
        XCTAssertEqual(greeting.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }, greeting.count)
        var reply = [UInt8](repeating: 0, count: 2)
        XCTAssertEqual(reply.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, MSG_WAITALL) }, 2)
        XCTAssertEqual(reply, [5, 0])
    }
}
