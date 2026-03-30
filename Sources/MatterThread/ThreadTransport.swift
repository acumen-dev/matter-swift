// ThreadTransport.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(OpenThread)

import Foundation
import Logging
import MatterTransport
import OpenThread

/// `MatterUDPTransport` implementation that routes UDP datagrams
/// through the OpenThread mesh network.
///
/// This allows a `MatterController` to communicate with Thread devices
/// by simply swapping the transport:
///
/// ```swift
/// let thread = try ThreadInstance(radioURL: "spinel+hdlc+uart:///dev/ttyACM0")
/// let transport = ThreadTransport(instance: thread)
///
/// let controller = try MatterController(
///     transport: transport,
///     discovery: ThreadDiscovery(instance: thread),
///     configuration: config
/// )
/// ```
public final class ThreadTransport: MatterUDPTransport, @unchecked Sendable {
    private let threadInstance: ThreadInstance
    private let logger: Logger
    private var udpSocket: OpaquePointer?  // otUdpSocket*
    private var receiveBridge: CallbackBridge<(Data, MatterAddress)>?
    private var _receiveStream: AsyncStream<(Data, MatterAddress)>?

    public init(
        instance: ThreadInstance,
        logger: Logger = Logger(label: "matter.thread.transport")
    ) {
        self.threadInstance = instance
        self.logger = logger
    }

    public func bind(port: UInt16) async throws {
        let (stream, continuation) = AsyncStream.makeStream(of: (Data, MatterAddress).self)
        let bridge = CallbackBridge(continuation: continuation)
        self.receiveBridge = bridge
        self._receiveStream = stream

        // Open a UDP socket on the Thread mesh
        var socket = otUdpSocket()
        let err = otUdpOpen(
            threadInstance.instance,
            &socket,
            { context, message, messageInfo in
                guard let message, let messageInfo else { return }

                // Extract the payload
                let length = otMessageGetLength(message) - otMessageGetOffset(message)
                guard length > 0 else { return }

                var data = Data(count: Int(length))
                let bytesRead = data.withUnsafeMutableBytes { ptr in
                    otMessageRead(message, otMessageGetOffset(message),
                                  ptr.baseAddress, length)
                }
                guard bytesRead == length else { return }

                // Extract source address
                let info = messageInfo.pointee
                var peerAddr = info.mPeerAddr
                let host = withUnsafePointer(to: &peerAddr) { addrPtr -> String in
                    var buf = [CChar](repeating: 0, count: 64)
                    otIp6AddressToString(addrPtr, &buf, 64)
                    return String(cString: buf)
                }
                let port = info.mPeerPort

                let address = MatterAddress(host: host, port: port)
                CallbackBridge<(Data, MatterAddress)>.yield(
                    context: context,
                    value: (data, address)
                )
            },
            bridge.pointer
        )
        try throwIfError(err)

        // Bind to the specified port
        var sockAddr = otSockAddr()
        sockAddr.mPort = port
        // mAddress left as unspecified (all-zeros) to receive on any address
        try throwIfError(otUdpBind(threadInstance.instance, &socket, &sockAddr, OT_NETIF_THREAD))

        self.udpSocket = withUnsafeMutablePointer(to: &socket) {
            OpaquePointer($0)
        }

        logger.info("Thread UDP socket bound on port \(port)")
    }

    public func send(_ data: Data, to address: MatterAddress) async throws {
        guard udpSocket != nil else {
            throw ThreadError.invalidState
        }

        // Allocate an OT message
        guard let message = otUdpNewMessage(threadInstance.instance, nil) else {
            throw ThreadError.noBufs
        }

        // Write payload
        let appendErr = data.withUnsafeBytes { ptr in
            otMessageAppend(message, ptr.baseAddress, UInt16(data.count))
        }
        guard ThreadError(appendErr) == nil else {
            otMessageFree(message)
            throw ThreadError(appendErr)!
        }

        // Set up destination
        var messageInfo = otMessageInfo()
        messageInfo.mPeerPort = address.port

        // Parse IPv6 address
        address.host.withCString { hostPtr in
            otIp6AddressFromString(hostPtr, &messageInfo.mPeerAddr)
        }

        // Send
        var socket = otUdpSocket()
        try throwIfError(otUdpSend(threadInstance.instance, &socket, message, &messageInfo))

        logger.trace("Sent \(data.count) bytes to \(address.host):\(address.port)")
    }

    public func receive() -> AsyncStream<(Data, MatterAddress)> {
        _receiveStream ?? AsyncStream { $0.finish() }
    }

    public func close() async {
        if var socket = udpSocket.map({ (ptr: OpaquePointer) -> otUdpSocket in
            UnsafeMutablePointer<otUdpSocket>(ptr).pointee
        }) {
            otUdpClose(threadInstance.instance, &socket)
        }
        udpSocket = nil
        receiveBridge?.finish()
        receiveBridge = nil
        logger.info("Thread UDP socket closed")
    }
}

#endif
