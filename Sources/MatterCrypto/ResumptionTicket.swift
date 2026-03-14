// ResumptionTicket.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// A stored ticket for CASE session resumption (Matter spec §4.13.2.3).
///
/// After a successful CASE handshake, the responder creates a resumption ticket
/// containing the shared secret and a resumption ID. On subsequent connections,
/// the initiator can present the resumption ID to skip the full Sigma exchange.
public struct ResumptionTicket: Sendable {

    /// 16-byte opaque identifier assigned by the responder.
    public let resumptionID: Data

    /// The ECDH shared secret from the original CASE exchange.
    public let sharedSecret: Data

    /// Node ID of the peer (initiator) for this session.
    public let peerNodeID: NodeID

    /// Fabric ID of the peer.
    public let peerFabricID: FabricID

    /// Local fabric index under which this ticket is stored.
    public let fabricIndex: FabricIndex

    /// Expiry timestamp — tickets are rejected after this date.
    public let expiryDate: Date

    public init(
        resumptionID: Data,
        sharedSecret: Data,
        peerNodeID: NodeID,
        peerFabricID: FabricID,
        fabricIndex: FabricIndex,
        expiryDate: Date
    ) {
        self.resumptionID = resumptionID
        self.sharedSecret = sharedSecret
        self.peerNodeID = peerNodeID
        self.peerFabricID = peerFabricID
        self.fabricIndex = fabricIndex
        self.expiryDate = expiryDate
    }
}
