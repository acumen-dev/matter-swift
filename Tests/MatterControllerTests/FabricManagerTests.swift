// FabricManagerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Crypto
@testable import MatterController
@testable import MatterCrypto
import MatterTypes

@Suite("FabricManager")
struct FabricManagerTests {

    @Test("RCAC is generated and valid")
    func rcacValid() async throws {
        let manager = try FabricManager(
            rootKey: P256.Signing.PrivateKey(),
            fabricID: FabricID(rawValue: 1),
            controllerNodeID: NodeID(rawValue: 1),
            vendorID: .test
        )

        let rcac = manager.rcac
        // RCAC should have a subject with fabricID
        #expect(rcac.subject.fabricID == FabricID(rawValue: 1))
    }

    @Test("Certificate chain validates")
    func chainValidates() async throws {
        let manager = try FabricManager(
            rootKey: P256.Signing.PrivateKey(),
            fabricID: FabricID(rawValue: 1),
            controllerNodeID: NodeID(rawValue: 1),
            vendorID: .test
        )

        let fabricInfo = manager.controllerFabricInfo
        #expect(fabricInfo.validateChain())
    }

    @Test("Node ID allocation is sequential")
    func nodeIDAllocation() async throws {
        let manager = try FabricManager(
            rootKey: P256.Signing.PrivateKey(),
            fabricID: FabricID(rawValue: 1),
            controllerNodeID: NodeID(rawValue: 100),
            vendorID: .test
        )

        let id1 = await manager.allocateNodeID()
        let id2 = await manager.allocateNodeID()
        let id3 = await manager.allocateNodeID()

        #expect(id1.rawValue == 101)
        #expect(id2.rawValue == 102)
        #expect(id3.rawValue == 103)
    }

    @Test("NOC generation produces valid chain")
    func nocGeneration() async throws {
        let rootKey = P256.Signing.PrivateKey()
        let manager = try FabricManager(
            rootKey: rootKey,
            fabricID: FabricID(rawValue: 42),
            controllerNodeID: NodeID(rawValue: 1),
            vendorID: .test
        )

        let deviceKey = P256.Signing.PrivateKey()
        let nodeID = await manager.allocateNodeID()
        let noc = try await manager.generateNOC(
            nodePublicKey: deviceKey.publicKey,
            nodeID: nodeID
        )

        // NOC subject should have the assigned node ID
        #expect(noc.subject.nodeID == nodeID)
        #expect(noc.subject.fabricID == FabricID(rawValue: 42))

        // Chain should validate: NOC signed by root
        let rcac = manager.rcac
        #expect(MatterCertificate.validateChain(noc: noc, rcac: rcac))
    }

    @Test("Compressed fabric ID is deterministic")
    func compressedFabricID() async throws {
        let rootKey = P256.Signing.PrivateKey()
        let manager = try FabricManager(
            rootKey: rootKey,
            fabricID: FabricID(rawValue: 1),
            controllerNodeID: NodeID(rawValue: 1),
            vendorID: .test
        )

        let cfid1 = manager.compressedFabricID()
        let cfid2 = manager.compressedFabricID()

        #expect(cfid1 == cfid2)
        #expect(cfid1 != 0) // Should not be zero
    }

    @Test("IPK derivation produces 16 bytes")
    func ipkDerivation() async throws {
        let manager = try FabricManager(
            rootKey: P256.Signing.PrivateKey(),
            fabricID: FabricID(rawValue: 1),
            controllerNodeID: NodeID(rawValue: 1),
            vendorID: .test
        )

        let ipk = manager.deriveIPK()
        #expect(ipk.count == 16)
    }

    @Test("Fabric index is preserved")
    func fabricIndex() async throws {
        let manager = try FabricManager(
            rootKey: P256.Signing.PrivateKey(),
            fabricID: FabricID(rawValue: 1),
            controllerNodeID: NodeID(rawValue: 1),
            vendorID: .test,
            fabricIndex: FabricIndex(rawValue: 3)
        )

        let idx = manager.fabricIndex
        #expect(idx.rawValue == 3)
    }
}
