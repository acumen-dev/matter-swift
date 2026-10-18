  // ControllerRedaction.swift
  // Copyright 2026 Monagle Pty Ltd

  import Foundation
  import MatterProtocol

  extension PASESession: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
      public var description: String { "PASESession(passcode: <redacted>)" }
      public var debugDescription: String { description }
      public var customMirror: Mirror { Mirror(self, children: ["passcode": "<redacted>"], displayStyle: .struct) }
  }

  extension PASESession.Pake1Context: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
      /// Session ids only: w1, the prover context and the hash context are never rendered.
      public var description: String {
          "Pake1Context(initiatorSession: \(MatterLogValue.hexString(initiatorSessionID)), responderSession: \(MatterLogValue.hexString(responderSessionID)), secrets: <redacted>)"
      }
      public var debugDescription: String { description }
      public var customMirror: Mirror {
          Mirror(self, children: ["initiatorSessionID": initiatorSessionID, "responderSessionID": responderSessionID, "secrets": "<redacted>"], displayStyle: .struct)
      }
  }

  extension CommissioningController.CommissioningContext: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
      /// Ids and identities only: the PASE session, its contexts, the attestation challenge and
      /// the DAC key are never rendered.
      public var description: String {
          var parts: [String] = []
          if let initiatorSessionID { parts.append("initiatorSession: \(MatterLogValue.hexString(initiatorSessionID))") }
          if let responderSessionID { parts.append("responderSession: \(MatterLogValue.hexString(responderSessionID))") }
          if let deviceNodeID { parts.append("deviceNode: \(MatterLogValue.hexString(deviceNodeID.rawValue))") }
          if let fabricIndex { parts.append("fabricIndex: \(fabricIndex.rawValue)") }
          if let deviceFabricIndex { parts.append("deviceFabricIndex: \(deviceFabricIndex.rawValue)") }
          if let basicInformationVendorID { parts.append("vendorID: \(MatterLogValue.hexString(basicInformationVendorID))") }
          if let basicInformationProductID { parts.append("productID: \(MatterLogValue.hexString(basicInformationProductID))") }
          switch attestation {
          case .verified?: parts.append("attestation: verified")
          case .overridden?: parts.append("attestation: overridden")
          case nil: break
          }
          parts.append("secrets: <redacted>")
          return "CommissioningContext(\(parts.joined(separator: ", ")))"
      }
      public var debugDescription: String { description }
      public var customMirror: Mirror {
          Mirror(self, children: ["summary": description], displayStyle: .struct)
      }
  }

  extension ControllerSession.HandshakeContext: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
      public var description: String { "HandshakeContext(peerNode: \(MatterLogValue.hexString(peerNodeID.rawValue)), keys: <redacted>)" }
      public var debugDescription: String { description }
      public var customMirror: Mirror { Mirror(self, children: ["peerNodeID": peerNodeID, "keys": "<redacted>"], displayStyle: .struct) }
  }

  extension MatterController.Configuration: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
      /// Every setting but the root key.
      public var description: String {
          let parts = [
              "fabricID: \(MatterLogValue.hexString(fabricID.rawValue))",
              "controllerNodeID: \(MatterLogValue.hexString(controllerNodeID.rawValue))",
              "vendorID: \(MatterLogValue.hexString(vendorID.rawValue))",
              "rootKey: <redacted>",
              "operationTimeout: \(operationTimeout)",
              "commissioningTimeout: \(commissioningTimeout)",
              "mrp: \(mrp.maxRetransmissions) retransmissions",
              "discoveryTimeout: \(discoveryTimeout)",
              "addressRefreshTimeout: \(addressRefreshTimeout)",
              "commissionableResolveTimeout: \(commissionableResolveTimeout)",
              "attestationTrustStore: \(attestationTrustStore == nil ? "bundled" : "custom")",
              "metricsLabelPrefix: \(metricsLabelPrefix)",
          ]
          return "Configuration(\(parts.joined(separator: ", ")))"
      }
      public var debugDescription: String { description }
      public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
  }
  