// AccessControlHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Access Control cluster (0x001F).
///
/// Manages ACL entries that determine which nodes can perform operations.
/// During commissioning, the controller writes an admin ACE via the IM write path.
/// ACL entries are staged in `CommissioningState` until `CommissioningComplete`.
public struct AccessControlHandler: ClusterHandler, @unchecked Sendable {

    public let clusterID = ClusterID.accessControl

    /// Shared commissioning state for staging ACLs.
    public let commissioningState: CommissioningState

    public init(commissioningState: CommissioningState) {
        self.commissioningState = commissioningState
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (AccessControlCluster.Attribute.acl, .array([])),
            (AccessControlCluster.Attribute.subjectsPerAccessControlEntry, .unsignedInt(4)),
            (AccessControlCluster.Attribute.targetsPerAccessControlEntry, .unsignedInt(3)),
            (AccessControlCluster.Attribute.accessControlEntriesPerFabric, .unsignedInt(4)),
        ]
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        switch attributeID {
        case AccessControlCluster.Attribute.acl:
            // Parse the ACL array — accept both ARRAY (0x16) and LIST (0x17)
            let elements: [TLVElement]
            switch value {
            case .array(let elems):
                elements = elems
            case .list(let fields):
                elements = fields.map { $0.value }
            default:
                #if DEBUG
                print("[ACL-WRITE] constraintError: value is not array or list")
                #endif
                return .constraintError
            }

            var entries: [AccessControlCluster.AccessControlEntry] = []
            for element in elements {
                do {
                    let ace = try AccessControlCluster.AccessControlEntry.fromTLVElement(element)
                    entries.append(ace)
                } catch {
                    #if DEBUG
                    print("[ACL-WRITE] constraintError: failed to parse ACE: \(error)")
                    #endif
                    return .constraintError
                }
            }

            #if DEBUG
            for (i, entry) in entries.enumerated() {
                let subDesc = entry.subjects.map { "\($0) (0x\(String($0, radix: 16)))" }.joined(separator: ",")
                print("[ACL-WRITE] ACE[\(i)]: priv=\(entry.privilege) auth=\(entry.authMode) subs=[\(subDesc)] targets=\(entry.targets?.count ?? -1) fab=\(entry.fabricIndex)")
            }
            #endif

            if commissioningState.isFailSafeArmed {
                // During commissioning: stage for CommissioningComplete
                commissioningState.stagedACLs = entries
                #if DEBUG
                print("[ACL-WRITE] Staged \(entries.count) ACL entries (fail-safe armed)")
                #endif
            } else if let fabricIndex = commissioningState.invokingFabricIndex {
                // Post-commissioning: commit directly and persist
                // Stamp the fabric index onto entries that have a placeholder (0)
                let fixedEntries = entries.map { entry in
                    if entry.fabricIndex.rawValue == 0 {
                        return AccessControlCluster.AccessControlEntry(
                            privilege: entry.privilege,
                            authMode: entry.authMode,
                            subjects: entry.subjects,
                            targets: entry.targets,
                            fabricIndex: fabricIndex
                        )
                    }
                    return entry
                }
                commissioningState.updateCommittedACLs(fabricIndex: fabricIndex, entries: fixedEntries)
                #if DEBUG
                print("[ACL-WRITE] Committed \(fixedEntries.count) ACL entries directly for fabric \(fabricIndex.rawValue)")
                #endif
            } else {
                // Fallback: stage (shouldn't normally happen)
                commissioningState.stagedACLs = entries
                #if DEBUG
                print("[ACL-WRITE] Staged \(entries.count) ACL entries (no fabric context)")
                #endif
            }
            return .allowed
        default:
            return .unsupportedWrite
        }
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        // ACL cluster has no commands — all operations are via attribute writes
        nil
    }

    // MARK: - Fabric Scoping

    /// The ACL attribute is fabric-scoped — each fabric's entries must be kept separate.
    public func isFabricScoped(attributeID: AttributeID) -> Bool {
        attributeID == AccessControlCluster.Attribute.acl
    }

    /// Filter the ACL array to only include entries belonging to the requesting fabric.
    ///
    /// ACL entries carry a fabricIndex field at context tag `0xFE`. Entries whose
    /// fabricIndex does not match the requesting fabric are removed from the result.
    public func filterFabricScopedAttribute(attributeID: AttributeID, value: TLVElement, fabricIndex: FabricIndex) -> TLVElement {
        guard attributeID == AccessControlCluster.Attribute.acl,
              case .array(let elements) = value else {
            return value
        }

        let filtered = elements.filter { element in
            guard case .structure(let fields) = element,
                  let fiValue = fields.first(where: { $0.tag == .contextSpecific(0xFE) })?.value.uintValue else {
                // If we can't read the fabricIndex, exclude the entry
                return false
            }
            return UInt8(fiValue) == fabricIndex.rawValue
        }

        return .array(filtered)
    }
}
