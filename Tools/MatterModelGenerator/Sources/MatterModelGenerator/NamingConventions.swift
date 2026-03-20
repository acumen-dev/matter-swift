// NamingConventions.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

enum NamingConventions {

    /// Converts a cluster name from XML (e.g., "On/Off Cluster", "Level Control")
    /// to a Swift enum name (e.g., "OnOffCluster", "LevelControlCluster").
    static func clusterEnumName(from xmlName: String) -> String {
        // Strip trailing " Cluster" if present
        var name = xmlName
        if name.hasSuffix(" Cluster") {
            name = String(name.dropLast(8))
        }

        // Convert to PascalCase, removing spaces and slashes
        let pascal = toPascalCase(name)
        return pascal + "Cluster"
    }

    /// Converts a cluster name from XML to a ClusterID property name.
    /// e.g., "On/Off Cluster" → "onOff", "Level Control" → "levelControl"
    static func clusterIDPropertyName(from xmlName: String) -> String {
        var name = xmlName
        if name.hasSuffix(" Cluster") {
            name = String(name.dropLast(8))
        }
        return toCamelCase(name)
    }

    /// Converts a device type name from XML to a DeviceTypeID property name.
    /// e.g., "On/Off Light" → "onOffLight", "Color Temperature Light" → "colorTemperatureLight"
    static func deviceTypePropertyName(from xmlName: String) -> String {
        return toCamelCase(xmlName)
    }

    /// Converts an attribute/command/event name to a Swift property name (camelCase).
    /// Handles PascalCase names (e.g., "OnOff"), names with spaces (e.g., "Status Codes"),
    /// and acronym runs (e.g., "ACLEntry" → "aclEntry").
    static func propertyName(from xmlName: String) -> String {
        guard !xmlName.isEmpty else { return xmlName }

        // If the name contains spaces, slashes, or hyphens, convert through PascalCase first
        if xmlName.contains(" ") || xmlName.contains("/") || xmlName.contains("-") {
            let pascal = toPascalCase(xmlName)
            return lowercaseFirst(pascal)
        }

        return lowercaseFirst(xmlName)
    }

    /// Lowercases the leading uppercase run of a PascalCase identifier.
    /// "OnOff" → "onOff", "ACLEntry" → "aclEntry", "GTIN" → "gtin"
    private static func lowercaseFirst(_ name: String) -> String {
        let chars = Array(name)
        var uppercaseRun = 0

        for i in 0..<chars.count {
            if chars[i].isUppercase {
                uppercaseRun = i + 1
            } else {
                break
            }
        }

        if uppercaseRun <= 1 {
            return name.prefix(1).lowercased() + name.dropFirst()
        }
        if uppercaseRun == chars.count {
            return name.lowercased()
        }
        let prefixEnd = uppercaseRun - 1
        return name.prefix(prefixEnd).lowercased() + name.dropFirst(prefixEnd)
    }

    /// Converts an enum case name to Swift camelCase.
    /// e.g., "DelayedAllOff" → "delayedAllOff", "DyingLight" → "dyingLight"
    /// Handles names starting with digits by prefixing with underscore.
    static func enumCaseName(from xmlName: String) -> String {
        var name = propertyName(from: xmlName)
        // Swift identifiers cannot start with a digit
        if let first = name.first, first.isNumber {
            name = "_" + name
        }
        return name
    }

    /// Converts a bitmap field name to Swift camelCase.
    static func bitmapFieldName(from xmlName: String) -> String {
        return propertyName(from: xmlName)
    }

    /// Converts a feature name to Swift camelCase property name.
    /// e.g., "Lighting" → "lighting", "DeadFrontBehavior" → "deadFrontBehavior"
    static func featurePropertyName(from xmlName: String) -> String {
        return propertyName(from: xmlName)
    }

    /// Generates a filename for a cluster.
    /// e.g., "OnOffCluster" → "OnOffCluster.generated.swift"
    static func clusterFileName(enumName: String) -> String {
        return "\(enumName).generated.swift"
    }

    // MARK: - Private Helpers

    /// Converts a string with spaces and slashes to PascalCase.
    /// e.g., "On/Off" → "OnOff", "Level Control" → "LevelControl"
    private static func toPascalCase(_ string: String) -> String {
        // Split on spaces, slashes, hyphens, underscores
        let words = string.components(separatedBy: CharacterSet(charactersIn: " /-_"))
            .filter { !$0.isEmpty }

        return words.map { word in
            // Capitalize first letter, keep rest as-is
            word.prefix(1).uppercased() + word.dropFirst()
        }.joined()
    }

    /// Converts a string with spaces and slashes to camelCase.
    private static func toCamelCase(_ string: String) -> String {
        let pascal = toPascalCase(string)
        return propertyName(from: pascal)
    }
}
