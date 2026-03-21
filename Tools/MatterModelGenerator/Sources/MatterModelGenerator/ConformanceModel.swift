// ConformanceModel.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Represents a Matter conformance rule parsed from XML conformance elements.
indirect enum Conformance {
    case mandatory
    case optional
    case provisional
    case deprecated
    case disallowed
    /// Mandatory if the expression is true.
    case mandatoryIf(ConformanceExpression)
    /// Optional if the expression is true.
    case optionalIf(ConformanceExpression)
    /// Otherwise conformance: a list of (conformance, condition) pairs tried in order.
    case otherwise([Conformance])
    /// Unknown/unparsed conformance.
    case unknown
}

/// A boolean expression over features and attributes used in conditional conformance.
indirect enum ConformanceExpression {
    case feature(String)
    case attribute(String)
    case not(ConformanceExpression)
    case or([ConformanceExpression])
    case and([ConformanceExpression])
    case condition(String)
}

// MARK: - Text Rendering

extension Conformance {
    /// Renders the conformance as a human-readable doc comment fragment.
    var description: String {
        switch self {
        case .mandatory:
            return "mandatory"
        case .optional:
            return "optional"
        case .provisional:
            return "provisional"
        case .deprecated:
            return "deprecated"
        case .disallowed:
            return "disallowed"
        case .mandatoryIf(let expr):
            return "mandatory when \(expr.description)"
        case .optionalIf(let expr):
            return "optional when \(expr.description)"
        case .otherwise(let conformances):
            return conformances.map(\.description).joined(separator: " | ")
        case .unknown:
            return ""
        }
    }
}

extension ConformanceExpression {
    var description: String {
        switch self {
        case .feature(let name):
            return name
        case .attribute(let name):
            return name
        case .not(let expr):
            let inner = expr.description
            if case .or = expr { return "!(\(inner))" }
            if case .and = expr { return "!(\(inner))" }
            return "!\(inner)"
        case .or(let exprs):
            return exprs.map(\.description).joined(separator: " | ")
        case .and(let exprs):
            return exprs.map(\.description).joined(separator: " & ")
        case .condition(let name):
            return name
        }
    }
}

// MARK: - Swift Code Generation

extension Conformance {

    /// Converts this conformance to Swift source code for a `SpecConformance` literal.
    ///
    /// Feature codes (e.g., "LT", "HS") are resolved to bit masks using the
    /// provided mapping. Unresolvable references fall back to `.optional`.
    func toSwiftCode(featureCodeToBit: [String: Int]) -> String {
        switch self {
        case .mandatory:
            return ".mandatory"
        case .optional:
            return ".optional"
        case .provisional, .unknown:
            return ".optional"
        case .deprecated:
            return ".deprecated"
        case .disallowed:
            return ".disallowed"
        case .mandatoryIf(let expr):
            if let condCode = expr.toConditionCode(featureCodeToBit: featureCodeToBit) {
                return ".mandatoryIf(\(condCode))"
            }
            return ".optional"
        case .optionalIf(let expr):
            if let condCode = expr.toConditionCode(featureCodeToBit: featureCodeToBit) {
                return ".optionalIf(\(condCode))"
            }
            return ".optional"
        case .otherwise(let conformances):
            // Find first conditional arm (mandatoryIf/optionalIf)
            for conf in conformances {
                switch conf {
                case .mandatoryIf(let expr):
                    if let condCode = expr.toConditionCode(featureCodeToBit: featureCodeToBit) {
                        return ".mandatoryIf(\(condCode))"
                    }
                case .optionalIf(let expr):
                    if let condCode = expr.toConditionCode(featureCodeToBit: featureCodeToBit) {
                        return ".optionalIf(\(condCode))"
                    }
                case .mandatory:
                    return ".mandatory"
                case .optional:
                    continue  // skip bare optional, look for conditional
                default:
                    break
                }
            }
            // Fall back to first absolute conformance
            for conf in conformances {
                switch conf {
                case .mandatory:
                    return ".mandatory"
                case .optional:
                    return ".optional"
                case .deprecated:
                    return ".deprecated"
                case .disallowed:
                    return ".disallowed"
                default:
                    continue
                }
            }
            return ".optional"
        }
    }
}

extension ConformanceExpression {

    /// Converts this expression to Swift source code for a `SpecCondition` literal.
    ///
    /// Returns `nil` if the expression references features not in the map.
    func toConditionCode(featureCodeToBit: [String: Int]) -> String? {
        switch self {
        case .feature(let code):
            guard let bit = featureCodeToBit[code] else { return nil }
            return ".feature(1 << \(bit))"
        case .attribute:
            // Attribute-based conformance cannot be evaluated at registration time
            return nil
        case .condition:
            // Named conditions (Zigbee, etc.) cannot be evaluated
            return nil
        case .not(let expr):
            guard let inner = expr.toConditionCode(featureCodeToBit: featureCodeToBit) else { return nil }
            return ".not(\(inner))"
        case .or(let exprs):
            let codes = exprs.compactMap { $0.toConditionCode(featureCodeToBit: featureCodeToBit) }
            if codes.isEmpty { return nil }
            if codes.count == 1 { return codes[0] }
            return ".or([\(codes.joined(separator: ", "))])"
        case .and(let exprs):
            let codes = exprs.compactMap { $0.toConditionCode(featureCodeToBit: featureCodeToBit) }
            if codes.isEmpty { return nil }
            if codes.count == 1 { return codes[0] }
            return ".and([\(codes.joined(separator: ", "))])"
        }
    }
}
