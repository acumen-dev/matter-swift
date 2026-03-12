// Thermostat.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Thermostat cluster (0x0201).
///
/// Provides an interface for controlling heating/cooling setpoints and
/// reading the local (measured) temperature. Temperatures are in 0.01°C units.
public enum ThermostatCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Local (measured) temperature. Int16 (0.01°C, nullable).
        public static let localTemperature            = AttributeID(rawValue: 0x0000)
        /// Occupied cooling setpoint. Int16 (0.01°C).
        public static let occupiedCoolingSetpoint     = AttributeID(rawValue: 0x0011)
        /// Occupied heating setpoint. Int16 (0.01°C).
        public static let occupiedHeatingSetpoint     = AttributeID(rawValue: 0x0012)
        /// Control sequence of operation. Enum8.
        public static let controlSequenceOfOperation  = AttributeID(rawValue: 0x001B)
        /// System mode (0=Off, 1=Auto, 3=Cool, 4=Heat). Enum8.
        public static let systemMode                  = AttributeID(rawValue: 0x001C)
    }

    // MARK: - Command IDs

    public enum Command {
        /// Raise or lower the setpoint(s).
        public static let setpointRaiseLower = CommandID(rawValue: 0x00)
    }
}
