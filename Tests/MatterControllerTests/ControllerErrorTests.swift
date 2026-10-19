// ControllerErrorTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterController

@Suite("ControllerError")
struct ControllerErrorTests {

    @Test("isStopped is true for the messenger's stopped error, raw or as the controller maps it")
    func stoppedForms() {
        #expect(ControllerError.isStopped(MessagingError.stopped))
        #expect(ControllerError.isStopped(ControllerError.transportError("\(MessagingError.stopped)")))
    }

    @Test("isStopped is false for any other error, another transport error included")
    func otherErrors() {
        #expect(!ControllerError.isStopped(ControllerError.transportError("send failed")))
        #expect(!ControllerError.isStopped(ControllerError.transportError("\(MessagingError.exchangeClosed)")))
        #expect(!ControllerError.isStopped(MessagingError.sessionClosed))
        #expect(!ControllerError.isStopped(ControllerError.timeout("stopped")))
        #expect(!ControllerError.isStopped(CancellationError()))
    }
}
