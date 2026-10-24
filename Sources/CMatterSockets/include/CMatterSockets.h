// CMatterSockets.h
// Copyright 2026 Monagle Pty Ltd
//
// Thin POSIX shim for UDP sockets that pin the outgoing interface / source
// address per datagram with PKTINFO control messages, and report the arrival
// interface / destination address on receive. A datagram sent this way keeps
// the socket's bound source port (unlike binding a fresh socket per interface).
//
// Platform notes:
//  - Darwin: IPV6_PKTINFO / IP_PKTINFO cmsgs on sendmsg; receive enabled with
//    IPV6_RECVPKTINFO / IP_RECVPKTINFO. Route probing scopes with
//    IPV6_BOUND_IF / IP_BOUND_IF.
//  - Linux: IPV6_PKTINFO / IP_PKTINFO cmsgs; receive enabled with
//    IPV6_RECVPKTINFO / IP_PKTINFO. Route probing scopes with
//    IPV6_UNICAST_IF / IP_UNICAST_IF (both take the index in network byte order).

#ifndef CMATTERSOCKETS_H
#define CMATTERSOCKETS_H

// Must precede every system include so Darwin exposes the RFC 3542 PKTINFO API
// (the module build otherwise imports <netinet/in.h> without it).
#ifdef __APPLE__
#ifndef __APPLE_USE_RFC_3542
#define __APPLE_USE_RFC_3542 1
#endif
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Open a non-blocking-agnostic UDP socket bound to the wildcard address on
/// `port` (0 = ephemeral). IPv6 sockets are V6ONLY. SO_REUSEADDR is set and
/// packet-info reception is enabled. Returns the fd, or -1 with `*err` = errno.
int cms_open_udp(int family, uint16_t port, int *err);

/// sendmsg to `dst`. When `ifindex` != 0 or `src_literal` is a non-empty
/// address literal, a PKTINFO cmsg pins the interface / source address.
/// Sends with MSG_DONTWAIT: a full send buffer fails with EAGAIN/EWOULDBLOCK
/// instead of blocking. Returns bytes sent, or -1 with errno set.
ssize_t cms_send(int fd, const void *buf, size_t len,
                 const struct sockaddr *dst, socklen_t dstlen,
                 uint32_t ifindex, const char *src_literal);

/// recvmsg with `flags` (e.g. MSG_DONTWAIT). Fills the sender, the arrival
/// interface index (0 if unknown) and the destination address literal (empty
/// if unknown, never carries a zone).
/// Returns bytes received, or -1 with errno set.
ssize_t cms_recv(int fd, void *buf, size_t len,
                 struct sockaddr_storage *from,
                 uint32_t *ifindex, char *dst_literal, size_t dst_cap,
                 int flags);

/// Ask the kernel which source address it would use to reach `peer_literal`,
/// optionally scoped to `ifindex` (0 = unscoped). `scope_ifindex` becomes the
/// sin6_scope_id for link-local IPv6 peers. Returns 0 and writes the source
/// literal to `src_out`, otherwise an errno value.
int cms_route_probe(int family, const char *peer_literal, uint32_t scope_ifindex,
                    uint32_t ifindex, char *src_out, size_t src_cap);

/// Local port the socket is bound to (host order), 0 on failure.
uint16_t cms_bound_port(int fd);

#ifdef __cplusplus
}
#endif

#endif
