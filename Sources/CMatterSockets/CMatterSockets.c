// CMatterSockets.c
// Copyright 2026 Monagle Pty Ltd

#ifdef __APPLE__
#define __APPLE_USE_RFC_3542 1
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include "CMatterSockets.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

int cms_open_udp(int family, uint16_t port, int *err) {
    if (family != AF_INET && family != AF_INET6) {
        if (err) *err = EAFNOSUPPORT;
        return -1;
    }
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) { if (err) *err = errno; return -1; }
    int one = 1;
    // SO_REUSEADDR is best-effort: failing to set it does not break the design.
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    int rc;
    if (family == AF_INET6) {
        // Not best-effort: a silent dual-stack socket would break the per-family design.
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) != 0) {
            if (err) *err = errno;
            close(fd);
            return -1;
        }
        rc = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof one);
    } else {
#ifdef __APPLE__
        rc = setsockopt(fd, IPPROTO_IP, IP_RECVPKTINFO, &one, sizeof one);
#else
        rc = setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof one);
#endif
    }
    if (rc != 0) { if (err) *err = errno; close(fd); return -1; }

    if (family == AF_INET6) {
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof a);
#ifdef __APPLE__
        a.sin6_len = sizeof a;
#endif
        a.sin6_family = AF_INET6;
        a.sin6_port = htons(port);
        rc = bind(fd, (struct sockaddr *)&a, sizeof a);
    } else {
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
#ifdef __APPLE__
        a.sin_len = sizeof a;
#endif
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        rc = bind(fd, (struct sockaddr *)&a, sizeof a);
    }
    if (rc != 0) { if (err) *err = errno; close(fd); return -1; }
    if (err) *err = 0;
    return fd;
}

ssize_t cms_send(int fd, const void *buf, size_t len,
                 const struct sockaddr *dst, socklen_t dstlen,
                 uint32_t ifindex, const char *src_literal) {
    int have_src = src_literal != NULL && src_literal[0] != '\0';
    struct iovec iov;
    iov.iov_base = (void *)buf;
    iov.iov_len = len;

    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_name = (void *)dst;
    m.msg_namelen = dstlen;
    m.msg_iov = &iov;
    m.msg_iovlen = 1;

    union {
        char v6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
        char v4[CMSG_SPACE(sizeof(struct in_pktinfo))];
        struct cmsghdr align;
    } cbuf;
    memset(&cbuf, 0, sizeof cbuf);

    if (ifindex != 0 || have_src) {
        if (dst->sa_family == AF_INET6) {
            struct in6_pktinfo pi;
            memset(&pi, 0, sizeof pi);
            if (have_src && inet_pton(AF_INET6, src_literal, &pi.ipi6_addr) != 1) {
                errno = EINVAL;
                return -1;
            }
            pi.ipi6_ifindex = ifindex;
            m.msg_control = cbuf.v6;
            m.msg_controllen = sizeof cbuf.v6;
            struct cmsghdr *c = CMSG_FIRSTHDR(&m);
            c->cmsg_level = IPPROTO_IPV6;
            c->cmsg_type = IPV6_PKTINFO;
            c->cmsg_len = CMSG_LEN(sizeof pi);
            memcpy(CMSG_DATA(c), &pi, sizeof pi);
        } else if (dst->sa_family == AF_INET) {
            struct in_pktinfo pi;
            memset(&pi, 0, sizeof pi);
            if (have_src && inet_pton(AF_INET, src_literal, &pi.ipi_spec_dst) != 1) {
                errno = EINVAL;
                return -1;
            }
            pi.ipi_ifindex = ifindex;
            m.msg_control = cbuf.v4;
            m.msg_controllen = sizeof cbuf.v4;
            struct cmsghdr *c = CMSG_FIRSTHDR(&m);
            c->cmsg_level = IPPROTO_IP;
            c->cmsg_type = IP_PKTINFO;
            c->cmsg_len = CMSG_LEN(sizeof pi);
            memcpy(CMSG_DATA(c), &pi, sizeof pi);
        } else {
            errno = EAFNOSUPPORT;
            return -1;
        }
    }
    return sendmsg(fd, &m, 0);
}

ssize_t cms_recv(int fd, void *buf, size_t len,
                 struct sockaddr_storage *from,
                 uint32_t *ifindex, char *dst_literal, size_t dst_cap) {
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = len;

    union {
        char space[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(struct in_pktinfo)) + 64];
        struct cmsghdr align;
    } cbuf;
    memset(&cbuf, 0, sizeof cbuf);

    struct msghdr m;
    memset(&m, 0, sizeof m);
    memset(from, 0, sizeof *from);
    m.msg_name = from;
    m.msg_namelen = sizeof *from;
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = cbuf.space;
    m.msg_controllen = sizeof cbuf.space;

    if (ifindex) *ifindex = 0;
    if (dst_literal && dst_cap > 0) dst_literal[0] = '\0';

    ssize_t n = recvmsg(fd, &m, 0);
    if (n < 0) return n;

    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
        if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo pi;
            memcpy(&pi, CMSG_DATA(c), sizeof pi);
            if (ifindex) *ifindex = pi.ipi6_ifindex;
            if (dst_literal && dst_cap > 0) inet_ntop(AF_INET6, &pi.ipi6_addr, dst_literal, (socklen_t)dst_cap);
        } else if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo pi;
            memcpy(&pi, CMSG_DATA(c), sizeof pi);
            if (ifindex) *ifindex = (uint32_t)pi.ipi_ifindex;
            if (dst_literal && dst_cap > 0) inet_ntop(AF_INET, &pi.ipi_addr, dst_literal, (socklen_t)dst_cap);
        }
    }
    return n;
}

int cms_route_probe(int family, const char *peer_literal, uint32_t scope_ifindex,
                    uint32_t ifindex, char *src_out, size_t src_cap) {
    if (family != AF_INET && family != AF_INET6) return EAFNOSUPPORT;
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) return errno;

    if (ifindex != 0) {
        int rc;
#ifdef __APPLE__
        unsigned int idx = ifindex;
        rc = family == AF_INET6
            ? setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof idx)
            : setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof idx);
#else
        // Both options take the index in network byte order (the kernel ntohl()s
        // it); a host-order index names a nonexistent interface: EADDRNOTAVAIL.
        uint32_t idx = htonl(ifindex);
        rc = family == AF_INET6
            ? setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, &idx, sizeof idx)
            : setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, &idx, sizeof idx);
#endif
        if (rc != 0) { int e = errno; close(fd); return e; }
    }

    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    socklen_t sl;
    if (family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
#ifdef __APPLE__
        a->sin6_len = sizeof *a;
#endif
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(9);
        if (inet_pton(AF_INET6, peer_literal, &a->sin6_addr) != 1) { close(fd); return EINVAL; }
        a->sin6_scope_id = scope_ifindex;
        sl = sizeof *a;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
#ifdef __APPLE__
        a->sin_len = sizeof *a;
#endif
        a->sin_family = AF_INET;
        a->sin_port = htons(9);
        if (inet_pton(AF_INET, peer_literal, &a->sin_addr) != 1) { close(fd); return EINVAL; }
        sl = sizeof *a;
    }
    if (connect(fd, (struct sockaddr *)&ss, sl) != 0) { int e = errno; close(fd); return e; }

    struct sockaddr_storage local;
    socklen_t ll = sizeof local;
    if (getsockname(fd, (struct sockaddr *)&local, &ll) != 0) { int e = errno; close(fd); return e; }
    close(fd);

    const void *addr = family == AF_INET6
        ? (const void *)&((struct sockaddr_in6 *)&local)->sin6_addr
        : (const void *)&((struct sockaddr_in *)&local)->sin_addr;
    if (src_out == NULL || src_cap == 0 || inet_ntop(family, addr, src_out, (socklen_t)src_cap) == NULL) return ENOSPC;
    return 0;
}

uint16_t cms_bound_port(int fd) {
    struct sockaddr_storage ss;
    socklen_t l = sizeof ss;
    if (getsockname(fd, (struct sockaddr *)&ss, &l) != 0) return 0;
    if (ss.ss_family == AF_INET6) return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    if (ss.ss_family == AF_INET) return ntohs(((struct sockaddr_in *)&ss)->sin_port);
    return 0;
}
