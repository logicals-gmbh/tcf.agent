/*******************************************************************************
 * Copyright (c) 2007, 2008 Wind River Systems, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *     Wind River Systems - initial API and implementation
 *******************************************************************************/

/*
 * Implements simple UDP based auto discovery.
 */

#include "mdep.h"
#include "config.h"

#if ENABLE_Discovery

#include <stddef.h>
#include <errno.h>
#include <assert.h>
#include "tcf.h"
#include "discovery.h"
#include "discovery_udp.h"
#include "myalloc.h"
#include "events.h"
#include "errors.h"
#include "trace.h"
#include "peer.h"
#include "ip_ifc.h"
#include "asyncreq.h"

#define MAX_IFC                 10
#define MAX_RECV_ERRORS         8

static int ifc_cnt;
static ip_ifc_info ifc_list[MAX_IFC];
static time_t last_req_slaves_time[MAX_IFC];
static int beacon_ok[MAX_IFC];

static int udp_server_port = 0;
static int udp_server_socket = -1;
static int udp_server_generation = 0;

static AsyncReqInfo recvreq;
static int recvreq_error_cnt = 0;
static int recvreq_generation = 0;
static struct sockaddr_in recvreq_addr;
static char recvreq_buf[PKT_SIZE];
static int recvreq_pending = 0;

static time_t last_master_packet_time = 0;

typedef struct SlaveInfo {
    struct sockaddr_in addr;
    time_t last_packet_time;        /* Time of last packet from this slave */
    time_t last_req_slaves_time;    /* Time of last UDP_REQ_SLAVES packet from this slave */
} SlaveInfo;

static SlaveInfo * slave_info = NULL;
static int slave_cnt = 0;
static int slave_max = 0;

#define MAX(x,y) ((x) > (y) ? (x) : (y))

static void app_char(char * buf, int * pos, char ch) {
    if (*pos < PKT_SIZE) buf[*pos] = ch;
    (*pos)++;
}

static void app_str(char * buf, int * pos, char * str) {
    while (*str) {
        if (*pos < PKT_SIZE) buf[*pos] = *str;
        (*pos)++;
        str++;
    }
}

static void app_strz(char * buf, int * pos, char * str) {
    app_str(buf, pos, str);
    app_char(buf, pos, 0);
}

static void app_addr(char * buf, int * pos, struct sockaddr_in * addr) {
    char str[256];
    snprintf(str, sizeof(str), "%d:%s", ntohs(addr->sin_port), inet_ntoa(addr->sin_addr));
    app_strz(buf, pos, str);
}

static int get_addr(char * buf, int * pos, struct sockaddr_in * addr) {
    char * port = buf + *pos;
    char * host = buf + *pos;
    int len = strlen(buf + *pos);

    while (*host && *host != ':') host++;
    if (*host == ':') *host++ = 0;
    *pos += len + 1;

    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
#ifdef _WRS_KERNEL
    /* VxWorks inet_aton() return codes are opposite to standard */
    if (inet_aton(host, &addr->sin_addr) != OK) return 0;
#else
    if (inet_aton(host, &addr->sin_addr) == 0) return 0;
#endif
    addr->sin_port = htons(atoi(port));
    return 1;
}

static void trigger_recv(void);
static void udp_server_recv(void * x);

static void delayed_server_recv(void * x) {
    assert(recvreq_pending);
    if (recvreq_generation != udp_server_generation) {
        /* Cancel and restart */
        recvreq_pending = 0;
        trigger_recv();
    }
    else {
        async_req_post(&recvreq);
    }
}

static void trigger_recv(void) {
    if (recvreq_pending || udp_server_socket < 0) return;
    recvreq_pending = 1;
    recvreq_generation = udp_server_generation;
    recvreq.done = udp_server_recv;
    recvreq.client_data = NULL;
    recvreq.type = AsyncReqRecvFrom;
    recvreq.u.sio.sock = udp_server_socket;
    recvreq.u.sio.flags = 0;
    recvreq.u.sio.bufp = recvreq_buf;
    recvreq.u.sio.bufsz = sizeof recvreq_buf;
    recvreq.u.sio.addr = (struct sockaddr *)&recvreq_addr;
    recvreq.u.sio.addrlen = sizeof recvreq_addr;
    memset(&recvreq_addr, 0, sizeof recvreq_addr);
    if (recvreq_error_cnt >= MAX_RECV_ERRORS) {
        /* Delay the request to aviod flooding with error reports */
        post_event_with_delay(delayed_server_recv, NULL, 1000000);
    }
    else {
        async_req_post(&recvreq);
    }
}

static int create_server_socket(void) {
    int sock = -1;
    int error = 0;
    char * reason = NULL;
    const int i = 1;
    struct addrinfo hints;
    struct addrinfo * reslist = NULL;
    struct addrinfo * res = NULL;
    struct sockaddr_in local_addr;
    int local_addr_size = sizeof(local_addr);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;
    error = loc_getaddrinfo(NULL, "", &hints, &reslist);
    if (error) {
        trace(LOG_ALWAYS, "getaddrinfo error: %s", loc_gai_strerror(error));
        return error;
    }
    for (res = reslist; res != NULL; res = res->ai_next) {
        int def_port = 0;
        sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock < 0) {
            error = errno;
            reason = "create";
            continue;
        }
        if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&i, sizeof(i)) < 0) {
            error = errno;
            reason = "setsockopt(SO_BROADCAST)";
            closesocket(sock);
            sock = -1;
            continue;
        }
        if (res->ai_addr->sa_family == AF_INET) {
            struct sockaddr_in addr;
            assert(sizeof(addr) >= res->ai_addrlen);
            memset(&addr, 0, sizeof(addr));
            memcpy(&addr, res->ai_addr, res->ai_addrlen);
            if (addr.sin_port == 0) {
                addr.sin_port = htons(DISCOVERY_TCF_PORT);
                if (!bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
                    def_port = 1;
                }
                else {
                    trace(LOG_DISCOVERY, "Cannot bind to default UDP port %d: %s",
                        DISCOVERY_TCF_PORT, errno_to_str(errno));
                    if (udp_server_socket >= 0 && recvreq_error_cnt < MAX_RECV_ERRORS) {
                        loc_freeaddrinfo(reslist);
                        closesocket(sock);
                        return 0;
                    }
                }
            }
        }
        if (!def_port && bind(sock, res->ai_addr, res->ai_addrlen)) {
            error = errno;
            reason = "bind";
            closesocket(sock);
            sock = -1;
            continue;
        }
        if (getsockname(sock, (struct sockaddr *)&local_addr, &local_addr_size)) {
            error = errno;
            reason = "getsockname";
            closesocket(sock);
            sock = -1;
            continue;
        }
        /* Only bind once - don't see how getaddrinfo with the given
         * arguments could return more then one anyway */
        break;
    }
    if (sock < 0) {
        assert(error);
        trace(LOG_ALWAYS, "Socket %s error: %s", reason, errno_to_str(error));
        loc_freeaddrinfo(reslist);
        return error;
    }

    if (udp_server_socket >= 0) closesocket(udp_server_socket);
    udp_server_port = ntohs(local_addr.sin_port);
    udp_server_socket = sock;
    udp_server_generation++;
    loc_freeaddrinfo(reslist);
    trace(LOG_DISCOVERY, "UDP discovery server created at port %d", udp_server_port);
    trigger_recv();
    return 0;
}

static int udp_send_peer_info(PeerServer * ps, void * arg) {
    struct sockaddr_in * addr = arg;
    char * transport = NULL;
    char * host = NULL;
    struct in_addr src_addr;
    int n;

    if ((ps->flags & PS_FLAG_PRIVATE) != 0) return 0;
    if ((ps->flags & PS_FLAG_LOCAL) == 0) return 0;
    if ((ps->flags & PS_FLAG_DISCOVERABLE) == 0) return 0;

    transport = peer_server_getprop(ps, "TransportName", "");
    if (strcmp(transport, "TCP") != 0 && strcmp(transport, "UDP") != 0) return 0;
    host = peer_server_getprop(ps, "Host", NULL);
#ifdef _WRS_KERNEL
    /* VxWorks inet_aton() return codes are opposite to standard */
    if (host == NULL || inet_aton(host, &src_addr) != OK) return 0;
#else
    if (host == NULL || inet_aton(host, &src_addr) == 0) return 0;
#endif
    if (peer_server_getprop(ps, "Port", NULL) == NULL) return 0;

    for (n = 0; n < ifc_cnt; n++) {
        int i;
        int pos = 0;
        int seenName = 0;
        int seenOSName = 0;
        struct sockaddr_in * dst_addr;
        struct sockaddr_in dst_addr_buf;
        char buf[PKT_SIZE];
        ip_ifc_info * ifc = ifc_list + n;

        if (src_addr.s_addr != INADDR_ANY &&
            (ifc->addr & ifc->mask) != (src_addr.s_addr & ifc->mask)) {
            /* Server address not matching this interface */
            continue;
        }
        if (addr != NULL &&
            (ifc->addr & ifc->mask) != (addr->sin_addr.s_addr & ifc->mask)) {
            /* Packet destination address not matching this interface */
            continue;
        }
        if (addr == NULL) {
            dst_addr = &dst_addr_buf;
            memset(&dst_addr_buf, 0, sizeof dst_addr_buf);
            dst_addr->sin_family = AF_INET;
            dst_addr->sin_port = htons(DISCOVERY_TCF_PORT);
            dst_addr->sin_addr.s_addr = ifc->addr | ~ifc->mask;
            beacon_ok[n] = 1;
        }
        else {
            dst_addr = addr;
        }
        trace(LOG_DISCOVERY, "ACK_INFO to %s:%d, ID=%s",
            inet_ntoa(dst_addr->sin_addr), ntohs(dst_addr->sin_port), ps->id);

        buf[pos++] = 'T';
        buf[pos++] = 'C';
        buf[pos++] = 'F';
        buf[pos++] = '1';
        buf[pos++] = UDP_ACK_INFO;
        buf[pos++] = 0;
        buf[pos++] = 0;
        buf[pos++] = 0;
        app_str(buf, &pos, "ID=");
        app_strz(buf, &pos, ps->id);
        for (i = 0; i < ps->ind; i++) {
            char *name = ps->list[i].name;
            assert(strcmp(name, "ID") != 0);
            app_str(buf, &pos, name);
            app_char(buf, &pos, '=');
            if (strcmp(name, "Name") == 0) {
                seenName = 1;
            }
            if (strcmp(name, "OSName") == 0) {
                seenOSName = 1;
            }
            app_strz(buf, &pos, ps->list[i].value);
        }
        if (!seenName) {
            app_strz(buf, &pos, "Name=TCF Agent");
        }
        if (!seenOSName) {
            app_str(buf, &pos, "OSName=");
            app_strz(buf, &pos, get_os_name());
        }
        if (sendto(udp_server_socket, buf, pos, 0, (struct sockaddr *)dst_addr, sizeof *dst_addr) < 0) {
            trace(LOG_ALWAYS, "Can't send UDP discovery reply packet to %s: %s",
                  inet_ntoa(dst_addr->sin_addr), errno_to_str(errno));
        }
        if (addr == NULL) {
            /* Send to slaves */
            int n = 0;
            while (n < slave_cnt) {
                SlaveInfo * s = slave_info + n++;
                if ((ifc->addr & ifc->mask) != (s->addr.sin_addr.s_addr & ifc->mask)) {
                    /* Slave address not matching this interface */
                    continue;
                }
                trace(LOG_DISCOVERY, "ACK_INFO to %s:%d, ID=%s",
                    inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port), ps->id);
                if (sendto(udp_server_socket, buf, pos, 0, (struct sockaddr *)&s->addr, sizeof s->addr) < 0) {
                    trace(LOG_ALWAYS, "Can't send UDP discovery reply packet to %s:%d: %s",
                          inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port), errno_to_str(errno));
                }
            }
        }
    }
    return 0;
}

static void udp_send_ack_info(struct sockaddr_in * addr) {
    assert(is_dispatch_thread());
    peer_server_iter(udp_send_peer_info, addr);
}

static void udp_send_req_info(struct sockaddr_in * addr) {
    int i = 0;
    int n = 0;
    char buf[PKT_SIZE];
    ip_ifc_info * ifc;

    trace(LOG_DISCOVERY, "Broadcast REQ_INFO");

    buf[i++] = 'T';
    buf[i++] = 'C';
    buf[i++] = 'F';
    buf[i++] = '1';
    buf[i++] = UDP_REQ_INFO;
    buf[i++] = 0;
    buf[i++] = 0;
    buf[i++] = 0;

    if (addr == NULL) {
        /* Broadcast to all masters */
        for (ifc = ifc_list; ifc < &ifc_list[ifc_cnt]; ifc++) {
            struct sockaddr_in dst_addr;
            memset(&dst_addr, 0, sizeof dst_addr);
            dst_addr.sin_family = AF_INET;
            dst_addr.sin_port = htons(DISCOVERY_TCF_PORT);
            dst_addr.sin_addr.s_addr = ifc->addr | ~ifc->mask;
            if (sendto(udp_server_socket, buf, i, 0, (struct sockaddr *)&dst_addr, sizeof dst_addr) < 0) {
                trace(LOG_ALWAYS, "Can't send UDP discovery request packet to %s:%d: %s",
                      inet_ntoa(dst_addr.sin_addr), ntohs(dst_addr.sin_port), errno_to_str(errno));
            }
        }
        /* Notify known slaves */
        n = 0;
        while (n < slave_cnt) {
            SlaveInfo * s = slave_info + n++;
            if (sendto(udp_server_socket, buf, i, 0, (struct sockaddr *)&s->addr, sizeof s->addr) < 0) {
                trace(LOG_ALWAYS, "Can't send UDP discovery request packet to %s:%d: %s",
                      inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port), errno_to_str(errno));
            }
        }
    }
    else {
        if (sendto(udp_server_socket, buf, i, 0, (struct sockaddr *)addr, sizeof *addr) < 0) {
            trace(LOG_ALWAYS, "Can't send UDP discovery request packet to %s:%d: %s",
                  inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), errno_to_str(errno));
        }
    }
}

static void udp_send_req_slaves(struct sockaddr_in * addr) {
    int i = 0;
    char buf[PKT_SIZE];

    trace(LOG_DISCOVERY, "REQ_SLAVES to %s:%d",
        inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

    buf[i++] = 'T';
    buf[i++] = 'C';
    buf[i++] = 'F';
    buf[i++] = '1';
    buf[i++] = UDP_REQ_SLAVES;
    buf[i++] = 0;
    buf[i++] = 0;
    buf[i++] = 0;

    if (sendto(udp_server_socket, buf, i, 0, (struct sockaddr *)addr, sizeof *addr) < 0) {
        trace(LOG_ALWAYS, "Can't send UDP discovery packet to %s:%d: %s",
              inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), errno_to_str(errno));
    }
}

static void udp_send_ack_slaves_one(SlaveInfo * slave) {
    char buf[PKT_SIZE];
    ip_ifc_info * ifc;
    time_t timenow = time(NULL);    

    for (ifc = ifc_list; ifc < &ifc_list[ifc_cnt]; ifc++) {
        int n = 0;
        int i = 0;
        if ((ifc->addr & ifc->mask) != (slave->addr.sin_addr.s_addr & ifc->mask)) continue;
        buf[i++] = 'T';
        buf[i++] = 'C';
        buf[i++] = 'F';
        buf[i++] = '1';
        buf[i++] = UDP_ACK_SLAVES;
        buf[i++] = 0;
        buf[i++] = 0;
        buf[i++] = 0;
        app_addr(buf, &i, &slave->addr);

        while (n < slave_cnt) {
            SlaveInfo * s = slave_info + n++;
            if (s->last_req_slaves_time + PEER_DATA_RETENTION_PERIOD < timenow) continue;
            trace(LOG_DISCOVERY, "ACK_SLAVES to %s:%d",
                inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port));
            if (sendto(udp_server_socket, buf, i, 0, (struct sockaddr *)&s->addr, sizeof(struct sockaddr_in)) < 0) {
                trace(LOG_ALWAYS, "Can't send UDP discovery packet to %s:%d: %s",
                      inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port), errno_to_str(errno));
            }
        }
    }
}

static void udp_send_ack_slaves_all(struct sockaddr_in * addr) {
    char buf[PKT_SIZE];
    ip_ifc_info * ifc;

    trace(LOG_DISCOVERY, "ACK_SLAVES to %s:%d",
        inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

    for (ifc = ifc_list; ifc < &ifc_list[ifc_cnt]; ifc++) {
        int n = 0;
        if ((ifc->addr & ifc->mask) != (addr->sin_addr.s_addr & ifc->mask)) continue;
        while (n < slave_cnt) {
            int i = 0;
            buf[i++] = 'T';
            buf[i++] = 'C';
            buf[i++] = 'F';
            buf[i++] = '1';
            buf[i++] = UDP_ACK_SLAVES;
            buf[i++] = 0;
            buf[i++] = 0;
            buf[i++] = 0;

            while (n < slave_cnt && i + 32 <= PKT_SIZE) {
                SlaveInfo * s = slave_info + n++;
                if ((ifc->addr & ifc->mask) != (s->addr.sin_addr.s_addr & ifc->mask)) continue;
                app_addr(buf, &i, &s->addr);
            }

            if (sendto(udp_server_socket, buf, i, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) < 0) {
                trace(LOG_ALWAYS, "Can't send UDP discovery packet to %s:%d: %s",
                      inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), errno_to_str(errno));
            }
        }
    }
}

static void udp_send_ack_slaves_beacon(void) {
    int n;
    for (n = 0; n < ifc_cnt; n++) {
        if (!beacon_ok[n]) {
            int i = 0;
            char buf[PKT_SIZE];
            ip_ifc_info * ifc = ifc_list + n;
            struct sockaddr_in addr;

            memset(&addr, 0, sizeof addr);
            addr.sin_family = AF_INET;
            addr.sin_port = htons(DISCOVERY_TCF_PORT);
            addr.sin_addr.s_addr = ifc->addr | ~ifc->mask;

            trace(LOG_DISCOVERY, "ACK_SLAVES (beacon) to %s:%d",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

            buf[i++] = 'T';
            buf[i++] = 'C';
            buf[i++] = 'F';
            buf[i++] = '1';
            buf[i++] = UDP_ACK_SLAVES;
            buf[i++] = 0;
            buf[i++] = 0;
            buf[i++] = 0;

            if (sendto(udp_server_socket, buf, i, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
                trace(LOG_ALWAYS, "Can't send UDP discovery packet to %s:%d: %s",
                      inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), errno_to_str(errno));
            }
        }
    }
}

static void udp_refresh_timer(void * arg) {
    time_t timenow = time(0);

    if (slave_cnt > 0) {
        /* Cleanup slave table */
        int i = 0;
        int j = 0;
        while (i < slave_cnt) {
            SlaveInfo * s = slave_info + i++;
            if (s->last_packet_time + PEER_DATA_RETENTION_PERIOD >= timenow) {
                if (j < i) slave_info[j] = *s;
                j++;
            }
        }
        slave_cnt = j;
    }

    if (udp_server_port != DISCOVERY_TCF_PORT && last_master_packet_time + PEER_DATA_RETENTION_PERIOD / 2 <= timenow) {
        /* No master reponces, try to become a master */
        create_server_socket();
    }

    /* Refresh list of network interfaces */
    ifc_cnt = build_ifclist(udp_server_socket, MAX_IFC, ifc_list);

    /* Broadcast peer info */
    memset(beacon_ok, 0, sizeof(beacon_ok));
    udp_send_ack_info(NULL);
    if (udp_server_port != DISCOVERY_TCF_PORT) udp_send_ack_slaves_beacon();

    post_event_with_delay(udp_refresh_timer, NULL, PEER_DATA_REFRESH_PERIOD * 1000000);
}

static int is_remote(struct sockaddr_in * addr) {
    int i;

    if (ntohs(addr->sin_port) != udp_server_port) return 1;
    for (i = 0; i < ifc_cnt; i++) {
        if (addr->sin_addr.s_addr == ifc_list[i].addr) return 0;
    }
    return 1;
}

static SlaveInfo * add_slave(struct sockaddr_in * addr) {
    int i = 0;
    SlaveInfo * s = NULL;
    while (i < slave_cnt) {
        s = slave_info + i++;
        if (memcmp(&s->addr, addr, sizeof(struct sockaddr_in)) == 0) {
            s->last_packet_time = time(0);
            return s;
        }
    }
    if (slave_max == 0) {
        assert(slave_cnt == 0);
        slave_max = 16;
        slave_info = loc_alloc(sizeof(SlaveInfo) * slave_max);
    }
    else if (slave_cnt >= slave_max) {
        assert(slave_cnt == slave_max);
        slave_max *= 2;
        slave_info = loc_realloc(slave_info, sizeof(SlaveInfo) * slave_max);
    }
    s = slave_info + slave_cnt++;
    s->addr = *addr;
    s->last_packet_time = time(0);
    udp_send_req_info(addr);
    udp_send_ack_slaves_one(s);
    return s;
}

static void udp_receive_req_info(void) {
    trace(LOG_DISCOVERY, "REQ_INFO from %s:%d",
        inet_ntoa(recvreq_addr.sin_addr), ntohs(recvreq_addr.sin_port));
    udp_send_ack_info(&recvreq_addr);
}

static void udp_receive_ack_info(void) {
    PeerServer * ps = peer_server_alloc();
    char * p = recvreq_buf + 8;
    char * e = recvreq_buf + recvreq.u.sio.rval;

    assert(is_dispatch_thread());
    while (p < e) {
        char * name = p;
        char * value = NULL;
        while (p < e && *p != '\0' && *p != '=') p++;
        if (p >= e || *p != '=') {
            p = NULL;
            break;
        }
        *p++ = '\0';
        value = p;
        while (p < e && *p != '\0') p++;
        if (p >= e) {
            p = NULL;
            break;
        }
        peer_server_addprop(ps, loc_strdup(name), loc_strdup(value));
        p++;
    }
    if (p != NULL && ps->id != NULL) {
        trace(LOG_DISCOVERY, "ACK_INFO from %s:%d, ID=%s",
            inet_ntoa(recvreq_addr.sin_addr), ntohs(recvreq_addr.sin_port), ps->id);
        ps->flags = PS_FLAG_DISCOVERABLE;
        peer_server_add(ps, PEER_DATA_RETENTION_PERIOD);
    }
    else {
        trace(LOG_ALWAYS, "Received malformed UDP ACK packet from %s:%d",
            inet_ntoa(recvreq_addr.sin_addr), ntohs(recvreq_addr.sin_port));
        peer_server_free(ps);
    }
}

static void udp_receive_req_slaves(void) {
    trace(LOG_DISCOVERY, "REQ_SLAVES from %s:%d",
        inet_ntoa(recvreq_addr.sin_addr), ntohs(recvreq_addr.sin_port));
    udp_send_ack_slaves_all(&recvreq_addr);
}

static void udp_receive_ack_slaves(void) {
    int pos = 8;
    int len = recvreq.u.sio.rval;
    trace(LOG_DISCOVERY, "ACK_SLAVES from %s:%d",
        inet_ntoa(recvreq_addr.sin_addr), ntohs(recvreq_addr.sin_port));
    while (pos < len) {
        struct sockaddr_in addr;
        if (get_addr(recvreq_buf, &pos, &addr)) {
            trace(LOG_DISCOVERY, "  Slave at %s:%d",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            add_slave(&addr);
        }
    }
}

static void udp_server_recv(void * x) {
    assert(recvreq_pending != 0);
    recvreq_pending = 0;
    if (recvreq.error != 0) {
        if (recvreq_generation != udp_server_generation) {
            recvreq_error_cnt = 0;
        }
        else {
            recvreq_error_cnt++;
            trace(LOG_ALWAYS, "UDP socket receive failed: %s", errno_to_str(recvreq.error));
        }
    }
    else {
        recvreq_error_cnt = 0;
        if (recvreq.u.sio.rval < 8 || strncmp(recvreq_buf, "TCF1", 4) != 0) {
            trace(LOG_ALWAYS, "Received malformed UDP packet from %s:%d",
                inet_ntoa(recvreq_addr.sin_addr), ntohs(recvreq_addr.sin_port));
        }
        else if (is_remote(&recvreq_addr)) {
            SlaveInfo * s = NULL;
            if (ntohs(recvreq_addr.sin_port) != DISCOVERY_TCF_PORT) {
                /* Packet from a slave, save its address */
                s = add_slave(&recvreq_addr);
            }
            switch (recvreq_buf[4]) {
            case UDP_REQ_INFO:
                udp_receive_req_info();
                break;
            case UDP_ACK_INFO:
                udp_receive_ack_info();
                break;
            case UDP_REQ_SLAVES:
                if (s != NULL) s->last_req_slaves_time = s->last_packet_time;
                udp_receive_req_slaves();
                break;
            case UDP_ACK_SLAVES:
                udp_receive_ack_slaves();
                break;
            }
            if (udp_server_port != DISCOVERY_TCF_PORT) {
                /* Packet from a master, ask for list of slaves */
                int n = 0;
                time_t timenow = time(NULL);
                for (n = 0; n < ifc_cnt; n++) {
                    ip_ifc_info * ifc = ifc_list + n;
                    if ((ifc->addr & ifc->mask) != (recvreq_addr.sin_addr.s_addr & ifc->mask)) continue;
                    if (timenow > last_req_slaves_time[n] + PEER_DATA_RETENTION_PERIOD / 3) {
                        udp_send_req_slaves(&recvreq_addr);
                        last_req_slaves_time[n] = timenow;
                    }
                    /* Remember time only if master is on local host */
                    if (ifc->addr == recvreq_addr.sin_addr.s_addr) last_master_packet_time = timenow;
                }
            }
        }
    }
    trigger_recv();
}

static void local_peer_changed(PeerServer * ps, int type, void * arg) {
    trace(LOG_DISCOVERY, "Peer changed: ps=0x%x, type=%d", ps, type);
    switch (type) {
    case PS_EVENT_ADDED:
    case PS_EVENT_CHANGED:
        udp_send_peer_info(ps, NULL);
        break;
    }
}

int discovery_start_udp(void) {
    int error = create_server_socket();
    if (error) return error;
    peer_server_add_listener(local_peer_changed, NULL);
    post_event_with_delay(udp_refresh_timer, NULL, PEER_DATA_REFRESH_PERIOD * 1000000);
    ifc_cnt = build_ifclist(udp_server_socket, MAX_IFC, ifc_list);
    udp_send_ack_info(NULL);
    udp_send_req_info(NULL);
    return 0;
}

#endif
