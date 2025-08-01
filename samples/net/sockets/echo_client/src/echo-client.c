/* echo-client.c - Networking echo client */

/*
 * Copyright (c) 2017 Intel Corporation.
 * Copyright (c) 2018 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * The echo-client application is acting as a client that is run in Zephyr OS,
 * and echo-server is run in the host acting as a server. The client will send
 * either unicast or multicast packets to the server which will reply the packet
 * back to the originator.
 *
 * In this sample application we create four threads that start to send data.
 * This might not be what you want to do in your app so caveat emptor.
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_echo_client_sample, LOG_LEVEL_DBG);

#include <zephyr/kernel.h>
#include <errno.h>
#include <stdio.h>

#include <zephyr/posix/sys/eventfd.h>

#include <zephyr/misc/lorem_ipsum.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/conn_mgr_monitor.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/ethernet_mgmt.h>

#if defined(CONFIG_USERSPACE)
#include <zephyr/app_memory/app_memdomain.h>
K_APPMEM_PARTITION_DEFINE(app_partition);
struct k_mem_domain app_domain;
#endif

#include "common.h"
#include "ca_certificate.h"

#define APP_BANNER "Run echo client"

#define INVALID_SOCK (-1)

#define EVENT_MASK (NET_EVENT_L4_CONNECTED | \
		    NET_EVENT_L4_DISCONNECTED)
#define IPV6_EVENT_MASK (NET_EVENT_IPV6_ADDR_ADD | \
			 NET_EVENT_IPV6_ADDR_DEPRECATED)

const char lorem_ipsum[] = LOREM_IPSUM;

const int ipsum_len = sizeof(lorem_ipsum) - 1;

APP_DMEM struct configs conf = {
	.ipv4 = {
		.proto = "IPv4",
		.udp.sock = INVALID_SOCK,
		.tcp.sock = INVALID_SOCK,
	},
	.ipv6 = {
		.proto = "IPv6",
		.udp.sock = INVALID_SOCK,
		.tcp.sock = INVALID_SOCK,
	},
};

static APP_BMEM struct pollfd fds[1 + 4];
static APP_BMEM int nfds;

static APP_BMEM bool connected;
static APP_BMEM bool need_restart;

K_SEM_DEFINE(run_app, 0, 1);

static struct net_mgmt_event_callback mgmt_cb;
static struct net_mgmt_event_callback ipv6_mgmt_cb;

static void prepare_fds(void)
{
	nfds = 0;

	/* eventfd is used to trigger restart */
	fds[nfds].fd = eventfd(0, 0);
	fds[nfds].events = POLLIN;
	nfds++;

	if (conf.ipv4.udp.sock >= 0) {
		fds[nfds].fd = conf.ipv4.udp.sock;
		fds[nfds].events = POLLIN;
		nfds++;
	}

	if (conf.ipv4.tcp.sock >= 0) {
		fds[nfds].fd = conf.ipv4.tcp.sock;
		fds[nfds].events = POLLIN;
		nfds++;
	}

	if (conf.ipv6.udp.sock >= 0) {
		fds[nfds].fd = conf.ipv6.udp.sock;
		fds[nfds].events = POLLIN;
		nfds++;
	}

	if (conf.ipv6.tcp.sock >= 0) {
		fds[nfds].fd = conf.ipv6.tcp.sock;
		fds[nfds].events = POLLIN;
		nfds++;
	}
}

static void wait(void)
{
	int ret;

	/* Wait for event on any socket used. Once event occurs,
	 * we'll check them all.
	 */
	ret = poll(fds, nfds, -1);
	if (ret < 0) {
		static bool once;

		if (!once) {
			once = true;
			LOG_ERR("Error in poll:%d", errno);
		}

		return;
	}

	if (ret > 0 && fds[0].revents) {
		eventfd_t value;

		eventfd_read(fds[0].fd, &value);
		LOG_DBG("Received restart event.");
		return;
	}
}

static int start_udp_and_tcp(void)
{
	int ret;

	LOG_INF("Starting...");

	if (IS_ENABLED(CONFIG_NET_TCP)) {
		ret = start_tcp();
		if (ret < 0) {
			return ret;
		}
	}

	if (IS_ENABLED(CONFIG_NET_UDP)) {
		ret = start_udp();
		if (ret < 0) {
			return ret;
		}
	}

	prepare_fds();

	return 0;
}

static int run_udp_and_tcp(void)
{
	int ret;

	wait();

	if (IS_ENABLED(CONFIG_NET_TCP)) {
		ret = process_tcp();
		if (ret < 0) {
			return ret;
		}
	}

	if (IS_ENABLED(CONFIG_NET_UDP)) {
		ret = process_udp();
		if (ret < 0) {
			return ret;
		}
	}

	return 0;
}

static void stop_udp_and_tcp(void)
{
	LOG_INF("Stopping...");

	if (IS_ENABLED(CONFIG_NET_UDP)) {
		stop_udp();
	}

	if (IS_ENABLED(CONFIG_NET_TCP)) {
		stop_tcp();
	}
}

static int check_our_ipv6_sockets(int sock,
				  struct in6_addr *deprecated_addr)
{
	struct sockaddr_in6 addr = { 0 };
	socklen_t addrlen = sizeof(addr);
	int ret;

	if (sock < 0) {
		return -EINVAL;
	}

	ret = getsockname(sock, (struct sockaddr *)&addr, &addrlen);
	if (ret != 0) {
		return -errno;
	}

	if (!net_ipv6_addr_cmp(deprecated_addr, &addr.sin6_addr)) {
		return -ENOENT;
	}

	need_restart = true;

	return 0;
}

static void ipv6_event_handler(struct net_mgmt_event_callback *cb,
			       uint64_t mgmt_event, struct net_if *iface)
{
	static char addr_str[INET6_ADDRSTRLEN];

	if (!IS_ENABLED(CONFIG_NET_IPV6_PE)) {
		return;
	}

	if ((mgmt_event & IPV6_EVENT_MASK) != mgmt_event) {
		return;
	}

	if (cb->info == NULL ||
	    cb->info_length != sizeof(struct in6_addr)) {
		return;
	}

	if (mgmt_event == NET_EVENT_IPV6_ADDR_ADD) {
		struct net_if_addr *ifaddr;
		struct in6_addr added_addr;

		memcpy(&added_addr, cb->info, sizeof(struct in6_addr));

		ifaddr = net_if_ipv6_addr_lookup(&added_addr, &iface);
		if (ifaddr == NULL) {
			return;
		}

		/* Wait until we get a temporary address before continuing after
		 * boot.
		 */
		if (ifaddr->is_temporary) {
			static bool once;

			LOG_INF("Temporary IPv6 address %s added",
				inet_ntop(AF_INET6, &added_addr, addr_str,
					  sizeof(addr_str) - 1));

			if (!once) {
				k_sem_give(&run_app);
				once = true;
			}
		}
	}

	if (mgmt_event == NET_EVENT_IPV6_ADDR_DEPRECATED) {
		struct in6_addr deprecated_addr;

		memcpy(&deprecated_addr, cb->info, sizeof(struct in6_addr));

		LOG_INF("IPv6 address %s deprecated",
			inet_ntop(AF_INET6, &deprecated_addr, addr_str,
				  sizeof(addr_str) - 1));

		(void)check_our_ipv6_sockets(conf.ipv6.tcp.sock,
					     &deprecated_addr);
		(void)check_our_ipv6_sockets(conf.ipv6.udp.sock,
					     &deprecated_addr);

		if (need_restart) {
			eventfd_write(fds[0].fd, 1);
		}

		return;
	}
}

static void event_handler(struct net_mgmt_event_callback *cb,
			  uint64_t mgmt_event, struct net_if *iface)
{
	if ((mgmt_event & EVENT_MASK) != mgmt_event) {
		return;
	}

	if (mgmt_event == NET_EVENT_L4_CONNECTED) {
		LOG_INF("Network connected");

		connected = true;
		conf.ipv4.udp.mtu = net_if_get_mtu(iface);
		conf.ipv6.udp.mtu = conf.ipv4.udp.mtu;

		if (!IS_ENABLED(CONFIG_NET_IPV6_PE)) {
			k_sem_give(&run_app);
		}

		return;
	}

	if (mgmt_event == NET_EVENT_L4_DISCONNECTED) {
		LOG_INF("Network disconnected");

		connected = false;
		k_sem_reset(&run_app);

		return;
	}
}

static const uint8_t mac_addr_change[6] = { 0xAA, 0xBB, 0xCC,
					 0x01,  0x02,  0x04 };
static int init_macaddr(void)
{
	struct ethernet_req_params params;
	struct net_if *iface = net_if_get_default();
	int ret;

	net_if_down(iface);
	memcpy(params.mac_address.addr, mac_addr_change, 6);

	ret = net_mgmt(NET_REQUEST_ETHERNET_SET_MAC_ADDRESS,
	               iface, &params,
	               sizeof(struct ethernet_req_params));
	net_if_up(iface);

	return ret;
}

static void init_app(void)
{
	LOG_INF(APP_BANNER);

#if defined(CONFIG_USERSPACE)
	struct k_mem_partition *parts[] = {
#if Z_LIBC_PARTITION_EXISTS
		&z_libc_partition,
#endif
		&app_partition
	};

	int ret = k_mem_domain_init(&app_domain, ARRAY_SIZE(parts), parts);

	__ASSERT(ret == 0, "k_mem_domain_init() failed %d", ret);
	ARG_UNUSED(ret);
#endif

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	int err = tls_credential_add(CA_CERTIFICATE_TAG,
				    TLS_CREDENTIAL_CA_CERTIFICATE,
				    ca_certificate,
				    sizeof(ca_certificate));
	if (err < 0) {
		LOG_ERR("Failed to register public certificate: %d", err);
	}

#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
	err = tls_credential_add(PSK_TAG,
				TLS_CREDENTIAL_PSK,
				psk,
				sizeof(psk));
	if (err < 0) {
		LOG_ERR("Failed to register PSK: %d", err);
	}
	err = tls_credential_add(PSK_TAG,
				TLS_CREDENTIAL_PSK_ID,
				psk_id,
				sizeof(psk_id) - 1);
	if (err < 0) {
		LOG_ERR("Failed to register PSK ID: %d", err);
	}
#endif /* defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) */
#endif /* defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS) */


	if (IS_ENABLED(CONFIG_NET_CONNECTION_MANAGER)) {
		net_mgmt_init_event_callback(&mgmt_cb,
					     event_handler, EVENT_MASK);
		net_mgmt_add_event_callback(&mgmt_cb);

		conn_mgr_mon_resend_status();
	}

	net_mgmt_init_event_callback(&ipv6_mgmt_cb,
				     ipv6_event_handler, IPV6_EVENT_MASK);
	net_mgmt_add_event_callback(&ipv6_mgmt_cb);

	init_vlan();
	init_udp();
	init_macaddr();
}

static void start_client(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	int iterations = CONFIG_NET_SAMPLE_SEND_ITERATIONS;
	int i = 0;
	int ret;

	while (iterations == 0 || i < iterations) {
		/* Wait for the connection. */
		k_sem_take(&run_app, K_FOREVER);

		if (IS_ENABLED(CONFIG_NET_IPV6_PE)) {
			/* Make sure that we have a temporary address */
			k_sleep(K_SECONDS(1));
		}

		do {
			if (need_restart) {
				/* Close all sockets and get a fresh restart */
				stop_udp_and_tcp();
				need_restart = false;
			}

			ret = start_udp_and_tcp();

			while (connected && (ret == 0)) {
				ret = run_udp_and_tcp();

				if (iterations > 0) {
					i++;
					if (i >= iterations) {
						break;
					}
				}

				if (need_restart) {
					break;
				}
			}
		} while (need_restart);

		stop_udp_and_tcp();
	}
}

int main(void)
{
	init_app();

	if (!IS_ENABLED(CONFIG_NET_CONNECTION_MANAGER)) {
		/* If the config library has not been configured to start the
		 * app only after we have a connection, then we can start
		 * it right away.
		 */
		connected = true;
		k_sem_give(&run_app);
	}

	k_thread_priority_set(k_current_get(), THREAD_PRIORITY);

#if defined(CONFIG_USERSPACE)
	k_thread_access_grant(k_current_get(), &run_app);
	k_mem_domain_add_thread(&app_domain, k_current_get());

	k_thread_user_mode_enter(start_client, NULL, NULL, NULL);
#else
	start_client(NULL, NULL, NULL);
#endif
	return 0;
}