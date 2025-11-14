/* can_spe_adapter.c - Transceiver for CTA */

/*
 * Copyright (c) 2017 Intel Corporation.
 * Copyright (c) 2018 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_echo_client_sample, LOG_LEVEL_DBG);

#include <zephyr/kernel.h>
#include <errno.h>
#include <stdio.h>

#include <zephyr/posix/sys/eventfd.h>

#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/conn_mgr_monitor.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/ethernet_mgmt.h>

#include "common.h"
#include "app_can.h"
#include "ca_certificate.h"


#define APP_BANNER "Run echo client"

#define INVALID_SOCK (-1)

#define EVENT_MASK (NET_EVENT_L4_CONNECTED | \
		    NET_EVENT_L4_DISCONNECTED)


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

K_THREAD_DEFINE(can_tid, CAN_THREAD_STACK_SIZE,
					can_thread, NULL, NULL, NULL,
					CAN_THREAD_PRIORITY, 0, 0);

static struct net_mgmt_event_callback mgmt_cb;



#define CAN_QUEUE_SIZE 50U
#define CAN_FRAME_SIZE sizeof(can_frame_t)

#define SPE_QUEUE_SIZE 10U
#define SPE_FRAME_SIZE sizeof(can_frame_t) // can_frame_t for now. Should be spe_frame_t when not tested with echo_server

static uint8_t can_msgq_buffer[CAN_QUEUE_SIZE * CAN_FRAME_SIZE];
struct k_msgq can_msgq;

static uint8_t spe_msgq_buffer[SPE_QUEUE_SIZE * SPE_FRAME_SIZE];
struct k_msgq spe_msgq;


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
}

static void wait(void)
{
	int ret;

	/* Wait for event on any socket used. Once event occurs,
	 * we'll check them all.
	 */
	ret = poll(fds, nfds, 100);
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

__attribute__((unused)) static int run_udp_and_tcp(void)
{
	int ret = 0;

	wait();

	ret = process_tcp();

	return ret;
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

	k_msgq_init(&can_msgq, can_msgq_buffer, CAN_FRAME_SIZE, CAN_QUEUE_SIZE);
	k_msgq_init(&spe_msgq, spe_msgq_buffer, SPE_FRAME_SIZE, SPE_QUEUE_SIZE);

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
		
		do {
			if (need_restart) {
				/* Close all sockets and get a fresh restart */
				stop_udp_and_tcp();
				need_restart = false;
			}

			ret = start_udp_and_tcp();

			while (connected && (ret == 0)) {

				ret = process_tcp_proto(&conf.ipv4);
				// ret = run_udp_and_tcp();

				if (iterations > 0) {
					i++;
					if (i >= iterations) {
						break;
					}
				}

				// if (need_restart) {
				// 	break;
				// }
				k_yield();
			}
		} while (need_restart);

		stop_udp_and_tcp();
	}
}

int main(void)
{
	//log_thread_set(k_current_get());
	//k_thread_suspend(can_tid);

	init_app();

	

    LOG_INF("CAN→SPE bridge running");

	if (!IS_ENABLED(CONFIG_NET_CONNECTION_MANAGER)) {
		/* If the config library has not been configured to start the
		 * app only after we have a connection, then we can start
		 * it right away.
		 */
		connected = true;
		k_sem_give(&run_app);
	}

	//k_thread_start(can_tid);

	//k_thread_priority_set(k_current_get(), THREAD_PRIORITY);

	k_yield();

	start_client(NULL, NULL, NULL);

	return 0;
}