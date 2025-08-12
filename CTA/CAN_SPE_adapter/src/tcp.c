/* tcp.c - TCP specific code for echo client */

/*
 * Copyright (c) 2017 Intel Corporation.
 * Copyright (c) 2018 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(net_echo_client_sample, LOG_LEVEL_DBG);

#include <zephyr/kernel.h>
#include <errno.h>
#include <stdio.h>

#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/random/random.h>

#include "common.h"
#include "ca_certificate.h"

#define RECV_BUF_SIZE 128

/* These proxy server addresses are only used when CONFIG_SOCKS
 * is enabled. To connect to a proxy server that is not running
 * under the same IP as the peer or uses a different port number,
 * modify the values.
 */
#define SOCKS5_PROXY_V4_ADDR CONFIG_NET_CONFIG_PEER_IPV4_ADDR
#define SOCKS5_PROXY_PORT 1080

static ssize_t sendall(int sock, const void *buf, size_t len)
{
	while (len) {
		ssize_t out_len = send(sock, buf, len, 0);

		if (out_len < 0) {
			return out_len;
		}
		buf = (const char *)buf + out_len;
		len -= out_len;
	}

	return 0;
}

int send_tcp_data(struct sample_data *data)
{
	int ret = 0;

	// do {
	// 	data->tcp.expecting = sys_rand32_get() % ipsum_len;
	// } while (data->tcp.expecting == 0U);

	// data->tcp.received = 0U;

	// // ret =  sendall(data->tcp.sock, lorem_ipsum, data->tcp.expecting);

	// if (ret < 0) {
	// 	LOG_ERR("%s TCP: Failed to send data, errno %d", data->proto,
	// 		errno);
	// } else {
	// 	if (PRINT_PROGRESS) {
	// 		LOG_DBG("%s TCP: Sent %d bytes", data->proto,
	// 			data->tcp.expecting);
	// 	}
	// }

	return ret;
}

int send_buf_tcp(struct sample_data *data, uint8_t *data_buffer, uint32_t len)
{
	int ret;

	if(len)
	{
		data->tcp.expecting = len;
	}

	data->tcp.received = 0U;

	ret =  sendall(data->tcp.sock, data_buffer, data->tcp.expecting);

	if (ret < 0) {
		LOG_ERR("%s TCP: Failed to send data, errno %d", data->proto,
			errno);
	} else {
		if (PRINT_PROGRESS) {
			LOG_DBG("%s TCP: Sent %d bytes", data->proto,
				data->tcp.expecting);
		}
	}

	return ret;
}

static int start_tcp_proto(struct sample_data *data, sa_family_t family,
			   struct sockaddr *addr, socklen_t addrlen)
{
	int optval;
	int ret;

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	data->tcp.sock = socket(family, SOCK_STREAM, IPPROTO_TLS_1_2);
#else
	data->tcp.sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
#endif
	if (data->tcp.sock < 0) {
		LOG_ERR("Failed to create TCP socket (%s): %d", data->proto,
			errno);
		return -errno;
	}

	if (IS_ENABLED(CONFIG_SOCKS)) {
		struct sockaddr proxy_addr;
		socklen_t proxy_addrlen;

		if (family == AF_INET) {
			struct sockaddr_in *proxy4 =
				(struct sockaddr_in *)&proxy_addr;

			proxy4->sin_family = AF_INET;
			proxy4->sin_port = htons(SOCKS5_PROXY_PORT);
			inet_pton(AF_INET, SOCKS5_PROXY_V4_ADDR,
				  &proxy4->sin_addr);
			proxy_addrlen = sizeof(struct sockaddr_in);
		} else {
			return -EINVAL;
		}

		ret = setsockopt(data->tcp.sock, SOL_SOCKET, SO_SOCKS5,
				 &proxy_addr, proxy_addrlen);
		if (ret < 0) {
			return ret;
		}
	}

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	sec_tag_t sec_tag_list[] = {
		CA_CERTIFICATE_TAG,
#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
		PSK_TAG,
#endif
	};

	ret = setsockopt(data->tcp.sock, SOL_TLS, TLS_SEC_TAG_LIST,
			 sec_tag_list, sizeof(sec_tag_list));
	if (ret < 0) {
		LOG_ERR("Failed to set TLS_SEC_TAG_LIST option (%s): %d",
			data->proto, errno);
		ret = -errno;
	}

	ret = setsockopt(data->tcp.sock, SOL_TLS, TLS_HOSTNAME,
			 TLS_PEER_HOSTNAME, sizeof(TLS_PEER_HOSTNAME));
	if (ret < 0) {
		LOG_ERR("Failed to set TLS_HOSTNAME option (%s): %d",
			data->proto, errno);
		ret = -errno;
	}
#endif

	ret = connect(data->tcp.sock, addr, addrlen);
	if (ret < 0) {
		LOG_ERR("Cannot connect to TCP remote (%s): %d", data->proto,
			errno);
		ret = -errno;
	}

	return ret;
}

static int process_tcp_proto(struct sample_data *data)
{
	int ret, received;
	char buf[RECV_BUF_SIZE];

	do {
		received = recv(data->tcp.sock, buf, sizeof(buf), MSG_DONTWAIT);

		/* No data or error. */
		if (received == 0) {
			ret = -EIO;
			continue;
		} else if (received < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ret = 0;
			} else {
				ret = -errno;
			}
			continue;
		}

		/* Successful comparison. */
		data->tcp.received += received;
		if (data->tcp.received < data->tcp.expecting) {
			continue;
		}

		ret = send_tcp_data(data);

		break;
	} while (received > 0);

	return ret;
}

int start_tcp(void)
{
	int ret = 0;
	struct sockaddr_in addr4;
	
	if (IS_ENABLED(CONFIG_NET_IPV4)) {
		addr4.sin_family = AF_INET;
		addr4.sin_port = htons(PEER_PORT);
		inet_pton(AF_INET, CONFIG_NET_CONFIG_PEER_IPV4_ADDR,
			  &addr4.sin_addr);

		ret = start_tcp_proto(&conf.ipv4, AF_INET,
				      (struct sockaddr *)&addr4,
				      sizeof(addr4));
		if (ret < 0) {
			return ret;
		}
	}

	if (IS_ENABLED(CONFIG_NET_IPV4)) {
		ret = send_tcp_data(&conf.ipv4);
	}

	return ret;
}

int process_tcp(void)
{
	int ret = 0;

	if (IS_ENABLED(CONFIG_NET_IPV4)) {
		ret = process_tcp_proto(&conf.ipv4);
		if (ret < 0) {
			return ret;
		}
	}

	return ret;
}

void stop_tcp(void)
{
	if (IS_ENABLED(CONFIG_NET_IPV4)) {
		if (conf.ipv4.tcp.sock >= 0) {
			(void)close(conf.ipv4.tcp.sock);
		}
	}
}
