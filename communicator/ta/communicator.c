#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_tcpsocket.h>
#include <tee_udpsocket.h>
#include <tee_tlssocket.h>

#include <communicator.h>

struct sock_handle {
	TEE_iSocketHandle tcp_ctx;
	TEE_iSocket *tcp_socket;
	TEE_ObjectHandle trustedCerts;
	TEE_iSocketHandle tls_ctx;
	TEE_iSocket *tls_socket;
} h = {};

#define DIGICERT_GLOBAL_ROOT_CA                                                \
	"-----BEGIN CERTIFICATE-----\r\n"                                      \
	"MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh\r\n" \
	"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n" \
	"d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\r\n" \
	"QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT\r\n" \
	"MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\r\n" \
	"b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG\r\n" \
	"9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB\r\n" \
	"CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97\r\n" \
	"nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt\r\n" \
	"43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P\r\n" \
	"T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4\r\n" \
	"gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO\r\n" \
	"BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR\r\n" \
	"TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw\r\n" \
	"DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr\r\n" \
	"hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg\r\n" \
	"06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF\r\n" \
	"PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls\r\n" \
	"YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk\r\n" \
	"CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=\r\n"                 \
	"-----END CERTIFICATE-----\r\n"

const char digicert_global_root_ca[] = DIGICERT_GLOBAL_ROOT_CA;

TEE_Result TA_CreateEntryPoint(void)
{
	char *cert_id;
	TEE_Result res;

	cert_id = "DigiCert Global Root CA";
	res = TEE_CreatePersistentObject(
		TEE_STORAGE_PRIVATE, cert_id, sizeof(cert_id),
		TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META,
		TEE_HANDLE_NULL, digicert_global_root_ca,
		sizeof(digicert_global_root_ca), &h.trustedCerts);
	if (res != TEE_SUCCESS) {
		EMSG("Couldn't create persistent object for certificate: %x",
		     res);
		TEE_CloseAndDeletePersistentObject1(h.trustedCerts);
		return res;
	}

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	TEE_CloseAndDeletePersistentObject1(h.trustedCerts);
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
}

static TEE_Result open_socket(uint32_t __maybe_unused param_types,
			      TEE_Param __maybe_unused params[4])
{
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (strncmp(params[0].memref.buffer, "www.example.com",
		    params[0].memref.size) != 0) {
		EMSG("Wrong destination url! dest: %s",
		     params[0].memref.buffer);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// TEE_udpSocket_Setup setup_udp = {};
	TEE_tcpSocket_Setup tcp_setup = {};
	uint32_t error;
	TEE_Result res;

	// setup_udp.ipVersion = TEE_IP_VERSION_4;
	// setup_udp.server_addr = "93.184.216.34";
	// setup_udp.server_port = 80;

	tcp_setup.ipVersion = TEE_IP_VERSION_4;
	tcp_setup.server_addr = (char *)"93.184.216.34";
	tcp_setup.server_port = 80;

	// h.socket = TEE_udpSocket;
	h.tcp_socket = TEE_tcpSocket;
	// res = h.socket->open(&h.ctx, &setup_udp, &error);
	res = h.tcp_socket->open(&h.tcp_ctx, &tcp_setup, &error);
	if (res == TEE_SUCCESS) {
		IMSG("Opened tcp_socket.\n");
	} else {
		EMSG("Couldn't open tcp_socket: %x", res);
	}

	return res;
}

static TEE_Result open_ssl_socket(uint32_t __maybe_unused param_types,
				  TEE_Param __maybe_unused params[4])
{
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (strncmp(params[0].memref.buffer, "www.example.com",
		    params[0].memref.size) != 0) {
		EMSG("Wrong destination url! dest: %s",
		     params[0].memref.buffer);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	const unsigned char *pers = "ssl_client1";
	const unsigned char *server_name = "example.com";
	TEE_tcpSocket_Setup tcp_setup = {};
	TEE_tlsSocket_Setup tls_setup = {};
	TEE_tlsSocket_Credentials credentials = {};
	TEE_tlsSocket_ServerPDC server_creds = {};
	uint32_t error;
	TEE_Result res;

	tcp_setup.ipVersion = TEE_IP_VERSION_4;
	tcp_setup.server_addr = (char *)"93.184.216.34";
	tcp_setup.server_port = 443;

	h.tcp_socket = TEE_tcpSocket;
	res = h.tcp_socket->open(&h.tcp_ctx, &tcp_setup, &error);
	if (res != TEE_SUCCESS) {
		EMSG("Couldn't open tcp_socket: %x", res);
		return res;
	}

	tls_setup.baseContext = &h.tcp_ctx;
	tls_setup.baseSocket = h.tcp_socket;
	tls_setup.persString = pers;
	tls_setup.persStringLen = strlen(pers);
	tls_setup.serverName = server_name;
	tls_setup.serverNameLen = strlen(server_name);
	tls_setup.credentials = &credentials;

	credentials = (TEE_tlsSocket_Credentials){
		.serverCredType = TEE_TLS_SERVER_CRED_CSC,
		.serverCred = &server_creds,
	};

	uint32_t cert_encodings[] = { 0x2 };
	server_creds = (TEE_tlsSocket_ServerPDC){
		.numTrustedCerts = 1,
		.trustedCertEncodings = cert_encodings,
		.trustedCerts = &h.trustedCerts,
	};

	h.tls_socket = TEE_tlsSocket;
	res = h.tls_socket->open(&h.tls_ctx, &tls_setup, &error);
	if (res != TEE_SUCCESS) {
		EMSG("Couldn't open tls_socket: %x", res);
		h.tcp_socket->close(h.tcp_ctx);
		return res;
	}

	IMSG("Opened encrypted socket\n");
	return TEE_SUCCESS;
}

static TEE_Result close_socket(uint32_t __maybe_unused param_types,
			       TEE_Param __maybe_unused params[4])
{
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (strncmp(params[0].memref.buffer, "www.example.com",
		    params[0].memref.size) != 0) {
		EMSG("Wrong destination url! dest: %s",
		     params[0].memref.buffer);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_Result res;

	res = h.tcp_socket->close(h.tcp_ctx);
	if (res == TEE_SUCCESS) {
		IMSG("Socket closed\n");
	}

	return res;
}

static TEE_Result close_ssl_socket(uint32_t __maybe_unused param_types,
				   TEE_Param __maybe_unused params[4])
{
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (strncmp(params[0].memref.buffer, "www.example.com",
		    params[0].memref.size) != 0) {
		EMSG("Wrong destination url! dest: %s",
		     params[0].memref.buffer);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_Result res;

	res = h.tls_socket->close(h.tls_ctx);
	if (res == TEE_SUCCESS) {
		IMSG("TLS socket closed\n");
	}
	res = h.tcp_socket->close(h.tcp_ctx);
	if (res == TEE_SUCCESS) {
		IMSG("TCP socket closed\n");
	}

	return res;
}

static TEE_Result get_data(uint32_t __maybe_unused param_types,
			   TEE_Param __maybe_unused params[4])
{
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (strncmp(params[0].memref.buffer, "www.example.com",
		    params[0].memref.size) != 0) {
		EMSG("Wrong destination url! dest: %s",
		     params[0].memref.buffer);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_Result res;
	void *recv = NULL;
	uint32_t recv_len;
	uint32_t i;

	const char *buf = "GET / HTTP/1.1\r\n"
			  "Host: www.example.com\r\n"
			  "Connection: Close\r\n"
			  "\r\n";
	uint32_t send_len = strlen(buf);
	DMSG("Invoking print function: 20472843b0e2\n");

	res = h.tcp_socket->send(h.tcp_ctx, buf, &send_len,
				 TEE_TIMEOUT_INFINITE);
	DMSG("Invoking print function: 3b48a6df6abe\n");
	if (res != TEE_SUCCESS) {
		EMSG("Couldn't send data on tcp_socket: %x", res);
		return res;
	}
	DMSG("Invoking print function: d6a7eaebd186\n");

	recv_len = 0;
	do {
		DMSG("Invoking print function: 56f9997c50a9\n");
		res = h.tcp_socket->recv(h.tcp_ctx, NULL, &recv_len,
					 TEE_TIMEOUT_INFINITE);
		DMSG("Invoking print function: 8030a16b8253\n");
		if (res != TEE_SUCCESS) {
			EMSG("Couldn't get recv data length: %x", res);
			return res;
			DMSG("Invoking print function: d37bb73c2264\n");
		}
	} while (recv_len == 0);

	DMSG("Invoking print function: 8da9e3c00fb1\n");
	IMSG("Received %u bytes", recv_len);
	recv = TEE_Malloc(recv_len, TEE_MALLOC_FILL_ZERO);
	DMSG("Invoking print function: 9a36f93c0757\n");
	res = h.tcp_socket->recv(h.tcp_ctx, recv, &recv_len,
				 TEE_TIMEOUT_INFINITE);
	DMSG("Invoking print function: 01da64fc0dcd\n");
	if (res == TEE_SUCCESS) {
		for (i = 0; i < recv_len; i++) {
			putchar(((char *)recv)[i]);
		}
	} else {
		EMSG("Couldn't get recv data: %x", res);
	}

	DMSG("Invoking print function: f1cf2dd0cdd3\n");
	TEE_Free(recv);
	return res;
}

static TEE_Result get_ssl_data(uint32_t __maybe_unused param_types,
			       TEE_Param __maybe_unused params[4])
{
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (strncmp(params[0].memref.buffer, "www.example.com",
		    params[0].memref.size) != 0) {
		EMSG("Wrong destination url! dest: %s",
		     params[0].memref.buffer);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_Result res;
	int ret;
	unsigned char *recv;
	unsigned char last_buf[11];
	memset(last_buf, 0, sizeof(last_buf));
	char *const last = &last_buf[0];
	size_t last_len = sizeof(last_buf) - 1;
	uint32_t recv_len, recvd = 0;
	uint32_t i;

	const char *buf = "GET / HTTP/1.1\r\n"
			  "Host: www.example.com\r\n"
			  "Connection: Close\r\n"
			  "\r\n";
	uint32_t send_len = strlen(buf);

	res = h.tls_socket->send(h.tls_ctx, buf, &send_len,
				 TEE_TIMEOUT_INFINITE);
	if (res != TEE_SUCCESS) {
		EMSG("Couldn't send data on tcp_socket: %x", res);
		return res;
	}

	IMSG("Sent request.\n");

	do {
		recv_len = 0;
		do {
			res = h.tls_socket->recv(h.tls_ctx, NULL, &recv_len,
						 TEE_TIMEOUT_INFINITE);
			if (res != TEE_SUCCESS) {
				EMSG("Couldn't get recv data length: %x", res);
				return res;
			}
		} while (recv_len == 0);

		DMSG("Received %u bytes", recv_len);
		recv = TEE_Malloc(recv_len, TEE_MALLOC_FILL_ZERO);
		res = h.tls_socket->recv(h.tls_ctx, recv, &recv_len,
					 TEE_TIMEOUT_INFINITE);
		if (res != TEE_SUCCESS) {
			EMSG("Couldn't get recv data: %x", res);
			return res;
		}

		for (i = 0; i < recv_len; i++) {
			putchar(((char *)recv)[i]);
		}

		if (recv_len >= last_len) {
			memcpy(last, recv + (recv_len - last_len), last_len);
		} else if (recvd + recv_len >= last_len) {
			memcpy(last, last + recvd + recv_len - last_len,
			       last_len - recv_len);
			memcpy(last + last_len - recv_len, recv, recv_len);
		} else {
			memcpy(last + recvd, recv, recv_len);
		}
		recvd += recv_len;

		TEE_Free(recv);
	} while (!strstr(last, "</html>"));

exit:
	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */
	int ret;

	switch (cmd_id) {
	case TA_COMMUNICATOR_CMD_OPEN_SOCKET:
		return open_socket(param_types, params);
	case TA_COMMUNICATOR_CMD_CLOSE_SOCKET:
		return close_socket(param_types, params);
	case TA_COMMUNICATOR_CMD_GET_DATA:
		return get_data(param_types, params);
	case TA_COMMUNICATOR_CMD_OPEN_SSL_SOCKET:
		return open_ssl_socket(param_types, params);
	case TA_COMMUNICATOR_CMD_CLOSE_SSL_SOCKET:
		return close_ssl_socket(param_types, params);
	case TA_COMMUNICATOR_CMD_GET_SSL_DATA:
		return get_ssl_data(param_types, params);
	case TA_COMMUNICATOR_CMD_CONNECTION_REQUEST:
		if ((ret = open_socket(param_types, params)) != TEE_SUCCESS) {
			return ret;
		}
		if ((ret = get_data(param_types, params)) != TEE_SUCCESS) {
			return ret;
		}
		if ((ret = close_socket(param_types, params)) != TEE_SUCCESS) {
			return ret;
		}
		if ((ret = open_ssl_socket(param_types, params)) !=
		    TEE_SUCCESS) {
			return ret;
		}
		if ((ret = get_ssl_data(param_types, params)) != TEE_SUCCESS) {
			return ret;
		}
		if ((ret = close_ssl_socket(param_types, params)) !=
		    TEE_SUCCESS) {
			return ret;
		}
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
