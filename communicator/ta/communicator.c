#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_tcpsocket.h>
#include <tee_udpsocket.h>
#include <tee_tlssocket.h>
#include <malloc.h>

#include <communicator.h>

#define PTA_UPDATER_UUID                                               \
	{                                                              \
		0xb84653a5, 0x753a, 0x4fe1,                            \
		{                                                      \
			0xb1, 0x87, 0x0c, 0xcc, 0x6a, 0x7c, 0xdd, 0x83 \
		}                                                      \
	}

/* The function IDs implemented in this TA */
#define PTA_UPDATER_CMD_UPDATE	    0
#define PTA_UPDATER_CMD_ICREASE_MEM 1

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

#define SELFSIGNED_CERT                                                        \
	"-----BEGIN CERTIFICATE-----\r\n"                                      \
	"MIIGOzCCBCOgAwIBAgIUEBxLYFdoujaTyp8Wgk0XdNNLsA8wDQYJKoZIhvcNAQEL\r\n" \
	"BQAwgawxCzAJBgNVBAYTAkJFMRcwFQYDVQQIDA5WbGFhbXMtQnJhYmFudDEPMA0G\r\n" \
	"A1UEBwwGTGV1dmVuMRIwEAYDVQQKDAlLVSBMZXV2ZW4xGzAZBgNVBAsMEkRpc3Ry\r\n" \
	"aU5ldCwgbmVzLWxhYjEaMBgGA1UEAwwRdXBkYXRlLm5lcy1sYWIuYmUxJjAkBgkq\r\n" \
	"hkiG9w0BCQEWF3RvbS52YW5leWNrQGt1bGV1dmVuLmJlMB4XDTIzMTAyNTExNTQ0\r\n" \
	"NFoXDTI0MTAyNDExNTQ0NFowgawxCzAJBgNVBAYTAkJFMRcwFQYDVQQIDA5WbGFh\r\n" \
	"bXMtQnJhYmFudDEPMA0GA1UEBwwGTGV1dmVuMRIwEAYDVQQKDAlLVSBMZXV2ZW4x\r\n" \
	"GzAZBgNVBAsMEkRpc3RyaU5ldCwgbmVzLWxhYjEaMBgGA1UEAwwRdXBkYXRlLm5l\r\n" \
	"cy1sYWIuYmUxJjAkBgkqhkiG9w0BCQEWF3RvbS52YW5leWNrQGt1bGV1dmVuLmJl\r\n" \
	"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvb8/xnmLjxUCD7RLcJET\r\n" \
	"VKNjiJ4CfqXqTp90xpNZ/hTlfu1BbRXGU/ko8KSKU7ERoHfIuMXhkfaDCZ6g7v2I\r\n" \
	"SfinpS8rzG2LNeGYj7wDM7LeZBq5I7uDwKm8ZkmMSodre3kJIdIL6L2CAkzEEkDb\r\n" \
	"RnC5MZUBWly3bkkG5C+9TLlnzG4PEvNUSdhHY2h6JhtEkG/o7qsublX/ahAYhZnC\r\n" \
	"h6mnbQdbYAqYGAJ6bjW5V05Xq72l0HOAymbwFZ51TCG4jXOa5lRMq27HFpBEY+R9\r\n" \
	"ytGhFrx8FySam7X0oe4qNUl5Foz4kVqcaU7Y4+0Izxiqs9uc4io7HRUkszxK+zvJ\r\n" \
	"W45GAuhssI2DAwhe5bGg/2T4JgIxIWtFiHi/yZv7dpmxH+C4FTC55e+p31lOuyiK\r\n" \
	"hqugVxS7vRQPfbYRAYxKiy3X2zAjpPja5h6pJl1YubAKiLtFroflQMks103KrnNC\r\n" \
	"0Yoj8Jwtgmu6hlHMPXwLNpB7kQ+p1exhgIFypWSTJIOXSXfATZYRvWtNx1td0aIs\r\n" \
	"CrgAM/oovOUk7Hs5z6X9OhgiDzZYq/xiAkJnwgZ4MKyW4IoQtafka5q0DUAE47i0\r\n" \
	"QrNUV514t2Hx2aZRsOneDU+8xonNudoknY5mcM2bQACLkMRAXlp3sZ7XEyZxeRiq\r\n" \
	"g5Ez8rFWnDTFyx3jS3HSRJECAwEAAaNTMFEwHQYDVR0OBBYEFHqT0lyBgJS6x2eF\r\n" \
	"mArYmkLkQy7IMB8GA1UdIwQYMBaAFHqT0lyBgJS6x2eFmArYmkLkQy7IMA8GA1Ud\r\n" \
	"EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAKLtXky6v0IydTY0PlLOyV68\r\n" \
	"gOq0gc6f9tob6bS7C8KvCAsQ/L4GQDwgBlWV8RaFy6HMalTfrYqtLP/TpZl0HnTQ\r\n" \
	"TxOhxB4eI1LwGVRujyE7VR8Tsdclfe54WdOS0e2Vg+wl/WdLRUUSQhyJm0Rqj0M4\r\n" \
	"3gX7XstCoOz0hibdZbstoElNkd/iEDPSMUvp14YYtHR94jLHyXFqy+j7mXaJasXW\r\n" \
	"yjTJoU1B9qH8lrHfjmI6TLd99GmHeKTAOUHtGc2L8LL86zR7m0ykXSrcjHUA+owv\r\n" \
	"otC7nporuJY+5XuBgG/KvReGk4/a3glMe6OgQUVbK01o0WwFvbwxGA7COxpYTSwq\r\n" \
	"uWH1QeHK9qraZXpD6MOpKWGeYhd+6V0e2GIbDHbCjq1vHGW3rp5Xs7ft2n+MVoCo\r\n" \
	"7kgQVXew0CC9zzgb0YEuLjjRKkHBAV+7ybolOoZegpd6X0eJjp2VP28zRNIxjXmn\r\n" \
	"+Z5PshddHH2ZHGC9hORTKiBrt66UiBf2IIRBfEq1BAIDLxNx1/zhMXLoT6py2jkq\r\n" \
	"83FiBCGbMOfDQc7gsX75byjokij5EnSsJiEKrM7L3k5trNHZwfkspM6M9FInbhWK\r\n" \
	"yL8/mwoUWVuip5xcUOr5qzy5zDRle8CEuBPuVSRh11aY/xdbB+lDLGuSgucz6WMy\r\n" \
	"sraORoTaZczeHHgGB4mc\r\n"                                             \
	"-----END CERTIFICATE-----\r\n"

const char selfsigned_cert[] = SELFSIGNED_CERT;

#define HOST_NAME "update.nes-lab.be"
const char *host_name = HOST_NAME;
const char *server_name = "update.nes-lab.be";
const char *server_addr = "192.168.137.1";
const uint16_t tcp_port = 8000;
const uint16_t tls_port = 8001;

TEE_Result TA_CreateEntryPoint(void)
{
	const char *cert_id;
	TEE_Result res;

	// cert_id = "DigiCert Global Root CA";
	// res = TEE_CreatePersistentObject(
	// 	TEE_STORAGE_PRIVATE, cert_id, sizeof(cert_id),
	// 	TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META,
	// 	TEE_HANDLE_NULL, digicert_global_root_ca,
	// 	sizeof(digicert_global_root_ca), &h.trustedCerts);
	cert_id = "Selfsigned";
	res = TEE_OpenPersistentObject(
		TEE_STORAGE_PRIVATE, cert_id, sizeof(cert_id),
		TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META,
		&h.trustedCerts);

	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		res = TEE_CreatePersistentObject(
			TEE_STORAGE_PRIVATE, cert_id, sizeof(cert_id),
			TEE_DATA_FLAG_ACCESS_READ |
				TEE_DATA_FLAG_ACCESS_WRITE_META,
			TEE_HANDLE_NULL, selfsigned_cert,
			sizeof(selfsigned_cert), &h.trustedCerts);
	}

	if (res != TEE_SUCCESS) {
		EMSG("Couldn't create persistent object for certificate: %x",
		     res);
		if (h.trustedCerts != TEE_HANDLE_NULL) {
			TEE_CloseAndDeletePersistentObject1(h.trustedCerts);
		}
		return res;
	}

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	if (h.trustedCerts != TEE_HANDLE_NULL) {
		TEE_CloseAndDeletePersistentObject1(h.trustedCerts);
	}
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

	if (strncmp(params[0].memref.buffer, host_name,
		    params[0].memref.size) != 0) {
		EMSG("Wrong destination url! dest: %s",
		     (char *)params[0].memref.buffer);
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
	tcp_setup.server_addr = (char *)server_addr;
	tcp_setup.server_port = tcp_port;

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

	if (strncmp(params[0].memref.buffer, host_name,
		    params[0].memref.size) != 0) {
		EMSG("Wrong destination url! dest: %s",
		     (char *)params[0].memref.buffer);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	const char *pers = "ssl_client1";
	TEE_tcpSocket_Setup tcp_setup = {};
	TEE_tlsSocket_Setup tls_setup = {};
	TEE_tlsSocket_Credentials credentials = {};
	TEE_tlsSocket_ServerPDC server_creds = {};
	uint32_t error;
	TEE_Result res;

	tcp_setup.ipVersion = TEE_IP_VERSION_4;
	tcp_setup.server_addr = (char *)server_addr;
	tcp_setup.server_port = tls_port;

	h.tcp_socket = TEE_tcpSocket;
	res = h.tcp_socket->open(&h.tcp_ctx, &tcp_setup, &error);
	if (res != TEE_SUCCESS) {
		EMSG("Couldn't open tcp_socket: %x", res);
		return res;
	}

	tls_setup.baseContext = &h.tcp_ctx;
	tls_setup.baseSocket = h.tcp_socket;
	tls_setup.persString = (const unsigned char *)pers;
	tls_setup.persStringLen = strlen(pers);
	tls_setup.serverName = (unsigned char *)server_name;
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

	if (strncmp(params[0].memref.buffer, host_name,
		    params[0].memref.size) != 0) {
		EMSG("Wrong destination url! dest: %s",
		     (char *)params[0].memref.buffer);
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

	if (strncmp(params[0].memref.buffer, host_name,
		    params[0].memref.size) != 0) {
		EMSG("Wrong destination url! dest: %s",
		     (char *)params[0].memref.buffer);
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

	if (strncmp(params[0].memref.buffer, host_name,
		    params[0].memref.size) != 0) {
		EMSG("Wrong destination url! dest: %s",
		     (char *)params[0].memref.buffer);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_Result res;
	void *recv = NULL;
	uint32_t recv_len;
	uint32_t i;

	const char *buf = "GET / HTTP/1.1\r\n"
			  "Host:" HOST_NAME "\r\n"
			  "Connection: Close\r\n"
			  "\r\n";
	uint32_t send_len = strlen(buf);

	res = h.tcp_socket->send(h.tcp_ctx, buf, &send_len,
				 TEE_TIMEOUT_INFINITE);
	if (res != TEE_SUCCESS) {
		EMSG("Couldn't send data on tcp_socket: %x", res);
		return res;
	}

	recv_len = 0;
	do {
		res = h.tcp_socket->recv(h.tcp_ctx, NULL, &recv_len,
					 TEE_TIMEOUT_INFINITE);
		if (res != TEE_SUCCESS) {
			EMSG("Couldn't get recv data length: %x", res);
			return res;
		}
	} while (recv_len == 0);

	IMSG("Received %u bytes", recv_len);
	recv = TEE_Malloc(recv_len, TEE_MALLOC_FILL_ZERO);
	res = h.tcp_socket->recv(h.tcp_ctx, recv, &recv_len,
				 TEE_TIMEOUT_INFINITE);
	if (res == TEE_SUCCESS) {
		for (i = 0; i < recv_len; i++) {
			putchar(((char *)recv)[i]);
		}
	} else {
		EMSG("Couldn't get recv data: %x", res);
	}

	TEE_Free(recv);
	return res;
}

struct chunk {
	struct chunk *head;
	struct chunk *next;
	unsigned int n;
	size_t size;
	char data[];
};

static size_t find_header_end(struct chunk *chunk)
{
	size_t i;
	size_t count = 0;
	size_t present = 0;

	i = 0;
	// DMSG("  i, count, present, size, data");
	while (present < 4) {
		// DMSG("%3d, %5d, %7d, %4d, %x", i, count, present, chunk->size,
		//      chunk->data);
		if (i < chunk->size) {
			if (present % 2 == 1 && chunk->data[i] == '\n') {
				present++;
			} else if (present % 2 == 0 && chunk->data[i] == '\r') {
				present++;
			} else {
				present = 0;
			}
			i++;
		} else if (chunk->next) {
			count += chunk->size;
			i = 0;
			chunk = chunk->next;
		} else {
			return 0;
		}
	}

	return count + i;
}

static size_t find_content_length(struct chunk *chunk, size_t header_len)
{
	size_t i;
	size_t count = 0;
	const char *indicator = "Content-Length: ";

	do {
		for (i = 0; i <= chunk->size - strlen(indicator); i++) {
			if (strncmp(&chunk->data[i], indicator,
				    strlen(indicator)) == 0) {
				goto indicator_found;
			}
		}
		count += chunk->size;
	} while ((chunk = chunk->next) && count < header_len);

	return 0;

indicator_found:
	i += strlen(indicator);
	size_t length = 0;
	// DMSG("  i, count, size, data");

	while (chunk) {
		if (i < chunk->size) {
			// DMSG("%3d, %5d, %4d, %c", i, count, chunk->size,
			//      chunk->data[i]);
			if (chunk->data[i] == '\r') {
				return length;
			} else {
				length *= 10;
				length += chunk->data[i] - '0';
			}
			i++;
		} else {
			count += chunk->size;
			i = 0;
			chunk = chunk->next;
		}
	}

	return 0;
}

static TEE_Result receive_data(void *buf, size_t *bytes)
{
	TEE_Result res;
	size_t recv_len = 0;
	do {
		res = h.tls_socket->recv(h.tls_ctx, NULL, &recv_len,
					 TEE_TIMEOUT_INFINITE);
		if (res != TEE_SUCCESS) {
			EMSG("Couldn't get recv data length: %x", res);
			return res;
		}
	} while (recv_len == 0);
	// DMSG("%u bytes available", recv_len);

	res = h.tls_socket->recv(h.tls_ctx, buf, &recv_len,
				 TEE_TIMEOUT_INFINITE);
	if (res != TEE_SUCCESS) {
		EMSG("Couldn't get recv data: %x", res);
		return res;
	}
	// DMSG("Received %u bytes", recv_len);
	*bytes = recv_len;

	return TEE_SUCCESS;
}

static TEE_Result receive_chunk(struct chunk **chunk, size_t *bytes)
{
	TEE_Result res;
	size_t recv_len = 0;
	do {
		res = h.tls_socket->recv(h.tls_ctx, NULL, &recv_len,
					 TEE_TIMEOUT_INFINITE);
		if (res != TEE_SUCCESS) {
			EMSG("Couldn't get recv data length: %x", res);
			return res;
		}
	} while (recv_len == 0);
	DMSG("%u bytes available", recv_len);

	struct chunk *next_chunk =
		TEE_Malloc(sizeof(struct chunk) + recv_len * sizeof(char),
			   TEE_MALLOC_FILL_ZERO);
	if (!next_chunk) {
		EMSG("Couldn't allocate memory for chunk %d: %x",
		     *chunk ? (*chunk)->n + 1 : 0, (unsigned int)next_chunk);
		return res;
	}
	if (*chunk) {
		(*chunk)->next = next_chunk;
		next_chunk->head = (*chunk)->head;
		next_chunk->n = (*chunk)->n + 1;
	} else {
		next_chunk->head = next_chunk;
		next_chunk->n = 0;
	}
	next_chunk->size = recv_len;

	res = h.tls_socket->recv(h.tls_ctx, &next_chunk->data,
				 &next_chunk->size, TEE_TIMEOUT_INFINITE);
	if (res != TEE_SUCCESS) {
		EMSG("Couldn't get recv data: %x", res);
		return res;
	}
	DMSG("Received chunk %d of size %u", next_chunk->n, next_chunk->size);
	*chunk = next_chunk;
	*bytes = (*chunk)->size;

	return TEE_SUCCESS;
}

static TEE_Result get_ssl_data(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (strncmp(params[0].memref.buffer, host_name,
		    params[0].memref.size) != 0) {
		EMSG("Wrong destination url! dest: %s",
		     (char *)params[0].memref.buffer);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_Result res;
	struct chunk *chunk = 0;
	size_t bytes = 0;
	size_t header_length = 0;
	size_t content_length = 0;

	// Send request
	const char *buf = "GET /zImage HTTP/1.1\r\n"
			  "Host:" HOST_NAME "\r\n"
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

	// Receive header
	while (header_length == 0) {
		size_t recv = 0;
		res = receive_chunk(&chunk, &recv);
		if (res != TEE_SUCCESS) {
			EMSG("Could not receive chunk.");
			return res;
		}
		bytes += recv;

		header_length = find_header_end(chunk->head);
		if (header_length > 0) {
			content_length =
				find_content_length(chunk->head, header_length);
			if (content_length == 0) {
				EMSG("No \"Content-Length\" found in header");
				return TEE_ERROR_ITEM_NOT_FOUND;
			}
		}

		DMSG("header_length, content_length, recv_bytes");
		DMSG("%13d, %14d, %10d", header_length, content_length, bytes);
	}

	// Receive content
	char *image = TEE_Malloc(content_length, TEE_MALLOC_FILL_ZERO);
	if (!image) {
		EMSG("Could not allocate enough space for content.");
		return res;
	}

	bytes -= header_length;
	if (bytes > 0) {
		// Already received part of content.
		// As the above loop ends immediatly after receiving the header
		// end, all content that we have received is in one chunck only.
		// This means we do not have to cross chunk edges.
		TEE_MemMove(image, &(chunk->data[chunk->size - bytes]), bytes);
	}

	while (bytes < content_length) {
		size_t recv;
		res = receive_data(&image[bytes], &recv);
		if (res != TEE_SUCCESS) {
			EMSG("Could not receive chunk.");
			return res;
		}
		bytes += recv;

		/* Print chunk */
		// size_t buffer_len = 49;
		// char buffer[buffer_len + 1];
		// memset(buffer, 0, buffer_len + 1);
		// size_t c = 0;
		// size_t i = 0;
		// for (i = 0; i < chunk->size; i += 2) {
		// 	char char1 = chunk->data[i];
		// 	if (c <= buffer_len - 4 && i <= chunk->size - 2) {
		// 		char char2 = chunk->data[i + 1];
		// 		snprintf(&buffer[c], 5, "%02x%02x", char1,
		// 			 char2);
		// 		c += 4;
		// 		if (c < buffer_len - 2) {
		// 			buffer[c] = ' ';
		// 			c++;
		// 		}
		// 	} else if (c <= buffer_len - 2 &&
		// 		   i <= chunk->size - 1) {
		// 		snprintf(&buffer[c], 3, "%02x", char1);
		// 		DMSG("%s", buffer);
		// 	} else {
		// 		DMSG("%s", buffer);
		// 		memset(buffer, 0, buffer_len + 1);
		// 		c = 0;
		// 		i -= 2;
		// 	}
		// }

		// if (c > 0) {
		// 	DMSG("%s", buffer);
		// }

		if ((bytes * 100 / content_length) % 10 == 0) {
			DMSG("header_length, content_length, recv_bytes");
			DMSG("%13d, %14d, %10d", header_length, content_length,
			     bytes);
		}
	}

	static const TEE_UUID system_uuid = PTA_UPDATER_UUID;
	uint32_t nparam_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	TEE_Param nparams[TEE_NUM_PARAMS] = {};
	TEE_TASessionHandle sess;
	uint32_t ret_orig = 0;

	nparams[0].value.a = (uint32_t)image;
	nparams[0].value.b = (uint32_t)content_length;

	res = TEE_OpenTASession(&system_uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
				&sess, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("Can't open session to updater PTA: 0x%08x, 0x%08x", res,
		     ret_orig);
		return res;
	}

	// res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
	// 			  PTA_UPDATER_CMD_ICREASE_MEM, 0, NULL,
	// 			  &ret_orig);
	// if (res != TEE_SUCCESS)
	// 	EMSG("Can't invoke updater PTA: 0x%08x, 0x%08x", res, ret_orig);

	size_t buffer_len = 80;
	char buffer[buffer_len + 1];
	uint8_t *img = image;
	size_t c;
	size_t i;
	for (i = 0; i < 20; i++) {
		memset(buffer, 0, buffer_len + 1);
		for (c = 0; c < buffer_len; c += 3) {
			snprintf(&buffer[c], 4, "%02x ", *img++);
		}
		DMSG("%s", buffer);
	}

	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  PTA_UPDATER_CMD_UPDATE, nparam_types, nparams,
				  &ret_orig);
	if (res != TEE_SUCCESS)
		EMSG("Can't invoke updater PTA: 0x%08x, 0x%08x", res, ret_orig);

	TEE_CloseTASession(sess);

	chunk = chunk->head;
	while (chunk) {
		struct chunk *tmp = chunk;
		chunk = tmp->next;
		TEE_Free(tmp);
	}
	TEE_Free(image);

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
