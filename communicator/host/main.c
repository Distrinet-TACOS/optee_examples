#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <communicator.h>

#include <mqtt.h>
#define JSMN_STRICT
#include <jsmn.h>
#include <ctype.h>

static int hex(char c)
{
	char lc = tolower(c);

	if (isdigit(lc))
		return lc - '0';
	if (isxdigit(lc))
		return lc - 'a' + 10;
	return -1;
}

static uint32_t parse_hex(const char *s, size_t nchars, TEEC_Result *res)
{
	uint32_t v = 0;
	size_t n = 0;
	int c = 0;

	for (n = 0; n < nchars; n++) {
		c = hex(s[n]);
		if (c == -1) {
			*res = TEEC_ERROR_BAD_FORMAT;
			goto out;
		}
		v = (v << 4) + c;
	}
	*res = TEEC_SUCCESS;
out:
	return v;
}

TEEC_Result uuid_from_str(TEEC_UUID *uuid, const char *s)
{
	TEEC_Result res = 0;
	TEEC_UUID u = {};
	const char *p = s;
	size_t i = 0;

	if (!p || strnlen(p, 37) != 36)
		return -1;
	if (p[8] != '-' || p[13] != '-' || p[18] != '-' || p[23] != '-')
		return -1;

	u.timeLow = parse_hex(p, 8, &res);
	if (res != TEEC_SUCCESS)
		goto out;
	p += 9;
	u.timeMid = parse_hex(p, 4, &res);
	if (res != TEEC_SUCCESS)
		goto out;
	p += 5;
	u.timeHiAndVersion = parse_hex(p, 4, &res);
	if (res != TEEC_SUCCESS)
		goto out;
	p += 5;
	for (i = 0; i < 8; i++) {
		u.clockSeqAndNode[i] = parse_hex(p, 2, &res);
		if (res != TEEC_SUCCESS)
			goto out;
		if (i == 1)
			p += 3;
		else
			p += 2;
	}
	*uuid = u;
out:
	return res;
}

void call_secure_app(const char *uuid_str, const char *dest)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid;
	uint32_t err_origin;

	res = uuid_from_str(&uuid, uuid_str);
	if (res != TEEC_SUCCESS) {
		warnx("Could not form valid uuid from string: 0x%x\n"
		      "Ignoring request",
		      res);
		return;
	}

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	}

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		warnx("The uuid does not represent an existing app\n"
		      "Ignoring request");
		return;
	} else if (res != TEEC_SUCCESS) {
		TEEC_FinalizeContext(&ctx);
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
		     res, err_origin);
	}

	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're incrementing a number.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = dest;
	op.params[0].tmpref.size = strlen(dest);

	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */
	printf("Opening unencrypted socket\n");
	res = TEEC_InvokeCommand(&sess, TA_COMMUNICATOR_CMD_OPEN_SOCKET, &op,
				 &err_origin);
	if (res == TEEC_ERROR_BAD_PARAMETERS) {
		warnx("App did not accept given url: %s", dest);
	} else if (res != TEEC_SUCCESS) {
		errx(1,
		     "TEEC_InvokeCommand TA_COMMUNICATOR_CMD_OPEN_SOCKET "
		     "failed with code 0x%x origin 0x%x",
		     res, err_origin);
	} else {
		printf("Sending and receiving\n");
		res = TEEC_InvokeCommand(&sess, TA_COMMUNICATOR_CMD_GET_DATA,
					 &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1,
			     "TEEC_InvokeCommand TA_COMMUNICATOR_CMD_GET_DATA "
			     "failed with code 0x%x origin 0x%x",
			     res, err_origin);
		printf("Closing unencrypted socket\n");
		res = TEEC_InvokeCommand(&sess,
					 TA_COMMUNICATOR_CMD_CLOSE_SOCKET, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1,
			     "TEEC_InvokeCommand TA_COMMUNICATOR_CMD_CLOSE_SOCKET "
			     "failed with code 0x%x origin 0x%x",
			     res, err_origin);
	}

	printf("Opening encrypted socket\n");
	res = TEEC_InvokeCommand(&sess, TA_COMMUNICATOR_CMD_OPEN_SSL_SOCKET,
				 &op, &err_origin);
	if (res == TEEC_ERROR_BAD_PARAMETERS) {
		warnx("App did not accept given url: %s", dest);
	} else if (res != TEEC_SUCCESS) {
		errx(1,
		     "TEEC_InvokeCommand TA_COMMUNICATOR_CMD_OPEN_SSL_SOCKET "
		     "failed with code 0x%x origin 0x%x",
		     res, err_origin);
	} else {
		printf("Sending and receiving\n");
		res = TEEC_InvokeCommand(&sess,
					 TA_COMMUNICATOR_CMD_GET_SSL_DATA, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1,
			     "TEEC_InvokeCommand TA_COMMUNICATOR_CMD_GET_SSL_DATA "
			     "failed with code 0x%x origin 0x%x",
			     res, err_origin);
		printf("Closing encrypted socket\n");
		res = TEEC_InvokeCommand(&sess,
					 TA_COMMUNICATOR_CMD_CLOSE_SSL_SOCKET,
					 &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1,
			     "TEEC_InvokeCommand TA_COMMUNICATOR_CMD_CLOSE_SSL_SOCKET "
			     "failed with code 0x%x origin 0x%x",
			     res, err_origin);
	}

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);
}

/*
    A template for opening a non-blocking POSIX socket.
*/
int connect_to_broker(const char *addr, const char *port)
{
	struct addrinfo hints = { 0 };

	hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Must be TCP */
	int sockfd = -1;
	int rv;
	struct addrinfo *p, *servinfo;

	/* get address information */
	rv = getaddrinfo(addr, port, &hints, &servinfo);
	if (rv != 0) {
		fprintf(stderr, "Failed to open socket (getaddrinfo): %s\n",
			gai_strerror(rv));
		return -1;
	}

	/* open the first possible socket */
	for (p = servinfo; p != NULL; p = p->ai_next) {
		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd == -1)
			continue;

		/* connect to server */
		rv = connect(sockfd, p->ai_addr, p->ai_addrlen);
		if (rv == -1) {
			close(sockfd);
			sockfd = -1;
			continue;
		}
		break;
	}

	/* free servinfo */
	freeaddrinfo(servinfo);

	if (sockfd != -1)
		fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);

	/* return the new socket fd */
	return sockfd;
}

void publish_callback(void **unused, struct mqtt_response_publish *published)
{
	/* note that published->topic_name is NOT null-terminated (here we'll change it to a c-string) */
	char *topic_name = (char *)malloc(published->topic_name_size + 1);
	memcpy(topic_name, published->topic_name, published->topic_name_size);
	topic_name[published->topic_name_size] = '\0';

	printf("Received publish('%s'): %s\n", topic_name,
	       (const char *)published->application_message);

	jsmn_parser p;
	jsmntok_t t[128]; /* We expect no more than 3 JSON tokens */
	int r, i;
	char *s;

	jsmn_init(&p);
	memset(t, 0, sizeof(t));
	r = jsmn_parse(&p, (const char *)published->application_message,
		       published->application_message_size, t, 128);
	if (r < 0) {
		printf("Error parsing json: %d", r);
		goto out;
	}

	bool app = false;
	bool url = false;
	char *uuid;
	char *dest;
	const char *message = published->application_message;

	for (i = 0; i < 128; i++) {
		jsmntok_t token = t[i];
		if (token.type != JSMN_UNDEFINED) {
			printf("Received token: %.*s\n",
			       token.end - token.start, message + token.start);

			if (app) {
				app = false;
				uuid = calloc((token.end - token.start) + 1,
					      sizeof(char));
				strncpy(uuid, message + token.start,
					token.end - token.start);
				printf("uuid: %s\n", uuid);
			} else if (url) {
				url = false;
				dest = calloc((token.end - token.start) + 1,
					      sizeof(char));
				strncpy(dest, message + token.start,
					token.end - token.start);
				printf("dest: %s\n", dest);
				break;
			}

			if (strncmp("app", message + token.start,
				    token.end - token.start) == 0) {
				app = true;
			} else if (strncmp("url", message + token.start,
					   token.end - token.start) == 0) {
				url = true;
			}
		}
	}

	if (uuid && dest) {
		call_secure_app(uuid, dest);
	}

out:
	free(topic_name);
	free(uuid);
	free(dest);
}

void *client_refresher(void *client)
{
	while (1) {
		mqtt_sync((struct mqtt_client *)client);
		usleep(100000U);
	}
	return NULL;
}

int main(void)
{
	const char *addr = "100.115.32.24";
	const char *port = "1883";
	const char *topic = "Device/"
			    "8b682154-cd03-4be7-bfd2-c809ab7bc408/"
			    "ConnectionRequest";
	int exit_code = EXIT_SUCCESS;

	/* open the non-blocking TCP socket (connecting to the broker) */
	int sockfd = connect_to_broker(addr, port);

	if (sockfd == -1) {
		perror("Failed to open socket: ");
		exit_code = EXIT_FAILURE;
		goto out;
	}

	/* setup a client */
	struct mqtt_client client;
	/* sendbuf should be large enough to hold multiple whole mqtt messages */
	uint8_t sendbuf[2048];
	/* recvbuf should be large enough any whole mqtt message expected to be received */
	uint8_t recvbuf[1024];
	mqtt_init(&client, sockfd, sendbuf, sizeof(sendbuf), recvbuf,
		  sizeof(recvbuf), publish_callback);
	/* Create an anonymous session */
	const char *client_id = NULL;
	/* Ensure we have a clean session */
	uint8_t connect_flags = MQTT_CONNECT_CLEAN_SESSION;
	/* Send connection request to the broker. */
	mqtt_connect(&client, client_id, NULL, NULL, 0, NULL, NULL,
		     connect_flags, 400);

	/* check that we don't have any errors */
	if (client.error != MQTT_OK) {
		fprintf(stderr, "error: %s\n", mqtt_error_str(client.error));
		exit_code = EXIT_FAILURE;
		goto out;
	}

	/* start a thread to refresh the client (handle egress and ingress client traffic) */
	pthread_t client_daemon;
	if (pthread_create(&client_daemon, NULL, client_refresher, &client)) {
		fprintf(stderr, "Failed to start client daemon.\n");
		exit_code = EXIT_FAILURE;
		goto out;
	}

	/* subscribe */
	mqtt_subscribe(&client, topic, 0);

	/* start publishing the time */
	printf("listening for '%s' messages.\n", topic);
	printf("Press CTRL-D to exit.\n\n");

	/* block */
	while (fgetc(stdin) != EOF)
		;

	/* disconnect */
	printf("\nDisconnecting from %s\n", addr);
	sleep(1);

out:
	/* exit */
	if (sockfd != -1)
		close(sockfd);
	if (client_daemon != NULL)
		pthread_cancel(client_daemon);
	exit(exit_code);
}
