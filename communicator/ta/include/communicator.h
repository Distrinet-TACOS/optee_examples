#ifndef TA_COMMUNICATOR_H
#define TA_COMMUNICATOR_H

#include <stdint.h>

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_COMMUNICATOR_UUID \
	{ 0xc76ff39b, 0x9d31, 0x402d, \
		{ 0xa1, 0xba, 0x60, 0xdf, 0xa9, 0xcc, 0x6d, 0xd2} }

/* The function IDs implemented in this TA */
#define TA_COMMUNICATOR_CMD_OPEN_SOCKET		0
#define TA_COMMUNICATOR_CMD_CLOSE_SOCKET	1
#define TA_COMMUNICATOR_CMD_GET_DATA		2
#define TA_COMMUNICATOR_CMD_OPEN_SSL_SOCKET	3
#define TA_COMMUNICATOR_CMD_CLOSE_SSL_SOCKET	4
#define TA_COMMUNICATOR_CMD_GET_SSL_DATA	5
#define TA_COMMUNICATOR_CMD_CONNECTION_REQUEST	UINT32_MAX

#endif /*TA_COMMUNICATOR_H*/
