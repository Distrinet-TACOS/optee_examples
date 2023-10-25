/*
 * The name of this file must not be modified
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

/* To get the TA UUID definition */
#include <communicator.h>

#define TA_UUID TA_COMMUNICATOR_UUID

/*
 * TA_FLAG_EXEC_DDR is meaningless but mandated.
 */
#define TA_FLAGS                                                               \
	(TA_FLAG_EXEC_DDR | TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION |  \
	 TA_FLAG_INSTANCE_KEEP_ALIVE)

/* Provisioned stack size */
#define TA_STACK_SIZE (10 * 1024)

/* Provisioned heap size for TEE_Malloc() and friends */
#define TA_DATA_SIZE (2 * 32 * 1024)

/* The gpd.ta.version property */
#define TA_VERSION "1.0"

/* The gpd.ta.description property */
#define TA_DESCRIPTION "ERATOSTHENES communicator component"

#endif /* USER_TA_HEADER_DEFINES_H */
