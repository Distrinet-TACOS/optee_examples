/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
// #include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

#define PTA_TEST_PRINT_UUID { 0xd4be3f91, 0xc4e1, 0x436c, \
    { 0xb2, 0x92, 0xbf, 0xf5, 0x3e, 0x43, 0x04, 0xd5 } }

#define PTA_REGISTER_ITR 0
#define PTA_DISABLE_ITR 1

static TEEC_UUID uuid = PTA_TEST_PRINT_UUID;

void createSession(TEEC_Context* ctx, TEEC_Session* sess, uint32_t* err_origin) {
	TEEC_Result res;

    /* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(ctx, sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, *err_origin);
}

TEEC_Operation* createOperation(void) {
    TEEC_Operation* op = calloc(1, sizeof(TEEC_Operation));
	op->paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    return op;
}

void enableInterrupt(TEEC_Session* sess, uint32_t* err_origin) {
	TEEC_Result res;
    TEEC_Operation* op = createOperation();

    res = TEEC_InvokeCommand(sess, PTA_REGISTER_ITR, op, err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
}

void disableInterrupt(TEEC_Session* sess, uint32_t* err_origin) {
	TEEC_Result res;

    res = TEEC_InvokeCommand(sess, PTA_DISABLE_ITR, createOperation(), err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
}

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	uint32_t err_origin;

    createSession(&ctx, &sess, &err_origin);

	char c;
    printf("Enable or disable interrupt? (e/d)\n");
    scanf(" %c", &c);
    printf("You entered: %c\n", c);
    if (c == 'e') {
        printf("Invoking PTA to register console interrupt.\n");
        enableInterrupt(&sess, &err_origin);
        printf("Console interrupt registered.\n");
    } else if (c == 'd') {
        printf("Invoking PTA to disable console interrupt.\n");
        enableInterrupt(&sess, &err_origin);
        printf("Console interrupt disabled.\n");
    } else {
        printf("Wrong option.");
        return 0;
    }

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
