/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <winscard.h>
#include <string.h>

int
main(int argc, char *argv[])
{
	struct timespec t1, t2;
	unsigned short status;
	int i;

	LONG rv;

	SCARDCONTEXT ctx;
	LPTSTR readers;
	LPTSTR thisrdr;
	SCARDHANDLE card;
	DWORD readersLen, activeProtocol, recvLength;

	SCARD_IO_REQUEST sendPci;
	BYTE recvBuffer[258];
	BYTE selectCmd[] = {
	    0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20,
	    0x01, 0x00
	};
	BYTE hmacCmd[] = {
	    0x00, 0x01, 0x30, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	    0x77, 0x88, 0x00
	};

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardEstablishContext failed: %s\n",
		    pcsc_stringify_error(rv));
		return (1);
	}

	rv = SCardListReaders(ctx, NULL, NULL, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardListReaders failed: %s\n",
		    pcsc_stringify_error(rv));
		return (1);
	}
	readers = calloc(readersLen, 1);
	rv = SCardListReaders(ctx, NULL, readers, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardListReaders failed: %s\n",
		    pcsc_stringify_error(rv));
		return (1);
	}

	for (thisrdr = readers; *thisrdr != 0; thisrdr += strlen(thisrdr) + 1) {
		fprintf(stderr, "trying reader %s...\n", thisrdr);

		rv = SCardConnect(ctx, thisrdr, SCARD_SHARE_SHARED,
		    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card,
		    &activeProtocol);
		if (rv != SCARD_S_SUCCESS) {
			fprintf(stderr, "SCardConnect failed: %s\n",
			    pcsc_stringify_error(rv));
			continue;
		}

		switch (activeProtocol) {
		case SCARD_PROTOCOL_T0:
			sendPci = *SCARD_PCI_T0;
			break;
		case SCARD_PROTOCOL_T1:
			sendPci = *SCARD_PCI_T1;
			break;
		}

		recvLength = sizeof (recvBuffer);

		rv = SCardTransmit(card, &sendPci, selectCmd, sizeof(selectCmd),
		    NULL, recvBuffer, &recvLength);
		if (rv != SCARD_S_SUCCESS) {
			fprintf(stderr, "SCardTransmit failed: %s\n",
			    pcsc_stringify_error(rv));
			continue;
		}

		recvLength -= 2;
		status = (recvBuffer[recvLength] << 8) |
		    recvBuffer[recvLength + 1];
		if (status != 0x9000) {
			fprintf(stderr, "Card returned status %04x\n", status);
			continue;
		}

		if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) {
			perror("clock_gettime");
			return (1);
		}

		for (i = 0; i < 250; ++i) {
			recvLength = sizeof (recvBuffer);

			rv = SCardTransmit(card, &sendPci, hmacCmd,
			    sizeof(hmacCmd), NULL, recvBuffer, &recvLength);
			if (rv != SCARD_S_SUCCESS) {
				fprintf(stderr, "SCardTransmit failed: %s\n",
				    pcsc_stringify_error(rv));
				return (1);
			}

			recvLength -= 2;
			status = (recvBuffer[recvLength] << 8) |
			    recvBuffer[recvLength + 1];
			if (status != 0x9000) {
				fprintf(stderr, "Card returned status %04x\n",
				    status);
				return (2);
			}

			if (recvLength != 20) {
				fprintf(stderr, "Card returned short HMAC "
				    "result (only %d bytes)\n", recvLength);
				return (2);
			}
		}

		if (clock_gettime(CLOCK_MONOTONIC, &t2) != 0) {
			perror("clock_gettime");
			return (1);
		}

		t2.tv_sec -= t1.tv_sec;
		t2.tv_nsec -= t1.tv_nsec;
		if (t2.tv_nsec < 0) {
			t2.tv_sec--;
			t2.tv_nsec += 1000000000;
		}
		fprintf(stdout, "250 hmacs in %ld.%09ld s\n", t2.tv_sec,
		    t2.tv_nsec);
		return (0);
	}

	fprintf(stderr, "No readers found\n");
	return (1);
}
