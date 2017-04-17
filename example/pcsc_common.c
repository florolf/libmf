#include <stdio.h>
#include <stdlib.h>

#include <pcsclite.h>
#include <winscard.h>

#include "libmf.h"

struct pcsc_state {
	SCARDHANDLE crd;
	SCARD_IO_REQUEST proto;
};

uint8_t buf[256];

ssize_t pcsc_send(void *tr_data, uint8_t *data, size_t dlen, uint8_t **out) {
	struct pcsc_state *state = (struct pcsc_state*)tr_data;
	int rv;
	DWORD len = 256;

	rv = SCardTransmit(state->crd, &state->proto, data, dlen, NULL, buf, &len);
	if(rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardTransmit: %s\n", pcsc_stringify_error(rv));
		return -1;
	}

	*out = buf;
	return len;
}

mf_interface *pcsc_init(void) {
	SCARDCONTEXT ctx;
	LONG rv;

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	if(rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardEstablishContext: %s\n", pcsc_stringify_error(rv));
		exit(EXIT_FAILURE);
	}

	DWORD dwReaders;
	rv = SCardListReaders(ctx, NULL, NULL, &dwReaders);
	if(rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardListReaders: %s\n", pcsc_stringify_error(rv));
		exit(EXIT_FAILURE);
	}

	LPTSTR readers;
	if(!(readers = getenv("PCSC_READER"))) {
		readers = malloc(dwReaders);
		rv = SCardListReaders(ctx, NULL, readers, &dwReaders);
		if(rv != SCARD_S_SUCCESS) {
			fprintf(stderr, "SCardListReaders: %s\n", pcsc_stringify_error(rv));
			exit(EXIT_FAILURE);
		}
	}

	DWORD proto;
	struct pcsc_state *state = malloc(sizeof(struct pcsc_state));
	rv = SCardConnect(ctx, readers, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &state->crd, &proto);
	if(rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardConnect: %s\n", pcsc_stringify_error(rv));
		exit(EXIT_FAILURE);
	}

	switch(proto) {
	case SCARD_PROTOCOL_T0:
		state->proto = *SCARD_PCI_T0;
		break;

	case SCARD_PROTOCOL_T1:
		state->proto = *SCARD_PCI_T1;
		break;
	}

	mf_interface *intf;
	intf = mf_interface_new(pcsc_send, state);

	return intf;
}
