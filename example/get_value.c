#include <stdio.h>
#include <stdlib.h>

#include <pcsclite.h>
#include <winscard.h>

#include "libmf.h"

mf_interface *pcsc_init();

int main(int argc, char **argv) {
	mf_interface *intf;
	mf_key_t k;

	if(argc < 2) {
		fprintf(stderr, "usage: %s master_key\n", argv[0]);
		fprintf(stderr, "Example: %s 00000000000000000000000000000000\n", argv[0]);

		return EXIT_FAILURE;
	}

	intf = pcsc_init();

	mf_key_parse(k, argv[1]);

	mf_err_t ret;

	ret = mf_select_application(intf, 0x621621);
	if(ret != MF_OK) {
		fprintf(stderr, "Selecting application failed: %s\n", mf_error_str(ret));
		return EXIT_FAILURE;
	}

	mf_session sess;
	ret = mf_authenticate(intf, 0, k, &sess);
	if(ret != MF_OK) {
		fprintf(stderr, "Authentication failed: %s\n", mf_error_str(ret));
		return EXIT_FAILURE;
	}

	uint32_t value;
	ret = mf_get_value(intf, &sess, 0x3, &value);
	if(ret != MF_OK) {
		fprintf(stderr, "Authentication failed: %s\n", mf_error_str(ret));
		return EXIT_FAILURE;
	}

	printf("Value: %d\n", value);

	return EXIT_SUCCESS;
}
