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
	ret = mf_authenticate(intf, 0, k, NULL);
	if(ret != MF_OK) {
		fprintf(stderr, "Authentication failed: %s\n", mf_error_str(ret));
		return EXIT_FAILURE;
	}

	ret = mf_format_picc(intf);
	if(ret != MF_OK) {
		fprintf(stderr, "Formatting PICC failed: %s\n", mf_error_str(ret));
		return EXIT_FAILURE;
	}
}
