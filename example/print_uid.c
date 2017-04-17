#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <gcrypt.h>

#include <pcsclite.h>
#include <winscard.h>

#include "libmf.h"

mf_interface *pcsc_init();

int print_buffer(FILE *f, uint8_t *b, size_t n) {
	for(int i=0; i < n; i++) {
		if(fprintf(f, "%02X", b[i]) != 2) {
			perror("Write failed");
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv) {
	mf_interface *intf;
	intf = pcsc_init();

	mf_err_t ret;

	mf_version v;
	ret = mf_get_version(intf, &v);
	if(ret != MF_OK) {
		fprintf(stderr, "Getting version failed: %s\n", mf_error_str(ret));
		return EXIT_FAILURE;
	}

	print_buffer(stdout, v.uid, 7);

	return EXIT_SUCCESS;
}
