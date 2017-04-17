#include <stdio.h>
#include <stdlib.h>

#include <pcsclite.h>
#include <winscard.h>

#include "libmf.h"

mf_interface *pcsc_init();

int main(int argc, char **argv) {
	mf_interface *intf;

	intf = pcsc_init();

	mf_err_t ret;
	mf_aid_t *aids;
	size_t aids_num;

	ret = mf_get_application_ids(intf, &aids, &aids_num);
	if(ret != MF_OK) {
		fprintf(stderr, "mf_get_application_ids: %s\n", mf_error_str(ret));
		return EXIT_FAILURE;
	}

	printf("Found %zu applications.\n", aids_num);
	for(int i=0; i < aids_num; i++) {
		printf(" %X\n", aids[i]);
	}
}
