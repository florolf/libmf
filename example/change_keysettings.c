#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcsclite.h>
#include <winscard.h>

#include "libmf.h"

mf_interface *pcsc_init();

int main(int argc, char **argv) {
	mf_interface *intf;

	intf = pcsc_init();
	
	mf_err_t ret;

	ret = mf_select_application(intf, 0x621621);
	if(ret != MF_OK) {
		fprintf(stderr, "Selecting application failed: %s\n", mf_error_str(ret));
		return EXIT_FAILURE;
	}

	mf_key_t k;
	memset(k, 0, 16);

	mf_session s;
	ret = mf_authenticate(intf, 0, k, &s);
	if(ret != MF_OK) {
		fprintf(stderr, "Authentication failed: %s\n", mf_error_str(ret));
		return EXIT_FAILURE;
	}

	ret = mf_change_key_settings(intf, &s, 0x80);
	if(ret != MF_OK) {
		fprintf(stderr, "ChangeKeySettings failed: %s\n", mf_error_str(ret));
		return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;
}
