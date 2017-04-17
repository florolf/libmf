#include <stdio.h>
#include <stdlib.h>

#include <histedit.h>

#include <pcsclite.h>
#include <winscard.h>

#include "libmf.h"

mf_interface *pcsc_init();
int current_key = -1;

char *prompt(EditLine *e) {
	static char buf[64];

	if(current_key < 0) {
		snprintf(buf, 64, "> ");
	} else {
		snprintf(buf, 64, "%x> ", current_key);
	}

	return buf;
}

int main(int argc, char **argv) {
	mf_interface *intf;

	intf = pcsc_init();
	if(!intf) {
		fprintf(stderr, "Failed to initialize pcsc\n");
		return EXIT_FAILURE;
	}

	EditLine *e = el_init("mfsh", stdin, stdout, stderr);
	el_set(e, EL_PROMPT, prompt);

	History *h = history_init();
	el_set(e, EL_HIST, h);
	
	while(1) {
		int count;
		const char *line = el_gets(e, &count);

	}
}
