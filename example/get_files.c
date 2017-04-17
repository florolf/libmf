#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcsclite.h>
#include <winscard.h>

#include "libmf.h"

mf_interface *pcsc_init();

void print_help(const char *name) {
	fprintf(stderr, "usage: %s [-k key] aid\n", name);
}

mf_aid_t parse_aid(const char *a) {
	mf_aid_t out = 0;

	for(int i=0; i < 3; i++) {
		out <<= 8;

		char buf[3];
		buf[0] = a[2*i];
		buf[1] = a[2*i+1];
		buf[2] = 0;

		uint8_t tmp;
		sscanf(buf, "%hhx", &tmp);

		out |= tmp;
	}

	return out;
}

void print_access(mf_access_t access) {
	printf("%X", MF_ACCESS_GET_CHANGE(access));
	printf("%X", MF_ACCESS_GET_RW(access));
	printf("%X", MF_ACCESS_GET_W(access));
	printf("%X", MF_ACCESS_GET_R(access));
}

int main(int argc, char **argv) {
	mf_interface *intf;

	if(argc < 2) {
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	intf = pcsc_init();

	if(!strcmp(argv[1], "-k")) {
		if(argc < 4) {
			print_help(argv[0]);
			return EXIT_FAILURE;
		}

		mf_key_t k;
		mf_key_parse(k, argv[2]);

		mf_err_t ret;
		ret = mf_authenticate(intf, 0, k, NULL);
		if(ret != MF_OK) {
			fprintf(stderr, "Authentication failed: %s\n", mf_error_str(ret));
			return EXIT_FAILURE;
		}

		argv += 2;
	}

	mf_aid_t aid = parse_aid(argv[1]);
	mf_err_t ret;
	ret = mf_select_application(intf, aid);
	if(ret != MF_OK) {
		fprintf(stderr, "Selecting application failed: %s\n", mf_error_str(ret));
		return EXIT_FAILURE;
	}

	mf_file_id *file_list;
	size_t nfiles;
	ret = mf_get_file_ids(intf, &file_list, &nfiles);
	if(ret != MF_OK) {
		fprintf(stderr, "Listing files failed: %s\n", mf_error_str(ret));
		return EXIT_FAILURE;
	}

	printf("Application contains %zu files.\n", nfiles);

	for(int i=0; i < nfiles; i++) {
		mf_file_settings stat;
		ret = mf_get_file_settings(intf, file_list[i], &stat);
		if(ret != MF_OK) {
			fprintf(stderr, "Getting settings for file %02X failed: %s\n", file_list[i], mf_error_str(ret));
			return EXIT_FAILURE;
		}

		switch(stat.type) {
		case MF_FILE_TYPE_STANDARD:
			printf("-");
		case MF_FILE_TYPE_BACKUP:
			if(stat.type == MF_FILE_TYPE_BACKUP)
				printf("b");

			print_access(stat.access);

			printf("\t%02X", stat.comm_settings);
			printf("\t%d", stat.attr.standard.size);
			break;

		case MF_FILE_TYPE_VALUE:
			printf("%c", stat.attr.value.limited_enabled?'V':'v');
			print_access(stat.access);

			printf("\t%02X", stat.comm_settings);
			printf("\t%d-%d", stat.attr.value.lower_limit, stat.attr.value.upper_limit);

			if(stat.attr.value.limited_enabled) {
				printf("\t%d", stat.attr.value.limited_limit);
			}
			break;

		case MF_FILE_TYPE_LINREC:
			printf("l");
		case MF_FILE_TYPE_CYCREC:
			if(stat.type == MF_FILE_TYPE_CYCREC)
				printf("c");
			print_access(stat.access);

			printf("\t%02X", stat.comm_settings);
			printf("\t%d", stat.attr.record.record_size);
			printf("\t%d", stat.attr.record.cur_records);
			printf("\t%d", stat.attr.record.max_records);
		}

		printf("\t%02X\n", file_list[i]);
	}
}
