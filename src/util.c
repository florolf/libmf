#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "libmf.h"
#include "libmf-private.h"

static size_t _mf_build_iso(uint8_t cmd, uint8_t *args, uint8_t arg_size, uint8_t **out) {
	uint8_t *out_buffer;
	size_t out_size;

	out_size = 5;
	if(arg_size != 0) {
		assert(args);
		out_size += arg_size + 1;
	}

	out_buffer = malloc(out_size);
	out_buffer[0] = 0x90; //CLA
	out_buffer[1] = cmd; //INS
	out_buffer[2] = out_buffer[3] = 0x00; //P1, P2

	if(arg_size != 0) {
		out_buffer[4] = arg_size; //Lc
		memcpy(&out_buffer[5], args, arg_size);
	}

	out_buffer[out_size-1] = 0x00; //Le
	*out = out_buffer;

	return out_size;
}

static void *memndup(const void *src, size_t n) {
	if(!n)
		return NULL;

	void *out = malloc(n);
	memcpy(out, src, n);

	return out;
}

void *_mf_xmalloc(size_t size) {
	void *ret = malloc(size);
	assert(ret);

	return ret;
}

void _mf_dump_data(uint8_t *d, size_t n) {
	size_t i;
	for(i = 0; i < n; i++) {
		fprintf(stderr, "%02X ", d[i]);
	}
	fprintf(stderr, "\n");
}

int mf_call(mf_interface *intf, uint8_t cmd, uint8_t *args, size_t arg_size,
                uint8_t **out, size_t *out_size) {
	uint8_t *cmd_str, *out_str;
	ssize_t cmd_str_size, out_str_size;

	cmd_str_size = _mf_build_iso(cmd, args, arg_size, &cmd_str);
	if(getenv("LIBMF_DEBUG")) {
		fprintf(stderr, "Send: "); _mf_dump_data(cmd_str, cmd_str_size);
	}

	out_str_size = intf->transceive(intf->tr_data, cmd_str, cmd_str_size, &out_str);
	free(cmd_str);

	if(out_str_size < 2)
		return MF_ERR_TRANSFER_FAILED;

	// fail if we did not get a mifare response
	if(out_str[out_str_size-2] != 0x91)
		return MF_ERR_TRANSFER_FAILED;

	if(getenv("LIBMF_DEBUG")) {
		fprintf(stderr, "Recv: "); _mf_dump_data(out_str, out_str_size);
	}

	if(out) {
		*out = memndup(out_str, out_str_size - 2);
	}
	*out_size = out_str_size - 2;

	return out_str[out_str_size - 1];
}


uint16_t _mf_parse16(uint8_t *p) {
	return p[0] | p[1] << 8;
}

uint32_t _mf_parse24(uint8_t *p) {
	return p[0] | p[1] << 8 | p[2] << 16;
}

uint32_t _mf_parse32(uint8_t *p) {
	return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

void _mf_deparse16(uint8_t *p, uint16_t d) {
	p[0] = d & 0xFF;
	p[1] = (d >> 8) & 0xFF;
}

void _mf_deparse24(uint8_t *p, uint32_t d) {
	p[0] = d & 0xFF;
	p[1] = (d >> 8) & 0xFF;
	p[2] = (d >> 16) & 0xFF;
}

void _mf_deparse32(uint8_t *p, uint32_t d) {
	p[0] = d & 0xFF;
	p[1] = (d >> 8) & 0xFF;
	p[2] = (d >> 16) & 0xFF;
	p[3] = (d >> 24) & 0xFF;
}
