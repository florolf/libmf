#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "libmf.h"
#include "libmf-private.h"

mf_interface *mf_interface_new(ssize_t (*transceive)(void*, uint8_t *data, size_t dlen, uint8_t **out), void *data) {
	mf_interface *ret;

	ret = malloc(sizeof(struct _mf_interface));
	assert(ret);

	ret->transceive = transceive;
	ret->tr_data = data;

	return ret;
}

void *mf_interface_free(mf_interface *intf) {
	void *data = intf->tr_data;

	free(intf);

	return data;
}
