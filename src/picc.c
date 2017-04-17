#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "libmf.h"
#include "libmf-private.h"

/*
  GetVersion
  Out: 0x60
  In:  0xAF hw_vendor_id hw_type hw_subtype hw_major_version
       hw_minor_version hw_storage_size hw_protocol

  Out: 0xAF
  In:  0xAF sw_vendor_id sw_type sw_subtype sw_major_version
       sw_minor_version sw_storage_size sw_protocol

  Out: 0xAF
  In:  0x00 uid[7] batch[5] cw year
 */
mf_err_t mf_get_version(mf_interface *intf, mf_version *version) {
	uint8_t *out;
	size_t out_size;

	mf_err_t ret = mf_call(intf, 0x60, NULL, 0, &out, &out_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(ret != 0xAF || out_size != 7) {
		free(out);
		return MF_ERR_PROTO;
	}

	version->hw_vendor = out[0];
	version->hw_type = out[1];
	version->hw_subtype = out[2];
	version->hw_major_version = out[3];
	version->hw_minor_version = out[4];
	version->hw_storage_size = out[5];
	version->hw_protocol = out[6];
	free(out);

	ret = mf_call(intf, 0xAF, NULL, 0, &out, &out_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(ret != 0xAF || out_size != 7) {
		free(out);

		return MF_ERR_PROTO;
	}

	version->sw_vendor = out[0];
	version->sw_type = out[1];
	version->sw_subtype = out[2];
	version->sw_major_version = out[3];
	version->sw_minor_version = out[4];
	version->sw_storage_size = out[5];
	version->sw_protocol = out[6];
	free(out);

	ret = mf_call(intf, 0xAF, NULL, 0, &out, &out_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(ret != 0x00 || out_size != 14) {
		free(out);

		return MF_ERR_PROTO;
	}

	memcpy(version->uid, out, 7);
	memcpy(version->batch, out+7, 5);
	version->prod_cw = out[12];
	version->prod_year = out[13];
	free(out);

	return MF_OK;
}

/*
  FormatPicc
  Out: 0xFC
  In:  status
 */
mf_err_t mf_format_picc(mf_interface *intf) {
	uint8_t *out;
	size_t out_size;

	mf_err_t ret = mf_call(intf, 0xFC, NULL, 0, &out, &out_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_size != 0) {
		free(out);
		return MF_ERR_PROTO;
	}

	return ret;
}
