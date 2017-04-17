#include <stdlib.h>
#include <string.h>

#include "libmf.h"
#include "libmf-private.h"

static mf_aid_t _mf_pack_aid(uint8_t *buf) {
       return  buf[0] << 16 |
               buf[1] <<  8 |
               buf[2];
}

static void _mf_unpack_aid(uint8_t *buf, mf_aid_t aid) {
	buf[0] = (aid >> 16) & 0xFF;
	buf[1] = (aid >> 8) & 0xFF;
	buf[2] = aid & 0xFF;
}

/*
  SelectApplication
  Out: 0x5A aid[3]
  In:  status
*/
mf_err_t mf_select_application(mf_interface *intf, mf_aid_t aid) {
	uint8_t buf[3];

	_mf_unpack_aid(buf, aid);

	size_t out_str_size;
	mf_err_t ret = mf_call(intf, 0x5a, buf, 3, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

/*
  DeleteApplication
  Out: 0xDA aid[3]
  In:  status
*/
mf_err_t mf_delete_application(mf_interface *intf, mf_aid_t aid) {
	uint8_t buf[3];

	_mf_unpack_aid(buf, aid);

	size_t out_str_size;
	mf_err_t ret = mf_call(intf, 0xDA, buf, 3, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

mf_key_settings_t mf_build_key_settings(mf_key_id_t change_key_id, uint8_t flags) {
	return (change_key_id & 0x0F) << 4 | (flags & 0x0F);
}

/*
  DeleteApplication
  Out: 0xCA aid[3] key_settings key_num
  In:  status
*/
mf_err_t mf_create_application(mf_interface *intf, mf_aid_t aid, mf_key_settings_t key_settings, uint8_t key_num) {
	uint8_t buf[5];

	_mf_unpack_aid(buf, aid);

	buf[3] = key_settings;
	buf[4] = key_num;

	size_t out_str_size;
	mf_err_t ret = mf_call(intf, 0xCA, buf, 5, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

/*
  GetApplicationIDs
  Out: 0x6A
  In:  error/0x00 aids/0xAF aids1

  If 0xAF
  Out: 0xAF
  In:  error/0x00 aids2
*/
mf_err_t mf_get_application_ids(mf_interface *intf, mf_aid_t **aids, size_t *aids_num) {
	uint8_t *out_str;
	size_t out_str_size;

	mf_err_t ret = mf_call(intf, 0x6A, NULL, 0, &out_str, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if((!(ret == 0xAF || ret == 0x00) && out_str_size != 0) ||
	   ( (ret == 0xAF || ret == 0x00) && (out_str_size % 3 != 0))) {
		ret = MF_ERR_PROTO;
		goto out;
	}
	if(!(ret == 0xAF || ret == 0x00))
		goto out;

	if(out_str_size == 0) {
		*aids = NULL;
		*aids_num = 0;

		ret = MF_OK;
		goto out;
	}

	*aids_num = out_str_size/3;
	*aids = calloc(*aids_num, sizeof(mf_aid_t));
	int aid_index;
	for(aid_index=0; aid_index < *aids_num; aid_index++) {
		(*aids)[aid_index] = _mf_pack_aid(out_str + 3*aid_index);
	}

	// All AIDs did fit into one frame
	if(ret == 0x00) {
		ret = MF_OK;
		goto out;
	}

	// Get the rest
	free(out_str);
	ret = mf_call(intf, 0xAF, NULL, 0, &out_str, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if((ret != 0x00 && out_str_size != 0) ||
	   (ret == 0x00 && (out_str_size % 3 != 0 || out_str_size == 0)) ||
	   ret == 0xAF) {
		ret = MF_ERR_PROTO;
		goto out;
	}
	if(ret != 0x00)
		goto out;

	*aids_num += out_str_size/3;
	*aids = realloc(*aids, *aids_num * sizeof(mf_aid_t));
	for(int off=0; aid_index + off < *aids_num; off++) {
		(*aids)[aid_index+off] = _mf_pack_aid(out_str + 3*off);
	}

	ret = MF_OK;
out:
	free(out_str);
	return ret;
}
