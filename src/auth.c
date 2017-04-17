#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "libmf.h"
#include "libmf-private.h"

static void rol_string(uint8_t *s, size_t l) {
	uint8_t tmp;
	tmp = s[0];
	memmove(s, s+1, l-1);
	s[l-1] = tmp;
}

static void ror_string(uint8_t *s, size_t l) {
	uint8_t tmp;
	tmp = s[l-1];
	memmove(s+1, s, l-1);
	s[0] = tmp;
}

void mf_key_set(mf_key_t key, uint8_t data[16]) {
	memcpy(key, data, 16);
}

void mf_key_set_version(mf_key_t key, uint8_t version) {
	int is_3des = !_mf_key_is_des(key);

	for(int i = 0; i < 8; i++) {
		uint8_t bit = version & 1;
		version >>= 1;

		key[i] &= 0xFE;
		key[i] |= bit;

		key[i+8] &= 0xFE;
		if(is_3des) //Make sure it does not become a DES-key
			key[i+8] |= !bit;
		else
			key[i+8] |= bit;
	}
}

int mf_key_parse(mf_key_t key, const char *data) {
	if(!data || strlen(data) != 32)
		return -1;

	for(int i=0; i < 16; i++) {
		char buf[3];
		buf[0] = tolower(data[2*i]);
		buf[1] = tolower(data[2*i+1]);
		buf[2] = 0;

		sscanf(buf, "%hhx", &key[i]);
	}

	return 0;
}

void mf_erase_session(mf_session *session) {
	memset(session->skey, 0, 16);
}

/*
  Authenticate
  Out: 0x0A keyId
  In:  0xAF ekNo(RndB)

  Out: 0xAF dkNo(rol(RndB, 8) || RndA)
  In:  0x00 ekNo(rol(RndA', 8))
*/
mf_err_t mf_authenticate(mf_interface *intf, mf_key_id_t key_id, mf_key_t key, mf_session *session) {
	uint8_t *out_str;
	uint8_t rndA[8], rndB[8];
	size_t out_str_size;

	mf_err_t ret = mf_call(intf, 0x0a, &key_id, 1, &out_str, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if((ret == 0xAF && out_str_size != 8) ||
	   (ret != 0xAF && out_str_size != 0) ||
	   ret == 0x00) {
		ret = MF_ERR_PROTO;
		goto out;
	}
	if(ret != 0xAF)
		goto out;

	_mf_des_operate(key, out_str, 8, 0);
	memcpy(rndB, out_str, 8);

	rol_string(out_str, out_str_size);

	uint8_t arg[16];
	_mf_get_random(rndA, 8);
	memcpy(arg, rndA, 8);
	memcpy(arg+8, out_str, 8);
	free(out_str);

	_mf_des_operate(key, arg, 16, 0);

	ret = mf_call(intf, 0xaf, arg, 16, &out_str, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if((ret == 0x00 && out_str_size != 8) ||
	   (ret != 0x00 && out_str_size != 0)) {
		ret = MF_ERR_PROTO;
		goto out;
	}
	if(ret != 0x00)
		goto out;

	_mf_des_operate(key, out_str, 8, 0);

	ror_string(out_str, 8);
	if(memcmp(out_str, rndA, 8) != 0) {
		ret = MF_ERR_CARD_AUTH_FAIL;
		goto out;
	}

	if(session) {
		session->akey_id = key_id;

		memcpy(session->skey,      rndA, 4);
		memcpy(&session->skey[4],  rndB, 4);
		if(_mf_key_is_des(key)) { //create a single des session key
			memcpy(&session->skey[8],  rndA, 4);
			memcpy(&session->skey[12], rndB, 4);
		} else {
			memcpy(&session->skey[8],  rndA+4, 4);
			memcpy(&session->skey[12], rndB+4, 4);
		}
	}

	ret = MF_OK;
 out:
	free(out_str);
	return ret;
}

/*
  GetKeyVersion
  Out: 0x64 keyId
  In:  error/keyVer
*/
mf_err_t mf_get_key_version(mf_interface *intf, mf_key_id_t key_id, uint8_t *key_ver) {
	uint8_t *out_str;
	size_t out_str_size;

	mf_err_t ret = mf_call(intf, 0x64, &key_id, 1, &out_str, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if((ret == 0x00 && out_str_size != 1) ||
	   (ret != 0x00 && out_str_size != 0)) {
		ret = MF_ERR_PROTO;
		goto out;
	}
	if(ret != 0x00)
		goto out;

	*key_ver = out_str[0];

	ret = MF_OK;
out:
	free(out_str);
	return ret;
}

/*
  GetKeySettings
  Out: 0x45
  In:  error/keySettings maxKeyNo
*/
mf_err_t mf_get_key_settings(mf_interface *intf, mf_key_settings_t *key_settings, uint8_t *max_key_num) {
	uint8_t *out_str;
	size_t out_str_size;

	mf_err_t ret = mf_call(intf, 0x45, NULL, 0, &out_str, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if((ret == 0x00 && out_str_size != 2) ||
	   (ret != 0x00 && out_str_size != 0)) {
		ret = MF_ERR_PROTO;
		goto out;
	}
	if(ret != 0x00)
		goto out;

	*key_settings = out_str[0];
	*max_key_num = out_str[1];

	ret = MF_OK;
out:
	free(out_str);
	return ret;
}

/*
  ChangeKeySettings
  Out: 0x54
  In:  status
*/
mf_err_t mf_change_key_settings(mf_interface *intf, mf_session *session, mf_key_settings_t key_settings) {
	uint8_t arg[8];

	arg[0] = key_settings;
	_mf_crypto_write(session, MF_COMM_CRYPT, arg, 1, 8);
	
	size_t out_str_size;
	mf_err_t ret = mf_call(intf, 0x54, arg, 8, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;
	
	return ret;
}

/*
  ChangeKey
  Out: 0xC4 keyNo keyData[24]
  In: status
*/
mf_err_t mf_change_current_key(mf_interface *intf, mf_session *session, mf_key_t new_key) {
	uint8_t arg[25];

	arg[0] = session->akey_id;
	memcpy(arg+1, new_key, 16);
	_mf_crypto_write(session, MF_COMM_CRYPT, arg+1, 16, 24);

	size_t out_str_size;
	mf_err_t ret = mf_call(intf, 0xC4, arg, 25, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

mf_err_t mf_change_other_key(mf_interface *intf, mf_session *session, mf_key_id_t key_id, mf_key_t old_key, mf_key_t new_key) {
	uint8_t arg[25];

	arg[0] = key_id;
	memcpy(arg+1, new_key, 16);
	_mf_crc16(arg+1, 16, arg+19);
	_mf_do_xor(arg+1, old_key, 16);
	_mf_crc16(arg+1, 16, arg+17);

	memset(arg+21, 0, 4);

	_mf_des_operate(session->skey, arg+1, 24, 0);

	size_t out_str_size;
	mf_err_t ret = mf_call(intf, 0xC4, arg, 25, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}
