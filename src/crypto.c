#include <gcrypt.h>

#include "libmf.h"

void _mf_do_xor(uint8_t *d, uint8_t *s, size_t n) {
	size_t i;
	for(i=0; i < n; i++) {
		d[i] ^= s[i];
	}
}

int _mf_key_is_des(mf_key_t key) {
	for(int i=0; i < 8; i++)
		if(key[i] != key[i+8])
			return 0;

	return 1;
}

/*
  mode == 0: CBC encipher
  mode == 1: CBC decipher
*/
int _mf_des_operate(mf_key_t key, uint8_t *in, size_t len, int mode) {
	uint8_t iv[8];

	if(len % 8 != 0)
		return -1;

	memset(iv, 0, 8);

	gcry_cipher_hd_t des1, des2;

	int ret;
	ret = gcry_cipher_open(&des1, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
	if(ret)
		return -1;

	ret = gcry_cipher_setkey(des1, key, 8);
        if(ret && gcry_err_code(ret) != GPG_ERR_WEAK_KEY)
	        return -1;

	ret = gcry_cipher_open(&des2, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
	if(ret)
		return -1;

	ret = gcry_cipher_setkey(des2, key+8, 8);
        if(ret && gcry_err_code(ret) != GPG_ERR_WEAK_KEY)
	        return -1;

        for(int i=0; i < len/8; i++) {
	        uint8_t d[8], t[8];
	        memcpy(d, in + i*8, 8);

	        if(mode == 0)
		        _mf_do_xor(d, iv, 8);

	        gcry_cipher_decrypt(des1, t, 8, d, 8);
	        gcry_cipher_encrypt(des2, d, 8, t, 8);
	        gcry_cipher_decrypt(des1, t, 8, d, 8);

	        if(mode == 0) {
		        memcpy(iv, t, 8);
	        } else {
		        _mf_do_xor(t, iv, 8);
		        memcpy(iv, in + i*8, 8);
	        }

	        memcpy(in + i*8, t, 8);
        }

        gcry_cipher_close(des1);
        gcry_cipher_close(des2);

        return 0;
}

void _mf_get_random(uint8_t *out, size_t len) {
	gcry_randomize(out, len, GCRY_STRONG_RANDOM);
}

//libnfc
void _mf_crc16(uint8_t *data, size_t len, uint8_t *out) {
	uint8_t  bt;
	uint32_t wCrc = 0x6363;

	do {
		bt = *data++;
		bt = (bt ^ (uint8_t) (wCrc & 0x00FF));
		bt = (bt ^ (bt << 4));
		wCrc = (wCrc >> 8) ^ ((uint32_t) bt << 8) ^ ((uint32_t) bt << 3) ^ ((uint32_t) bt >> 4);
	} while (--len);

	*out++ = (uint8_t) (wCrc & 0xFF);
	*out = (uint8_t) ((wCrc >> 8) & 0xFF);
}

int _mf_crypto_read(mf_session *sess, mf_comm_settings_t cs, uint8_t *data, size_t inner_len, size_t len) {
	if(cs == MF_COMM_PLAIN)
		return 0;

	//MACing is not supported at present
	if(cs == MF_COMM_MAC)
		return -1;

	if(len % 8 != 0 ||
	   len < inner_len + 2 ||
	   len - (inner_len + 2) >= 8)
		return -1;

	int ret;
	ret = _mf_des_operate(sess->skey, data, len, 1);
	if(ret != 0)
		return ret;

	uint16_t crc;
	_mf_crc16(data, inner_len + 2, (uint8_t*)&crc);
	if(crc != 0)
		return -2;

	return 0;
}

int _mf_crypto_write(mf_session *sess, mf_comm_settings_t cs, uint8_t *data, size_t inner_len, size_t len) {
	if(cs == MF_COMM_PLAIN)
		return 0;

	//MACing is not supported at present
	if(cs == MF_COMM_MAC)
		return -1;

	if(len % 8 != 0 ||
	   len < inner_len + 2 ||
	   len - (inner_len + 2) >= 8)
		return -1;

	_mf_crc16(data, inner_len, data+inner_len);
	memset(data+inner_len+2, 0, len - (inner_len + 2));

	int ret;
	ret = _mf_des_operate(sess->skey, data, len, 0);
	if(ret != 0)
		return ret;

	return 0;
}
