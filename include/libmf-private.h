#ifndef __LIBMF_PRIVATE_H_
#define __LIBMF_PRIVATE_H_

struct _mf_interface {
	void *tr_data;
	// may use a statically allocated buffer for out
	ssize_t (*transceive)(void*, uint8_t *data, size_t dlen, uint8_t **out);
};

uint16_t _mf_parse16(uint8_t *p);
uint32_t _mf_parse24(uint8_t *p);
uint32_t _mf_parse32(uint8_t *p);

void _mf_deparse16(uint8_t *p, uint16_t d);
void _mf_deparse24(uint8_t *p, uint32_t d);
void _mf_deparse32(uint8_t *p, uint32_t d);

void _mf_crc16(uint8_t *data, size_t len, uint8_t *out);
void _mf_get_random(uint8_t *out, size_t len);
int _mf_des_operate(mf_key_t key, uint8_t *in, size_t len, int mode);
int _mf_crypto_read(mf_session *sess, mf_comm_settings_t cs, uint8_t *data, size_t inner_len, size_t len);
int _mf_crypto_write(mf_session *sess, mf_comm_settings_t cs, uint8_t *data, size_t inner_len, size_t len);
int _mf_key_is_des(mf_key_t key);
void _mf_do_xor(uint8_t *d, uint8_t *s, size_t n);
void *_mf_xmalloc(size_t size);

#endif
