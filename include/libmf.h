#ifndef __LIBMF_H_
#define __LIBMF_H_

#include <stdint.h>
#include <unistd.h>

#define MF_ERR_PROTO 0x1001
#define MF_ERR_CARD_AUTH_FAIL 0x1002
#define MF_ERR_TRANSFER_FAILED 0x1003
#define MF_ERR_NEED_SESSION 0x1004
#define MF_ERR_CRC 0x1005
#define MF_OK 0x00
#define MF_ERR_NO_CHANGES 0x0C
#define MF_ERR_OUT_OF_EEPROM_ERROR 0x0E
#define MF_ERR_ILLEGAL_COMMAND_CODE 0x1C
#define MF_ERR_INTEGRITY_ERROR 0x1E
#define MF_ERR_NO_SUCH_KEY 0x40
#define MF_ERR_LENGTH_ERROR 0x7E
#define MF_ERR_PERMISSION_DENIED 0x9D
#define MF_ERR_PARAMETER_ERROR 0x9E
#define MF_ERR_APPLICATION_NOT_FOUND 0xA0
#define MF_ERR_APPL_INTEGRITY_ERROR 0xA1
#define MF_ERR_AUTHENTICATION_ERROR 0xAE
#define MF_ERR_ADDITIONAL_FRAME 0xAF
#define MF_ERR_BOUNDARY_ERROR 0xBE
#define MF_ERR_PICC_INTEGRITY_ERROR 0xC1
#define MF_ERR_COMMAND_ABORTED 0xCA
#define MF_ERR_PICC_DISABLED_ERROR 0xCD
#define MF_ERR_COUNT_ERROR 0xCE
#define MF_ERR_DUPLICATE_ERROR 0xDE
#define MF_ERR_EEPROM_ERROR 0xEE
#define MF_ERR_FILE_NOT_FOUND 0xF0
#define MF_ERR_FILE_INTEGRITY_ERROR 0xF1

typedef int mf_err_t;
const char *mf_error_str(mf_err_t);

typedef struct _mf_interface mf_interface;

mf_interface *mf_interface_new(ssize_t (*transcieve)(void*, uint8_t *data, size_t dlen, uint8_t **out), void *data);
void *mf_interface_free(mf_interface *intf);

typedef struct {
	uint8_t hw_vendor, hw_type, hw_subtype, hw_major_version,
		hw_minor_version, hw_storage_size, hw_protocol;
	uint8_t sw_vendor, sw_type, sw_subtype, sw_major_version,
		sw_minor_version, sw_storage_size, sw_protocol;

	uint8_t uid[7];
	uint8_t batch[5];
	uint8_t prod_cw, prod_year;
} mf_version;

mf_err_t mf_get_version(mf_interface *intf, mf_version *version);
mf_err_t mf_format_picc(mf_interface *intf);

typedef uint32_t mf_aid_t;
typedef uint8_t mf_key_settings_t;
typedef uint8_t mf_key_id_t;

#define MF_KEY_ID_ALL 0xE
#define MF_KEY_ID_NONE 0xF

#define MF_PERM_CHANGE_CFG 0x8
#define MF_PERM_CREATE 0x4
#define MF_PERM_LIST 0x2
#define MF_PERM_CHANGE_KEY 0x1

mf_key_settings_t mf_build_key_settings(mf_key_id_t change_key_id, uint8_t flags);

mf_err_t mf_create_application(mf_interface *intf, mf_aid_t aid, mf_key_settings_t key_settings, uint8_t key_num);
mf_err_t mf_select_application(mf_interface *intf, mf_aid_t aid);
mf_err_t mf_delete_application(mf_interface *intf, mf_aid_t aid);
mf_err_t mf_get_application_ids(mf_interface *intf, mf_aid_t **aids, size_t *aids_num);

typedef uint8_t mf_key_t[16];
void mf_key_set(mf_key_t key, uint8_t data[16]);
void mf_key_set_version(mf_key_t key, uint8_t version);
int mf_key_parse(mf_key_t key, const char *data);

typedef struct {
	mf_key_t skey;
	mf_key_id_t akey_id;
} mf_session;

mf_err_t mf_authenticate(mf_interface *intf, mf_key_id_t key_id, mf_key_t key, mf_session *session);
void mf_erase_session(mf_session *session);

mf_err_t mf_change_other_key(mf_interface *intf, mf_session *session, mf_key_id_t key_id, mf_key_t old_key, mf_key_t new_key);
mf_err_t mf_change_current_key(mf_interface *intf, mf_session *session, mf_key_t new_key);

mf_err_t mf_get_key_settings(mf_interface *intf, mf_key_settings_t *key_settings, uint8_t *max_key_num);
mf_err_t mf_change_key_settings(mf_interface *intf, mf_session  *session, mf_key_settings_t key_settings);

mf_err_t mf_call(mf_interface *intf, uint8_t cmd, uint8_t *args, size_t arg_size, uint8_t **out, size_t *out_size);

typedef uint8_t mf_file_id;
mf_err_t mf_get_file_ids(mf_interface *intf, mf_file_id **out, size_t *out_size);

mf_err_t mf_commit_transaction(mf_interface *intf);
mf_err_t mf_abort_transaction(mf_interface *intf);
mf_err_t mf_delete_file(mf_interface *intf, mf_file_id file);

#define MF_FILE_TYPE_STANDARD 0x00
#define MF_FILE_TYPE_BACKUP  0x01
#define MF_FILE_TYPE_VALUE 0x02
#define MF_FILE_TYPE_LINREC 0x03
#define MF_FILE_TYPE_CYCREC 0x04

typedef uint8_t mf_comm_settings_t;
typedef uint16_t mf_access_t;

#define MF_ACCESS_GET_CHANGE(x) ((x) & 0xF)
#define MF_ACCESS_GET_RW(x) (((x) >> 4) & 0xF)
#define MF_ACCESS_GET_W(x) (((x) >> 8) & 0xF)
#define MF_ACCESS_GET_R(x) (((x) >> 12) & 0xF)
#define MF_ACCESS_SET_CHANGE(x, k) do { (x) = (((x) & ~0x000F) | k); } while(0)
#define MF_ACCESS_SET_RW(x, k) do { (x) = (((x) & ~0x00F0) | k<<4); } while(0)
#define MF_ACCESS_SET_W(x, k) do { (x) = (((x) & ~0x0F00) | k<<8); } while(0)
#define MF_ACCESS_SET_R(x, k) do { (x) = (((x) & ~0xF000) | k<<12); } while(0)

#define MF_COMM_PLAIN 0x00
#define MF_COMM_MAC 0x01
#define MF_COMM_CRYPT 0x03

typedef struct {
	uint8_t type;

	mf_comm_settings_t comm_settings;
	mf_access_t access;

	union {
		struct {
			uint32_t size;
		} standard;
		struct {
			int32_t lower_limit;
			int32_t upper_limit;
			int32_t limited_limit;
			uint8_t limited_enabled;
		} value;
		struct {
			uint32_t record_size;
			uint32_t max_records;
			uint32_t cur_records;
		} record;
	} attr;
} mf_file_settings;

mf_err_t mf_get_file_settings(mf_interface *intf, mf_file_id file, mf_file_settings *settings);
mf_err_t mf_get_value(mf_interface *intf, mf_session *sess, mf_file_id file, uint32_t *value);
mf_err_t mf_clear_record_file(mf_interface *intf, mf_file_id file);

mf_err_t mf_create_std_data_file(mf_interface *intf, mf_file_id file, mf_comm_settings_t cs, mf_access_t access, uint32_t size);
mf_err_t mf_create_backup_data_file(mf_interface *intf, mf_file_id file, mf_comm_settings_t cs, mf_access_t access, uint32_t size);

mf_err_t mf_create_linear_record_file(mf_interface *intf, mf_file_id file, mf_comm_settings_t cs, mf_access_t access,
                                      uint32_t record_size, uint32_t max_records);
mf_err_t mf_create_cyclic_record_file(mf_interface *intf, mf_file_id file, mf_comm_settings_t cs, mf_access_t access,
                                      uint32_t record_size, uint32_t max_records);
mf_err_t mf_create_value_file(mf_interface *intf, mf_file_id file, mf_comm_settings_t cs, mf_access_t access,
                              int32_t lower_limit, int32_t upper_limit, int32_t value, uint8_t limited_credit);

mf_err_t mf_credit(mf_interface *intf, mf_session *sess, mf_file_id file, int32_t value);
mf_err_t mf_limited_credit(mf_interface *intf, mf_session *sess, mf_file_id file, int32_t value);
mf_err_t mf_debit(mf_interface *intf, mf_session *sess, mf_file_id file, int32_t value);
mf_err_t mf_change_file_settings(mf_interface *intf, mf_session *sess, mf_file_id file, mf_comm_settings_t cs, mf_access_t access);
mf_err_t mf_read_file(mf_interface *intf, mf_session *sess, mf_file_id file, uint32_t offset, uint32_t length, uint8_t **out, size_t *out_size);

#endif
