#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "libmf.h"
#include "libmf-private.h"

/*
  GetFileIDs
  Out: 0x6F
  In:  error/fileIds[0-16]
*/
mf_err_t mf_get_file_ids(mf_interface *intf, mf_file_id **out, size_t *out_size) {
	mf_err_t ret = mf_call(intf, 0x6F, NULL, 0, out, out_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(ret != 0x00) {
		free(out);
		return ret;
	}

	return ret;
}

/*
  CommitTransaction
  Out: 0xC7
  In:  status
*/
mf_err_t mf_commit_transaction(mf_interface *intf) {
	size_t out_size;

	mf_err_t ret = mf_call(intf, 0xC7, NULL, 0, NULL, &out_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

/*
  AbortTransaction
  Out: 0xA7
  In:  status
*/
mf_err_t mf_abort_transaction(mf_interface *intf) {
	size_t out_size;

	mf_err_t ret = mf_call(intf, 0xA7, NULL, 0, NULL, &out_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_size != 0)
		return MF_ERR_PROTO;

	return ret;
}


/*
  DeleteFile
  Out: 0xDF file
  In:  status
*/
mf_err_t mf_delete_file(mf_interface *intf, mf_file_id file) {
	size_t out_size;

	mf_err_t ret = mf_call(intf, 0xDF, &file, 1, NULL, &out_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_size != 0) {
		return MF_ERR_PROTO;
	}

	return ret;
}

/*
  ClearRecordFile
  Out: 0xEB file
  In:  status
*/
mf_err_t mf_clear_record_file(mf_interface *intf, mf_file_id file) {
	size_t out_size;

	mf_err_t ret = mf_call(intf, 0xEB, &file, 1, NULL, &out_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_size != 0) {
		return MF_ERR_PROTO;
	}

	return ret;
}

/*
  GetValue
  Out: 0x6C file
  In:  error/0x00 data
*/
mf_err_t mf_get_value(mf_interface *intf, mf_session *sess, mf_file_id file, uint32_t *value) {
	uint8_t *out_str;
	size_t out_str_size;

	mf_file_settings stat;
	mf_err_t ret;
	ret = mf_get_file_settings(intf, file, &stat);
	if(ret != MF_OK)
		return ret;

	if(stat.type != MF_FILE_TYPE_VALUE)
		return MF_ERR_ILLEGAL_COMMAND_CODE;

	if(stat.comm_settings != MF_COMM_PLAIN && !sess)
		return MF_ERR_NEED_SESSION;

	ret = mf_call(intf, 0x6C, &file, 1, &out_str, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if((ret != 0x00 && out_str_size != 0) ||
	   (ret == 0x00 && out_str_size != ((stat.comm_settings == MF_COMM_PLAIN)?4:8))) {
		ret = MF_ERR_PROTO;
		goto out;
	}

	if(ret != 0x00)
		goto out;

	int cr = _mf_crypto_read(sess, stat.comm_settings, out_str, 4, out_str_size);
	switch(cr) {
	case -1:
		ret = MF_ERR_PROTO;
		goto out;
	case -2:
		ret = MF_ERR_CRC;
		goto out;
	}

	*value = _mf_parse32(out_str);

	ret = MF_OK;
out:
	free(out_str);
	return ret;
}

/*
  Credit
  Out: 0x0C data
  In:  status
*/
mf_err_t mf_credit(mf_interface *intf, mf_session *sess, mf_file_id file, int32_t value) {
	if(value < 0)
		return MF_ERR_PARAMETER_ERROR;

	mf_file_settings stat;
	mf_err_t ret;
	ret = mf_get_file_settings(intf, file, &stat);
	if(ret != MF_OK)
		return ret;

	if(stat.comm_settings != MF_COMM_PLAIN && !sess)
		return MF_ERR_NEED_SESSION;

	uint8_t arg[9];
	size_t arg_len = 4;

	arg[0] = file;
	_mf_deparse32(&arg[1], value);

	if(stat.comm_settings != MF_COMM_PLAIN) {
		arg_len = 8;

		int cr = _mf_crypto_write(sess, stat.comm_settings, &arg[1], 4, 8);
		switch(cr) {
		case -1:
			return MF_ERR_PROTO;
		case -2:
			return MF_ERR_CRC;
		}
	}

	size_t out_str_size;
	ret = mf_call(intf, 0x0C, arg, arg_len + 1, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

/*
  Debit
  Out: 0xDC data
  In:  status
*/
mf_err_t mf_debit(mf_interface *intf, mf_session *sess, mf_file_id file, int32_t value) {
	if(value < 0)
		return MF_ERR_PARAMETER_ERROR;

	mf_file_settings stat;
	mf_err_t ret;
	ret = mf_get_file_settings(intf, file, &stat);
	if(ret != MF_OK)
		return ret;

	if(stat.comm_settings != MF_COMM_PLAIN && !sess)
		return MF_ERR_NEED_SESSION;

	uint8_t arg[9];
	size_t arg_len = 4;

	arg[0] = file;
	_mf_deparse32(&arg[1], value);

	if(stat.comm_settings != MF_COMM_PLAIN) {
		arg_len = 8;

		int cr = _mf_crypto_write(sess, stat.comm_settings, &arg[1], 4, 8);
		switch(cr) {
		case -1:
			return MF_ERR_PROTO;
		case -2:
			return MF_ERR_CRC;
		}
	}

	size_t out_str_size;
	ret = mf_call(intf, 0xDC, arg, arg_len + 1, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

/*
  LimitedCredit
  Out: 0x1C data
  In:  status
*/
mf_err_t mf_limited_credit(mf_interface *intf, mf_session *sess, mf_file_id file, int32_t value) {
	if(value < 0)
		return MF_ERR_PARAMETER_ERROR;

	mf_file_settings stat;
	mf_err_t ret;
	ret = mf_get_file_settings(intf, file, &stat);
	if(ret != MF_OK)
		return ret;

	if(stat.comm_settings != MF_COMM_PLAIN && !sess)
		return MF_ERR_NEED_SESSION;

	uint8_t arg[9];
	size_t arg_len = 4;

	arg[0] = file;
	_mf_deparse32(&arg[1], value);

	if(stat.comm_settings != MF_COMM_PLAIN) {
		arg_len = 8;

		int cr = _mf_crypto_write(sess, stat.comm_settings, &arg[1], 4, 8);
		switch(cr) {
		case -1:
			return MF_ERR_PROTO;
		case -2:
			return MF_ERR_CRC;
		}
	}

	size_t out_str_size;
	ret = mf_call(intf, 0x1C, arg, arg_len + 1, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

/*
  GetFileSettings
  Out: 0xF5 file
*/
mf_err_t mf_get_file_settings(mf_interface *intf, mf_file_id file, mf_file_settings *settings) {
	uint8_t *out_str;
	size_t out_str_size;

	mf_err_t ret = mf_call(intf, 0xF5, &file, 1, &out_str, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if((ret != 0x00 && out_str_size != 0) ||
	   (ret == 0x00 && out_str_size < 4)) {
		ret = MF_ERR_PROTO;
		goto out;
	}
	if(ret != 0x00)
		goto out;

	settings->type = out_str[0];
	settings->comm_settings = out_str[1];
	settings->access = _mf_parse16(&out_str[2]);

	switch(settings->type) {
	case MF_FILE_TYPE_STANDARD:
	case MF_FILE_TYPE_BACKUP:
		if(out_str_size != 7) {
			ret = MF_ERR_PROTO;
			goto out;
		}

		settings->attr.standard.size = _mf_parse24(&out_str[4]);
		break;

	case MF_FILE_TYPE_VALUE:
		if(out_str_size != 17) {
			ret = MF_ERR_PROTO;
			goto out;
		}

		settings->attr.value.lower_limit = _mf_parse32(&out_str[4]);
		settings->attr.value.upper_limit = _mf_parse32(&out_str[8]);
		settings->attr.value.limited_limit = _mf_parse32(&out_str[12]);
		settings->attr.value.limited_enabled = out_str[16];
		break;

	case MF_FILE_TYPE_LINREC:
	case MF_FILE_TYPE_CYCREC:
		if(out_str_size != 13) {
			ret = MF_ERR_PROTO;
			goto out;
		}

		settings->attr.record.record_size = _mf_parse32(&out_str[4]);
		settings->attr.record.max_records = _mf_parse32(&out_str[7]);
		settings->attr.record.cur_records = _mf_parse32(&out_str[10]);
		break;

	default:
		ret = MF_ERR_PROTO;
		goto out;
	}

	ret = MF_OK;
out:
	free(out_str);
	return ret;
}

/*
  CreateStdDataFile
  Out: 0xCD fileNo commSettings access size
  In:  status
*/
mf_err_t mf_create_std_data_file(mf_interface *intf, mf_file_id file, mf_comm_settings_t cs, mf_access_t access, uint32_t size) {
	size_t out_str_size;

	if(size > 0xffffff)
		return MF_ERR_PARAMETER_ERROR;

	uint8_t arg[7];
	arg[0] = file;
	arg[1] = cs;
	_mf_deparse16(&arg[2], access);
	_mf_deparse24(&arg[4], size);

	mf_err_t ret = mf_call(intf, 0xCD, arg, 7, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

/*
  CreateBackupDataFile
  Out: 0xCB fileNo commSettings access size
  In:  status
*/
mf_err_t mf_create_backup_data_file(mf_interface *intf, mf_file_id file, mf_comm_settings_t cs, mf_access_t access, uint32_t size) {
	size_t out_str_size;

	if(size > 0xffffff)
		return MF_ERR_PARAMETER_ERROR;

	uint8_t arg[7];
	arg[0] = file;
	arg[1] = cs;
	_mf_deparse16(&arg[2], access);
	_mf_deparse24(&arg[4], size);

	mf_err_t ret = mf_call(intf, 0xCB, arg, 7, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

/*
  CreateLinearRecordFile
  Out: 0xC1 fileNo commSettings access recordSize maxRecords
  In:  status
*/
mf_err_t mf_create_linear_record_file(mf_interface *intf, mf_file_id file, mf_comm_settings_t cs, mf_access_t access,
                                      uint32_t record_size, uint32_t max_records) {
	size_t out_str_size;

	if(record_size == 0 || record_size > 0xffffff)
		return MF_ERR_PARAMETER_ERROR;

	if(max_records == 0 || max_records > 0xffffff)
		return MF_ERR_PARAMETER_ERROR;

	uint8_t arg[10];
	arg[0] = file;
	arg[1] = cs;
	_mf_deparse16(&arg[2], access);
	_mf_deparse24(&arg[4], record_size);
	_mf_deparse24(&arg[7], max_records);

	mf_err_t ret = mf_call(intf, 0xC1, arg, 10, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

/*
  CreateCyclicRecordFile
  Out: 0xC0 fileNo commSettings access recordSize maxRecords
  In:  status
*/
mf_err_t mf_create_cyclic_record_file(mf_interface *intf, mf_file_id file, mf_comm_settings_t cs, mf_access_t access,
                                      uint32_t record_size, uint32_t max_records) {
	size_t out_str_size;

	if(record_size == 0 || record_size > 0xffffff)
		return MF_ERR_PARAMETER_ERROR;

	if(max_records == 0 || max_records > 0xffffff)
		return MF_ERR_PARAMETER_ERROR;

	uint8_t arg[10];
	arg[0] = file;
	arg[1] = cs;
	_mf_deparse16(&arg[2], access);
	_mf_deparse24(&arg[4], record_size);
	_mf_deparse24(&arg[7], max_records);

	mf_err_t ret = mf_call(intf, 0xC0, arg, 10, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

/*
  CreateValueFile
  Out: 0xCC fileNo commSettings access lowerLimit upperLimit value limitedCreditEnabled
  In:  status
*/
mf_err_t mf_create_value_file(mf_interface *intf, mf_file_id file, mf_comm_settings_t cs, mf_access_t access,
                              int32_t lower_limit, int32_t upper_limit, int32_t value, uint8_t limited_credit) {
	size_t out_str_size;

	if(lower_limit > upper_limit)
		return MF_ERR_PARAMETER_ERROR;

	uint8_t arg[17];
	arg[0] = file;
	arg[1] = cs;
	_mf_deparse16(&arg[2], access);
	_mf_deparse32(&arg[4], lower_limit);
	_mf_deparse32(&arg[8], upper_limit);
	_mf_deparse32(&arg[12], value);
	arg[16] = limited_credit;


	mf_err_t ret = mf_call(intf, 0xCC, arg, 17, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

/*
  ChangeFileSettings
  Out: 0x5F fileNo crypt(commSettings access)
  In:  status
*/
mf_err_t mf_change_file_settings(mf_interface *intf, mf_session *sess, mf_file_id file, mf_comm_settings_t cs, mf_access_t access) {
	size_t out_str_size;

	mf_file_settings stat;
	mf_err_t ret;
	ret = mf_get_file_settings(intf, file, &stat);
	if(ret != MF_OK)
		return ret;

	if(MF_ACCESS_GET_CHANGE(stat.access) != 0xE && !sess)
		return MF_ERR_NEED_SESSION;

	uint8_t arg[9];
	size_t arg_len = 3;

	arg[0] = file;
	arg[1] = cs;
	_mf_deparse16(&arg[2], access);

	if(MF_ACCESS_GET_CHANGE(stat.access) != 0xE) {
		arg_len = 8;

		int cr = _mf_crypto_write(sess, MF_COMM_CRYPT, &arg[1], 3, 8);
		switch(cr) {
		case -1:
			return MF_ERR_PROTO;
		case -2:
			return MF_ERR_CRC;
		}
	}

	ret = mf_call(intf, 0x5F, arg, arg_len, NULL, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		return ret;

	if(out_str_size != 0)
		return MF_ERR_PROTO;

	return ret;
}

/*
  ReadData
  Out: 0xBD fileNo offset length
  In: error/status data
*/
mf_err_t mf_read_file(mf_interface *intf, mf_session *sess, mf_file_id file, uint32_t offset, uint32_t length, uint8_t **out, size_t *out_size) {
	mf_file_settings stat;
	mf_err_t ret;
	ret = mf_get_file_settings(intf, file, &stat);
	if(ret != MF_OK)
		return ret;

	if(stat.comm_settings != MF_COMM_PLAIN && !sess)
		return MF_ERR_NEED_SESSION;

	if(stat.type != MF_FILE_TYPE_STANDARD && stat.type != MF_FILE_TYPE_BACKUP)
		return MF_ERR_ILLEGAL_COMMAND_CODE;

	if(offset + length > stat.attr.standard.size ||
	   (length == 0 && offset >= stat.attr.standard.size))
		return MF_ERR_BOUNDARY_ERROR;

	uint8_t arg[7];
	arg[0] = file;
	_mf_deparse24(&arg[1], offset);
	_mf_deparse24(&arg[4], offset);

	size_t data_length, expected_length;
	if(length > 0)
		data_length = length;
	else //read the whole file
		data_length = stat.attr.standard.size - offset;

	if(stat.comm_settings != MF_COMM_PLAIN) // round up to multiples of 8 if padding is needed
		expected_length = (data_length + 7) & -8;
	else
		expected_length = data_length;

	*out = _mf_xmalloc(expected_length);

	uint8_t *out_str;
	size_t out_str_size;
	ret = mf_call(intf, 0xBD, arg, 7, &out_str, &out_str_size);
	if(ret == MF_ERR_TRANSFER_FAILED)
		goto out_err;

	size_t read_length = 0;
	while(1) {
		if((!(ret == 0x00 || ret == 0xAF) && out_str_size != 0) ||
		   ((ret == 0x00 || ret == 0xAF) &&
		    (out_str_size < 1 || out_str_size > 59 || out_str_size > expected_length - read_length))) {
			ret = MF_ERR_PROTO;

			goto out_err;
		}

		if(ret != 0x00 && ret != 0xAF)
			goto out_err;

		memcpy(*out + read_length, out_str, out_str_size);

		read_length += out_str_size;
		assert(read_length <= expected_length);

		if((read_length == expected_length && ret == 0xAF) ||
		   (read_length != expected_length && ret == 0x00)) {
			ret = MF_ERR_PROTO;

			goto out_err;
		}

		if(ret == 0x00)
			break;

		free(out_str); out_str = NULL;
		ret = mf_call(intf, 0xAF, NULL, 0, &out_str, &out_str_size);
		if(ret == MF_ERR_TRANSFER_FAILED)
			goto out_err;
	}

	int cr = _mf_crypto_read(sess, stat.comm_settings, *out, data_length, expected_length);
	switch(cr) {
	case -1:
		ret = MF_ERR_PROTO;
		goto out_err;
	case -2:
		ret = MF_ERR_CRC;
		goto out_err;
	}

	if(out_size)
		*out_size = data_length;

	ret = MF_OK;
	goto out;

 out_err:
	free(*out);
 out:
	free(out_str);
	return ret;
}
