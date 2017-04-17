#include "libmf.h"

static struct {
	mf_err_t err;
	const char *errname;
} err_assoc[] = {
	{0x1001, "MF_ERR_PROTO"},
	{0x1002, "MF_CARD_AUTH_FAIL"},
	{0x1003, "MF_ERR_TRANSFER_FAILED"},
	{0x1004, "MF_ERR_NEED_SESSION"},
	{0x1005, "MF_ERR_CRC"},
	{0x00, "MF_OK"},
	{0x0C, "MF_ERR_NO_CHANGES"},
	{0x0E, "MF_ERR_OUT_OF_EEPROM_ERROR"},
	{0x1C, "MF_ERR_ILLEGAL_COMMAND_CODE"},
	{0x1E, "MF_ERR_INTEGRITY_ERROR"},
	{0x40, "MF_ERR_NO_SUCH_KEY"},
	{0x7E, "MF_ERR_LENGTH_ERROR"},
	{0x9D, "MF_ERR_PERMISSION_DENIED"},
	{0x9E, "MF_ERR_PARAMETER_ERROR"},
	{0xA0, "MF_ERR_APPLICATION_NOT_FOUND"},
	{0xA1, "MF_ERR_APPL_INTEGRITY_ERROR"},
	{0xAE, "MF_ERR_AUTHENTICATION_ERROR"},
	{0xAF, "MF_ERR_ADDITIONAL_FRAME"},
	{0xBE, "MF_ERR_BOUNDARY_ERROR"},
	{0xC1, "MF_ERR_PICC_INTEGRITY_ERROR"},
	{0xCA, "MF_ERR_COMMAND_ABORTED"},
	{0xCD, "MF_ERR_PICC_DISABLED_ERROR"},
	{0xCE, "MF_ERR_COUNT_ERROR"},
	{0xDE, "MF_ERR_DUPLICATE_ERROR"},
	{0xEE, "MF_ERR_EEPROM_ERROR"},
	{0xF0, "MF_ERR_FILE_NOT_FOUND"},
	{0xF1, "MF_ERR_FILE_INTEGRITY_ERROR"},
	{0x00, 0x00},
};

const char *mf_error_str(mf_err_t err) {
	for(int i = 0; err_assoc[i].errname; i++)  {
		if(err_assoc[i].err == err)
			return err_assoc[i].errname;
	}

	return "Unknown error";
}
