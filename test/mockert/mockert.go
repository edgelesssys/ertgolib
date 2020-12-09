package mockert

/*
#include <openenclave/enclave.h>
#include <string.h>

oe_result_t oe_get_seal_key_by_policy_v2(
	oe_seal_policy_t seal_policy,
	uint8_t** key_buffer,
	size_t* key_buffer_size,
	uint8_t** key_info,
	size_t* key_info_size)
{
	*key_buffer = "1234567890123456";
	*key_buffer_size = 16;
	*key_info = "info";
	*key_info_size = 4;
	return OE_OK;
}

oe_result_t oe_get_seal_key_v2(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
	size_t* key_buffer_size)
{
	if (key_info_size != 4 || memcmp(key_info, "info", 4) != 0)
		return OE_FAILURE;
	*key_buffer = "1234567890123456";
	*key_buffer_size = 16;
	return OE_OK;
}

void oe_free_seal_key(uint8_t* key_buffer, uint8_t* key_info)
{
}
*/
import "C"
