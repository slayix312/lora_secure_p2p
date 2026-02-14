/**
 * @file aes_ccm.c
 * @brief AES-128-CCM authenticated encryption implementation
 */

#include "aes_ccm.h"

LOG_MODULE_REGISTER(aes_ccm, LOG_LEVEL_CRYPTO);

void crypto_context_init(struct crypto_context *ctx, uint16_t device_id)
{
	psa_status_t status;

	if (ctx == NULL) {
		return;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->local_device_id = device_id;
	ctx->local_msg_counter = 0;
	ctx->session_key_handle = 0;
	ctx->session_key_valid = false;
	status = psa_generate_random(ctx->nonce_boot_salt, sizeof(ctx->nonce_boot_salt));
	if (status != PSA_SUCCESS) {
		uint32_t fallback = k_cycle_get_32() ^ k_uptime_get_32() ^ device_id;
		memcpy(ctx->nonce_boot_salt, &fallback, sizeof(fallback));
		ctx->nonce_boot_salt[4] = (uint8_t)(device_id & 0xFF);
		ctx->nonce_boot_salt[5] = (uint8_t)(device_id >> 8);
		LOG_WRN("psa_generate_random() failed for nonce salt: %d", status);
	}

	LOG_DBG("Crypto context initialized (device_id=0x%04X)", device_id);
}

int crypto_set_session_key(struct crypto_context *ctx, psa_key_id_t key_handle)
{
	if (ctx == NULL) {
		LOG_ERR("Invalid context");
		return APP_ERR_INVALID_PARAM;
	}

	ctx->session_key_handle = key_handle;
	ctx->session_key_valid = (key_handle != 0);

	LOG_INF("Session key set (handle=%u)", key_handle);
	return APP_OK;
}

uint32_t crypto_get_message_counter(const struct crypto_context *ctx)
{
	if (ctx == NULL) {
		return 0;
	}
	return ctx->local_msg_counter;
}

bool crypto_counter_needs_rollover_warning(const struct crypto_context *ctx)
{
	if (ctx == NULL) {
		return false;
	}
	return (ctx->local_msg_counter > (UINT32_MAX - COUNTER_ROLLOVER_WARNING_THRESHOLD));
}

void crypto_construct_nonce(const struct crypto_context *ctx,
                            uint32_t msg_counter,
                            uint8_t *nonce)
{
	if (ctx == NULL || nonce == NULL) {
		return;
	}

	memset(nonce, 0, AES_CCM_NONCE_SIZE);

	/* Bytes 0-3: Message counter (little-endian) */
	memcpy(nonce, &msg_counter, sizeof(uint32_t));

	/* Bytes 4-5: Device ID (little-endian) */
	memcpy(nonce + 4, &ctx->local_device_id, sizeof(uint16_t));

	/* Bytes 6-11: Per-boot random salt */
	memcpy(nonce + 6, ctx->nonce_boot_salt, sizeof(ctx->nonce_boot_salt));
}

int crypto_aes_ccm_encrypt(struct crypto_context *ctx,
                           const uint8_t *nonce,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *ciphertext, size_t ciphertext_size,
                           size_t *ciphertext_len,
                           uint32_t *timing_us)
{
	psa_status_t status;
	uint32_t start_cycles, elapsed_cycles;

	/* Validate parameters */
	if (ctx == NULL || nonce == NULL || plaintext == NULL ||
	    ciphertext == NULL || ciphertext_len == NULL) {
		LOG_ERR("Invalid parameters");
		return APP_ERR_INVALID_PARAM;
	}

	if (!ctx->session_key_valid) {
		LOG_ERR("Session key not set");
		return APP_ERR_NOT_READY;
	}

	if (ciphertext_size < (plaintext_len + AES_CCM_TAG_SIZE)) {
		LOG_ERR("Ciphertext buffer too small");
		return APP_ERR_INVALID_PARAM;
	}

	/* AAD is optional */
	if (aad_len > 0 && aad == NULL) {
		LOG_ERR("AAD length specified but AAD is NULL");
		return APP_ERR_INVALID_PARAM;
	}

	/* Timing measurement for performance tracking */
	start_cycles = k_cycle_get_32();

	/* Encrypt with AES-CCM */
	status = psa_aead_encrypt(
		ctx->session_key_handle,
		PSA_ALG_CCM,
		nonce, AES_CCM_NONCE_SIZE,
		aad, aad_len,  /* AAD (can be NULL/0 if no AAD) */
		plaintext, plaintext_len,
		ciphertext, ciphertext_size,
		ciphertext_len
	);

	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_aead_encrypt() failed: %d", status);
		return APP_ERR_CRYPTO_ENCRYPT;
	}

	/* Update performance metrics */
	elapsed_cycles = k_cycle_get_32() - start_cycles;
	uint32_t encrypt_time_us = (uint32_t)k_cyc_to_us_floor64(elapsed_cycles);

	/* Return timing if caller wants it */
	if (timing_us != NULL) {
		*timing_us = encrypt_time_us;
	}

	LOG_DBG("Encryption successful (%u bytes -> %u bytes, %u us)",
	        plaintext_len, *ciphertext_len, encrypt_time_us);

	return APP_OK;
}

int crypto_aes_ccm_decrypt(struct crypto_context *ctx,
                           const uint8_t *nonce,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           uint8_t *plaintext, size_t plaintext_size,
                           size_t *plaintext_len,
                           uint32_t *timing_us)
{
	psa_status_t status;
	uint32_t start_cycles, elapsed_cycles;

	/* Validate parameters */
	if (ctx == NULL || nonce == NULL || ciphertext == NULL ||
	    plaintext == NULL || plaintext_len == NULL) {
		LOG_ERR("Invalid parameters");
		return APP_ERR_INVALID_PARAM;
	}

	if (!ctx->session_key_valid) {
		LOG_ERR("Session key not set");
		return APP_ERR_NOT_READY;
	}

	if (ciphertext_len < AES_CCM_TAG_SIZE) {
		LOG_ERR("Ciphertext too short (must include auth tag)");
		return APP_ERR_INVALID_PARAM;
	}

	size_t expected_plaintext_len = ciphertext_len - AES_CCM_TAG_SIZE;
	if (plaintext_size < expected_plaintext_len) {
		LOG_ERR("Plaintext buffer too small");
		return APP_ERR_INVALID_PARAM;
	}

	/* AAD is optional */
	if (aad_len > 0 && aad == NULL) {
		LOG_ERR("AAD length specified but AAD is NULL");
		return APP_ERR_INVALID_PARAM;
	}

	/* Timing measurement for performance tracking */
	start_cycles = k_cycle_get_32();

	/* Decrypt and authenticate with AES-CCM */
	status = psa_aead_decrypt(
		ctx->session_key_handle,
		PSA_ALG_CCM,
		nonce, AES_CCM_NONCE_SIZE,
		aad, aad_len,  /* AAD (can be NULL/0 if no AAD) */
		ciphertext, ciphertext_len,
		plaintext, plaintext_size,
		plaintext_len
	);

	if (status != PSA_SUCCESS) {
		if (status == PSA_ERROR_INVALID_SIGNATURE) {
			LOG_WRN("Authentication failed! Message tampered or wrong key.");
			return APP_ERR_CRYPTO_AUTH_FAILED;
		} else {
			LOG_ERR("psa_aead_decrypt() failed: %d", status);
			return APP_ERR_CRYPTO_DECRYPT;
		}
	}

	/* Update performance metrics */
	elapsed_cycles = k_cycle_get_32() - start_cycles;
	uint32_t decrypt_time_us = (uint32_t)k_cyc_to_us_floor64(elapsed_cycles);

	/* Return timing if caller wants it */
	if (timing_us != NULL) {
		*timing_us = decrypt_time_us;
	}

	LOG_DBG("Decryption successful (%u bytes -> %u bytes, %u us)",
	        ciphertext_len, *plaintext_len, decrypt_time_us);

	return APP_OK;
}
