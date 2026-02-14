/**
 * @file aes_ccm.h
 * @brief AES-128-CCM authenticated encryption
 *
 * This module provides AES-CCM authenticated encryption/decryption
 * using the CRACEN hardware accelerator on nRF54L15.
 *
 * AES-CCM (Counter with CBC-MAC) provides:
 * - Confidentiality (encryption)
 * - Integrity (authentication tag)
 * - Replay protection (via nonce)
 */

#ifndef AES_CCM_H
#define AES_CCM_H

#include "../app_config.h"
#include <string.h>

/**
 * @brief Crypto context structure
 *
 * Manages the crypto state including session key and message counters
 */
struct crypto_context {
	psa_key_id_t session_key_handle;  /**< PSA key handle for AES session key */
	uint32_t local_msg_counter;       /**< Local message counter (monotonic) */
	uint16_t local_device_id;         /**< Local device ID */
	uint8_t nonce_boot_salt[6];       /**< Per-boot random nonce salt */
	bool session_key_valid;           /**< True if session key is loaded */
};

/**
 * @brief Initialize crypto context
 *
 * @param ctx Pointer to crypto context structure
 * @param device_id Local device ID
 */
void crypto_context_init(struct crypto_context *ctx, uint16_t device_id);

/**
 * @brief Set session key for encryption/decryption
 *
 * @param ctx Pointer to crypto context
 * @param key_handle PSA key handle for the session key
 * @return APP_OK on success
 * @return APP_ERR_INVALID_PARAM if context is NULL
 */
int crypto_set_session_key(struct crypto_context *ctx, psa_key_id_t key_handle);

/**
 * @brief Get current message counter value
 *
 * @param ctx Pointer to crypto context
 * @return Current message counter
 */
uint32_t crypto_get_message_counter(const struct crypto_context *ctx);

/**
 * @brief Check if message counter is approaching rollover
 *
 * @param ctx Pointer to crypto context
 * @return true if counter is within warning threshold of UINT32_MAX
 * @return false if counter has sufficient remaining values
 */
bool crypto_counter_needs_rollover_warning(const struct crypto_context *ctx);

/**
 * @brief Construct a unique nonce for AES-CCM encryption
 *
 * The nonce is constructed from:
 * - Message counter (4 bytes) - ensures uniqueness
 * - Device ID (2 bytes) - adds device identity
 * - Per-boot random salt (6 bytes) - avoids deterministic reboot reuse
 *
 * Security: As long as msg_counter is never reused, nonces are unique.
 *
 * @param ctx Pointer to crypto context
 * @param msg_counter Message counter value
 * @param nonce Output buffer (must be AES_CCM_NONCE_SIZE bytes)
 */
void crypto_construct_nonce(const struct crypto_context *ctx,
                            uint32_t msg_counter,
                            uint8_t *nonce);

/**
 * @brief Encrypt data using AES-128-CCM
 *
 * Encrypts the plaintext using AES-CCM authenticated encryption.
 * Generates authentication tag for integrity protection.
 *
 * Process:
 * 1. Use provided nonce (must be unique)
 * 2. Authenticate Additional Authenticated Data (AAD) if provided
 * 3. Encrypt plaintext with AES-CCM
 * 4. Generate and append authentication tag
 *
 * @param ctx Pointer to crypto context
 * @param nonce Nonce for this encryption (must be AES_CCM_NONCE_SIZE bytes)
 * @param aad Additional authenticated data (can be NULL if aad_len is 0)
 * @param aad_len Length of AAD in bytes
 * @param plaintext Plaintext data to encrypt
 * @param plaintext_len Length of plaintext in bytes
 * @param ciphertext Output buffer for ciphertext + tag
 * @param ciphertext_size Size of ciphertext buffer (must be >= plaintext_len + AES_CCM_TAG_SIZE)
 * @param ciphertext_len Output: actual length of ciphertext + tag
 * @param timing_us Output: encryption time in microseconds (can be NULL)
 *
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO_ENCRYPT on encryption failure
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 * @return APP_ERR_NOT_READY if session key is not set
 */
int crypto_aes_ccm_encrypt(struct crypto_context *ctx,
                           const uint8_t *nonce,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *ciphertext, size_t ciphertext_size,
                           size_t *ciphertext_len,
                           uint32_t *timing_us);

/**
 * @brief Decrypt and authenticate data using AES-128-CCM
 *
 * Decrypts the ciphertext and verifies the authentication tag.
 * If authentication fails, the message is rejected (prevents tampering).
 *
 * Process:
 * 1. Use provided nonce
 * 2. Authenticate Additional Authenticated Data (AAD) if provided
 * 3. Decrypt ciphertext and verify auth tag with AES-CCM
 * 4. Reject if authentication fails
 *
 * @param ctx Pointer to crypto context
 * @param nonce Nonce used during encryption (must be AES_CCM_NONCE_SIZE bytes)
 * @param aad Additional authenticated data (can be NULL if aad_len is 0)
 * @param aad_len Length of AAD in bytes
 * @param ciphertext Ciphertext data with appended tag
 * @param ciphertext_len Length of ciphertext + tag in bytes
 * @param plaintext Output buffer for decrypted plaintext
 * @param plaintext_size Size of plaintext buffer (must be >= ciphertext_len - AES_CCM_TAG_SIZE)
 * @param plaintext_len Output: actual length of plaintext
 * @param timing_us Output: decryption time in microseconds (can be NULL)
 *
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO_AUTH_FAILED if authentication fails
 * @return APP_ERR_CRYPTO_DECRYPT on other decryption failures
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 * @return APP_ERR_NOT_READY if session key is not set
 */
int crypto_aes_ccm_decrypt(struct crypto_context *ctx,
                           const uint8_t *nonce,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           uint8_t *plaintext, size_t plaintext_size,
                           size_t *plaintext_len,
                           uint32_t *timing_us);

#endif /* AES_CCM_H */
