/**
 * @file crypto_init.h
 * @brief PSA Crypto subsystem initialization
 *
 * This module handles the initialization of the PSA Crypto API
 * and CRACEN hardware accelerator for the nRF54L15.
 *
 * @note Must be called before any cryptographic operations
 */

#ifndef CRYPTO_INIT_H
#define CRYPTO_INIT_H

#include "../app_config.h"

/**
 * @brief Initialize PSA Crypto subsystem
 *
 * Initializes the PSA Crypto API and CRACEN hardware accelerator.
 * This function must be called once during application startup,
 * before any cryptographic operations are performed.
 *
 * Features initialized:
 * - PSA Crypto API
 * - CRACEN hardware accelerator (AES, ECC, SHA-256, HMAC)
 * - Random number generator
 *
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO_INIT if initialization fails
 *
 * @note This function is idempotent - calling it multiple times is safe
 */
int crypto_init(void);

/**
 * @brief Check if PSA Crypto is initialized
 *
 * @return true if crypto subsystem is initialized
 * @return false if crypto subsystem is not initialized
 */
bool crypto_is_initialized(void);

/**
 * @brief Cleanup cryptography resources
 *
 * Destroys all crypto keys and resets the crypto state.
 * Should be called during shutdown or before re-initialization.
 *
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO if cleanup fails
 *
 * @note After calling this, crypto_init() must be called again before
 *       performing any cryptographic operations
 */
int crypto_cleanup(void);

#endif /* CRYPTO_INIT_H */
