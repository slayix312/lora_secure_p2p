/**
 * @file crypto_init.c
 * @brief PSA Crypto subsystem initialization implementation
 */

#include "crypto_init.h"

LOG_MODULE_REGISTER(crypto_init, LOG_LEVEL_CRYPTO);

/* Track initialization state */
static bool s_crypto_initialized = false;

int crypto_init(void)
{
	psa_status_t status;

	/* Idempotent - return success if already initialized */
	if (s_crypto_initialized) {
		LOG_DBG("PSA Crypto already initialized");
		return APP_OK;
	}

	LOG_INF("Initializing PSA Crypto subsystem...");

	/* Initialize PSA Crypto API */
	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_crypto_init() failed: %d", status);
		return APP_ERR_CRYPTO_INIT;
	}

	s_crypto_initialized = true;

	LOG_INF("PSA Crypto initialized successfully");
	LOG_INF("  CRACEN hardware accelerator active");
	LOG_INF("  Supported algorithms:");
	LOG_INF("    - AES-128-CCM (authenticated encryption)");
	LOG_INF("    - X25519 ECDH (key exchange)");
	LOG_INF("    - HKDF-SHA256 (key derivation)");
	LOG_INF("    - HMAC-SHA256 (authentication)");

	return APP_OK;
}

bool crypto_is_initialized(void)
{
	return s_crypto_initialized;
}

int crypto_cleanup(void)
{
	if (!s_crypto_initialized) {
		LOG_DBG("PSA Crypto not initialized, nothing to cleanup");
		return APP_OK;
	}

	LOG_INF("Cleaning up PSA Crypto subsystem...");

	/* Note: psa_crypto_init() doesn't have a corresponding cleanup function
	 * in the PSA Crypto API. Keys are destroyed individually using
	 * psa_destroy_key() in their respective modules.
	 */

	s_crypto_initialized = false;

	LOG_INF("PSA Crypto cleanup complete");
	return APP_OK;
}
