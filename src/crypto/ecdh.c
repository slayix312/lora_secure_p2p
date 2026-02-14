/**
 * @file ecdh.c
 * @brief X25519 ECDH key exchange implementation
 */

#include "ecdh.h"

LOG_MODULE_REGISTER(ecdh, LOG_LEVEL_CRYPTO);

/* HKDF context strings for key derivation */
static const uint8_t s_hkdf_salt[] = "LoRa P2P Salt v1";
static const uint8_t s_hkdf_info[] = "LoRa P2P Session Key";

/*
 * Use volatile writes so secret clearing is not optimized away by compiler.
 */
static void secure_zeroize(void *buf, size_t len)
{
	volatile uint8_t *p = (volatile uint8_t *)buf;

	while (len-- > 0) {
		*p++ = 0;
	}
}

void ecdh_context_init(struct ecdh_context *ctx)
{
	if (ctx == NULL) {
		return;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->keypair_generated = false;
	ctx->peer_key_received = false;
	ctx->session_key_derived = false;
#if ENABLE_PSK_AUTHENTICATION
	ctx->auth_psk_loaded = false;
#endif

	LOG_DBG("ECDH context initialized");
}

int ecdh_generate_keypair(struct ecdh_context *ctx)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	size_t pubkey_len;

	if (ctx == NULL) {
		LOG_ERR("Invalid context");
		return APP_ERR_INVALID_PARAM;
	}

	LOG_INF("Generating X25519 keypair for ECDH...");

	/* Configure key attributes for X25519 (Curve25519) */
	psa_set_key_type(&attributes,
		PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attributes, ECDH_PRIVATE_KEY_BITS);  /* Curve25519 = 255 bits */
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);

#if ENABLE_PERSISTENT_STORAGE
	/* Persistent keys in ITS/KMU */
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_id(&attributes, PSA_KEY_ID_ECDH_PRIVATE);
#else
	/* Volatile keys (lost on reboot) */
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
#endif

	/* Generate the key pair */
	status = psa_generate_key(&attributes, &ctx->private_key_handle);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_generate_key() failed: %d", status);
		psa_reset_key_attributes(&attributes);
		return APP_ERR_CRYPTO_KEY_GEN;
	}

	/* Export the public key (will be shared with peer) */
	status = psa_export_public_key(ctx->private_key_handle,
	                                ctx->local_public_key,
	                                sizeof(ctx->local_public_key),
	                                &pubkey_len);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_export_public_key() failed: %d", status);
		psa_destroy_key(ctx->private_key_handle);
		psa_reset_key_attributes(&attributes);
		return APP_ERR_CRYPTO_KEY_EXPORT;
	}

	psa_reset_key_attributes(&attributes);

	if (pubkey_len != ECDH_PUBLIC_KEY_SIZE) {
		LOG_ERR("Unexpected public key size: %u (expected %u)",
		        pubkey_len, ECDH_PUBLIC_KEY_SIZE);
		psa_destroy_key(ctx->private_key_handle);
		return APP_ERR_CRYPTO_KEY_GEN;
	}

	ctx->keypair_generated = true;

	LOG_INF("X25519 keypair generated successfully");
	LOG_INF("  Private key handle: %u", ctx->private_key_handle);
	LOG_INF("  Public key size: %u bytes", pubkey_len);
	LOG_HEXDUMP_INF(ctx->local_public_key, pubkey_len, "Public key:");

	return APP_OK;
}

int ecdh_get_public_key(const struct ecdh_context *ctx, uint8_t *public_key)
{
	if (ctx == NULL || public_key == NULL) {
		LOG_ERR("Invalid parameters");
		return APP_ERR_INVALID_PARAM;
	}

	if (!ctx->keypair_generated) {
		LOG_ERR("Keypair not generated");
		return APP_ERR_NOT_READY;
	}

	memcpy(public_key, ctx->local_public_key, ECDH_PUBLIC_KEY_SIZE);
	return APP_OK;
}

int ecdh_set_peer_public_key(struct ecdh_context *ctx, const uint8_t *peer_public_key)
{
	if (ctx == NULL || peer_public_key == NULL) {
		LOG_ERR("Invalid parameters");
		return APP_ERR_INVALID_PARAM;
	}

	memcpy(ctx->peer_public_key, peer_public_key, ECDH_PUBLIC_KEY_SIZE);
	ctx->peer_key_received = true;

	LOG_INF("Peer public key stored");
	LOG_HEXDUMP_DBG(ctx->peer_public_key, ECDH_PUBLIC_KEY_SIZE, "Peer key:");

	return APP_OK;
}

int ecdh_derive_session_key(struct ecdh_context *ctx)
{
	psa_status_t status;
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_key_attributes_t derived_key_attr = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t shared_secret[32];  /* X25519 shared secret = 32 bytes */
	size_t shared_secret_len;
	psa_key_id_t secret_key_handle = 0;

	if (ctx == NULL) {
		LOG_ERR("Invalid context");
		return APP_ERR_INVALID_PARAM;
	}

	if (!ctx->keypair_generated) {
		LOG_ERR("Keypair not generated");
		return APP_ERR_NOT_READY;
	}

	if (!ctx->peer_key_received) {
		LOG_ERR("Peer public key not set");
		return APP_ERR_NOT_READY;
	}

	LOG_INF("Deriving session key from ECDH shared secret...");

	/* Setup key derivation with HKDF-SHA256 */
	status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_key_derivation_setup() failed: %d", status);
		return APP_ERR_CRYPTO_DERIVE;
	}

	/* Input: Salt (improves security strength) */
	status = psa_key_derivation_input_bytes(&op,
		PSA_KEY_DERIVATION_INPUT_SALT,
		s_hkdf_salt, sizeof(s_hkdf_salt) - 1);  /* -1 to exclude null terminator */
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_key_derivation_input_bytes(SALT) failed: %d", status);
		psa_key_derivation_abort(&op);
		return APP_ERR_CRYPTO_DERIVE;
	}

	/* Step 1: Perform raw ECDH key agreement to compute shared secret */
	status = psa_raw_key_agreement(
		PSA_ALG_ECDH,
		ctx->private_key_handle,
		ctx->peer_public_key,
		ECDH_PUBLIC_KEY_SIZE,
		shared_secret,
		sizeof(shared_secret),
		&shared_secret_len);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_raw_key_agreement() failed: %d", status);
		psa_key_derivation_abort(&op);
		return APP_ERR_CRYPTO_DERIVE;
	}

	LOG_INF("  ECDH shared secret computed (%zu bytes)", shared_secret_len);

	/* Step 2: Import shared secret as a temporary key for HKDF */
	psa_key_attributes_t secret_key_attr = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_type(&secret_key_attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_bits(&secret_key_attr, shared_secret_len * 8);
	psa_set_key_usage_flags(&secret_key_attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&secret_key_attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	psa_set_key_lifetime(&secret_key_attr, PSA_KEY_LIFETIME_VOLATILE);

	/* Import shared secret as a key object */
	status = psa_import_key(&secret_key_attr, shared_secret, shared_secret_len,
	                        &secret_key_handle);

	/* Securely zero out shared secret immediately after import */
	secure_zeroize(shared_secret, sizeof(shared_secret));
	psa_reset_key_attributes(&secret_key_attr);

	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_import_key(shared_secret) failed: %d", status);
		psa_key_derivation_abort(&op);
		return APP_ERR_CRYPTO_DERIVE;
	}

	/* Step 3: Input the secret KEY into HKDF */
	status = psa_key_derivation_input_key(&op,
		PSA_KEY_DERIVATION_INPUT_SECRET,
		secret_key_handle);

	/* Destroy temporary secret key immediately after use */
	psa_destroy_key(secret_key_handle);

	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_key_derivation_input_key(SECRET) failed: %d", status);
		psa_key_derivation_abort(&op);
		return APP_ERR_CRYPTO_DERIVE;
	}

	/* Input: Info string (context) */
	status = psa_key_derivation_input_bytes(&op,
		PSA_KEY_DERIVATION_INPUT_INFO,
		s_hkdf_info, sizeof(s_hkdf_info) - 1);  /* -1 to exclude null terminator */
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_key_derivation_input_bytes(INFO) failed: %d", status);
		psa_key_derivation_abort(&op);
		return APP_ERR_CRYPTO_DERIVE;
	}

	/* Configure derived key attributes for AES-128-CCM */
	psa_set_key_type(&derived_key_attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&derived_key_attr, AES_KEY_SIZE_BITS);
	psa_set_key_algorithm(&derived_key_attr, PSA_ALG_CCM);
	psa_set_key_usage_flags(&derived_key_attr,
		PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);

#if ENABLE_PERSISTENT_STORAGE
	/* Persistent session key */
	psa_set_key_lifetime(&derived_key_attr, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_id(&derived_key_attr, PSA_KEY_ID_SESSION);
#else
	/* Volatile session key */
	psa_set_key_lifetime(&derived_key_attr, PSA_KEY_LIFETIME_VOLATILE);
#endif

	/* Derive the session key */
	status = psa_key_derivation_output_key(&derived_key_attr, &op,
	                                       &ctx->session_key_handle);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_key_derivation_output_key() failed: %d", status);
		psa_key_derivation_abort(&op);
		psa_reset_key_attributes(&derived_key_attr);
		return APP_ERR_CRYPTO_DERIVE;
	}

	/* Cleanup */
	psa_key_derivation_abort(&op);
	psa_reset_key_attributes(&derived_key_attr);

	ctx->session_key_derived = true;

	LOG_INF("Session key derived successfully from ECDH!");
	LOG_INF("  Session key handle: %u", ctx->session_key_handle);
	LOG_INF("  Encrypted communication enabled");

	return APP_OK;
}

int ecdh_get_session_key_handle(const struct ecdh_context *ctx, psa_key_id_t *key_handle)
{
	if (ctx == NULL || key_handle == NULL) {
		LOG_ERR("Invalid parameters");
		return APP_ERR_INVALID_PARAM;
	}

	if (!ctx->session_key_derived) {
		LOG_ERR("Session key not derived");
		return APP_ERR_NOT_READY;
	}

	*key_handle = ctx->session_key_handle;
	return APP_OK;
}

#if ENABLE_PSK_AUTHENTICATION
int ecdh_import_auth_psk(struct ecdh_context *ctx, const uint8_t *psk, size_t psk_len)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	if (ctx == NULL || psk == NULL) {
		LOG_ERR("Invalid parameters");
		return APP_ERR_INVALID_PARAM;
	}

	if (psk_len != HMAC_KEY_SIZE_BYTES) {
		LOG_ERR("Invalid PSK length: %u (expected %u)", psk_len, HMAC_KEY_SIZE_BYTES);
		return APP_ERR_INVALID_PARAM;
	}

	LOG_INF("Importing authentication PSK for HMAC...");

	/* Configure key attributes for HMAC-SHA256 */
	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attributes, HMAC_KEY_SIZE_BITS);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_usage_flags(&attributes,
		PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);

#if ENABLE_PERSISTENT_STORAGE
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_id(&attributes, PSA_KEY_ID_AUTH_PSK);
#else
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
#endif

	/* Import the authentication PSK */
	status = psa_import_key(&attributes, psk, psk_len, &ctx->auth_psk_handle);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_import_key() for auth PSK failed: %d", status);
		psa_reset_key_attributes(&attributes);
		return APP_ERR_CRYPTO_KEY_IMPORT;
	}

	psa_reset_key_attributes(&attributes);

	ctx->auth_psk_loaded = true;

	LOG_INF("Authentication PSK imported successfully (handle: %u)", ctx->auth_psk_handle);
	LOG_INF("MITM protection enabled!");

	return APP_OK;
}

int ecdh_generate_hmac(struct ecdh_context *ctx,
                       const uint8_t *data, size_t data_len,
                       uint8_t *hmac_tag)
{
	psa_status_t status;
	psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
	size_t hmac_len;

	if (ctx == NULL || data == NULL || hmac_tag == NULL) {
		LOG_ERR("Invalid parameters");
		return APP_ERR_INVALID_PARAM;
	}

	if (!ctx->auth_psk_loaded) {
		LOG_ERR("Auth PSK not loaded");
		return APP_ERR_NOT_READY;
	}

	/* Setup HMAC operation */
	status = psa_mac_sign_setup(&operation, ctx->auth_psk_handle,
	                             PSA_ALG_HMAC(PSA_ALG_SHA_256));
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_mac_sign_setup() failed: %d", status);
		return APP_ERR_CRYPTO_HMAC;
	}

	/* Update with data */
	status = psa_mac_update(&operation, data, data_len);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_mac_update() failed: %d", status);
		psa_mac_abort(&operation);
		return APP_ERR_CRYPTO_HMAC;
	}

	/* Finish and get HMAC tag */
	status = psa_mac_sign_finish(&operation, hmac_tag, HMAC_TAG_SIZE, &hmac_len);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_mac_sign_finish() failed: %d", status);
		psa_mac_abort(&operation);
		return APP_ERR_CRYPTO_HMAC;
	}

	if (hmac_len != HMAC_TAG_SIZE) {
		LOG_ERR("HMAC length mismatch: got %u, expected %u", hmac_len, HMAC_TAG_SIZE);
		return APP_ERR_CRYPTO_HMAC;
	}

	LOG_DBG("HMAC tag generated (%u bytes)", hmac_len);
	return APP_OK;
}

int ecdh_verify_hmac(struct ecdh_context *ctx,
                     const uint8_t *data, size_t data_len,
                     const uint8_t *hmac_tag)
{
	psa_status_t status;
	psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;

	if (ctx == NULL || data == NULL || hmac_tag == NULL) {
		LOG_ERR("Invalid parameters");
		return APP_ERR_INVALID_PARAM;
	}

	if (!ctx->auth_psk_loaded) {
		LOG_ERR("Auth PSK not loaded");
		return APP_ERR_NOT_READY;
	}

	/* Setup HMAC verification */
	status = psa_mac_verify_setup(&operation, ctx->auth_psk_handle,
	                               PSA_ALG_HMAC(PSA_ALG_SHA_256));
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_mac_verify_setup() failed: %d", status);
		return APP_ERR_CRYPTO_HMAC;
	}

	/* Update with data */
	status = psa_mac_update(&operation, data, data_len);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_mac_update() failed: %d", status);
		psa_mac_abort(&operation);
		return APP_ERR_CRYPTO_HMAC;
	}

	/* Verify HMAC tag */
	status = psa_mac_verify_finish(&operation, hmac_tag, HMAC_TAG_SIZE);
	if (status != PSA_SUCCESS) {
		if (status == PSA_ERROR_INVALID_SIGNATURE) {
			LOG_ERR("HMAC VERIFICATION FAILED!");
			LOG_ERR("  This is likely a MITM attack!");
			LOG_ERR("  The sender doesn't know the PSK.");
			return APP_ERR_CRYPTO_AUTH_FAILED;
		} else {
			LOG_ERR("psa_mac_verify_finish() failed: %d", status);
			psa_mac_abort(&operation);
			return APP_ERR_CRYPTO_HMAC;
		}
	}

	LOG_DBG("HMAC verified - sender authenticated!");
	return APP_OK;
}
#endif /* ENABLE_PSK_AUTHENTICATION */

int ecdh_cleanup_exchange_material(struct ecdh_context *ctx)
{
	psa_status_t status;
	int ret = APP_OK;

	if (ctx == NULL) {
		return APP_OK;
	}

	if (ctx->private_key_handle != 0) {
		status = psa_destroy_key(ctx->private_key_handle);
		if (status != PSA_SUCCESS) {
			LOG_WRN("Failed to destroy ECDH private key: %d", status);
			ret = APP_ERR_CRYPTO;
		}
		ctx->private_key_handle = 0;
	}

#if ENABLE_PSK_AUTHENTICATION
	if (ctx->auth_psk_handle != 0) {
		status = psa_destroy_key(ctx->auth_psk_handle);
		if (status != PSA_SUCCESS) {
			LOG_WRN("Failed to destroy authentication PSK: %d", status);
			ret = APP_ERR_CRYPTO;
		}
		ctx->auth_psk_handle = 0;
		ctx->auth_psk_loaded = false;
	}
#endif

	secure_zeroize(ctx->local_public_key, sizeof(ctx->local_public_key));
	secure_zeroize(ctx->peer_public_key, sizeof(ctx->peer_public_key));
	ctx->keypair_generated = false;
	ctx->peer_key_received = false;

	return ret;
}

int ecdh_cleanup(struct ecdh_context *ctx)
{
	psa_status_t status;
	int ret = APP_OK;

	if (ctx == NULL) {
		return APP_OK;
	}

	LOG_INF("Cleaning up ECDH context...");

	/* Destroy private key */
	if (ctx->private_key_handle != 0) {
		LOG_DBG("Destroying ECDH private key...");
		status = psa_destroy_key(ctx->private_key_handle);
		if (status != PSA_SUCCESS) {
			LOG_WRN("Failed to destroy private key: %d", status);
			ret = APP_ERR_CRYPTO;
		}
	}

	/* Destroy session key */
	if (ctx->session_key_handle != 0) {
		LOG_DBG("Destroying session key...");
		status = psa_destroy_key(ctx->session_key_handle);
		if (status != PSA_SUCCESS) {
			LOG_WRN("Failed to destroy session key: %d", status);
			ret = APP_ERR_CRYPTO;
		}
	}

#if ENABLE_PSK_AUTHENTICATION
	/* Destroy auth PSK */
	if (ctx->auth_psk_handle != 0) {
		LOG_DBG("Destroying authentication PSK...");
		status = psa_destroy_key(ctx->auth_psk_handle);
		if (status != PSA_SUCCESS) {
			LOG_WRN("Failed to destroy auth PSK: %d", status);
			ret = APP_ERR_CRYPTO;
		}
	}
	#endif

	/* Zero out sensitive data */
	secure_zeroize(ctx->local_public_key, sizeof(ctx->local_public_key));
	secure_zeroize(ctx->peer_public_key, sizeof(ctx->peer_public_key));

	/* Reset context */
	ecdh_context_init(ctx);

	LOG_INF("ECDH cleanup complete");
	return ret;
}
