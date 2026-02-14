/**
 * @file ecdh.h
 * @brief X25519 ECDH key exchange and session key derivation
 *
 * This module implements Elliptic Curve Diffie-Hellman (ECDH) key exchange
 * using Curve25519 (X25519) for secure session key establishment.
 *
 * Features:
 * - X25519 keypair generation
 * - ECDH shared secret computation
 * - HKDF-SHA256 session key derivation
 * - Optional HMAC-SHA256 authentication (MITM protection)
 */

#ifndef ECDH_H
#define ECDH_H

#include "../app_config.h"

/**
 * @brief ECDH context structure
 *
 * Manages ECDH state including keypairs and derived session key
 */
struct ecdh_context {
	psa_key_id_t private_key_handle;           /**< X25519 private key handle */
	uint8_t local_public_key[ECDH_PUBLIC_KEY_SIZE];   /**< Our public key */
	uint8_t peer_public_key[ECDH_PUBLIC_KEY_SIZE];    /**< Peer's public key */
	psa_key_id_t session_key_handle;           /**< Derived AES session key handle */
	bool keypair_generated;                     /**< True if local keypair is ready */
	bool peer_key_received;                     /**< True if peer public key received */
	bool session_key_derived;                   /**< True if session key is derived */
#if ENABLE_PSK_AUTHENTICATION
	psa_key_id_t auth_psk_handle;              /**< HMAC authentication PSK handle */
	bool auth_psk_loaded;                       /**< True if auth PSK is loaded */
#endif
};

/**
 * @brief Initialize ECDH context
 *
 * @param ctx Pointer to ECDH context structure
 */
void ecdh_context_init(struct ecdh_context *ctx);

/**
 * @brief Generate X25519 keypair for ECDH
 *
 * Generates a Curve25519 key pair for Elliptic Curve Diffie-Hellman key exchange.
 * The private key is stored securely and the public key is exported for sharing.
 *
 * Key Storage Options:
 * - VOLATILE: Key lost on reboot (current implementation)
 * - PERSISTENT: Key stored in ITS with HUK encryption (planned)
 * - KMU: Key stored in hardware-protected KMU slot (planned, most secure)
 *
 * @param ctx Pointer to ECDH context
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO_KEY_GEN on key generation failure
 * @return APP_ERR_INVALID_PARAM if context is NULL
 */
int ecdh_generate_keypair(struct ecdh_context *ctx);

/**
 * @brief Get local public key
 *
 * @param ctx Pointer to ECDH context
 * @param public_key Output buffer for public key (must be ECDH_PUBLIC_KEY_SIZE bytes)
 * @return APP_OK on success
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 * @return APP_ERR_NOT_READY if keypair not generated
 */
int ecdh_get_public_key(const struct ecdh_context *ctx, uint8_t *public_key);

/**
 * @brief Set peer's public key
 *
 * Stores the peer's public key for later ECDH computation
 *
 * @param ctx Pointer to ECDH context
 * @param peer_public_key Peer's X25519 public key (must be ECDH_PUBLIC_KEY_SIZE bytes)
 * @return APP_OK on success
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 */
int ecdh_set_peer_public_key(struct ecdh_context *ctx, const uint8_t *peer_public_key);

/**
 * @brief Derive AES session key from ECDH shared secret
 *
 * Performs X25519 ECDH with peer's public key to compute shared secret,
 * then derives an AES-128 session key using HKDF-SHA256.
 *
 * Process:
 * 1. Perform ECDH: shared_secret = my_private_key × peer_public_key
 * 2. Derive AES key: session_key = HKDF-SHA256(shared_secret, salt, info)
 * 3. Store session key for AES-CCM encryption
 *
 * @param ctx Pointer to ECDH context
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO_DERIVE on key derivation failure
 * @return APP_ERR_INVALID_PARAM if context is NULL
 * @return APP_ERR_NOT_READY if keypair or peer key not set
 */
int ecdh_derive_session_key(struct ecdh_context *ctx);

/**
 * @brief Get derived session key handle
 *
 * @param ctx Pointer to ECDH context
 * @param key_handle Output: PSA key handle for session key
 * @return APP_OK on success
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 * @return APP_ERR_NOT_READY if session key not derived
 */
int ecdh_get_session_key_handle(const struct ecdh_context *ctx, psa_key_id_t *key_handle);

/**
 * @brief Cleanup ephemeral key-exchange material but keep session key
 *
 * Destroys ECDH private key and auth PSK handles after session key handoff.
 * Keeps the derived session key handle valid for ongoing encrypted traffic.
 *
 * @param ctx Pointer to ECDH context
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO on cleanup failure
 */
int ecdh_cleanup_exchange_material(struct ecdh_context *ctx);

#if ENABLE_PSK_AUTHENTICATION
/**
 * @brief Import pre-shared key for HMAC authentication (MITM protection)
 *
 * This PSK is used to authenticate the ECDH public key exchange.
 * Both devices must have the same PSK programmed.
 *
 * Security Model:
 * - PSK proves device identity (prevents impersonation)
 * - ECDH provides forward secrecy (prevents future decryption)
 * - Together: Authenticated key exchange with forward secrecy
 *
 * @param ctx Pointer to ECDH context
 * @param psk Pre-shared key data (must be HMAC_KEY_SIZE_BYTES)
 * @param psk_len Length of PSK in bytes
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO_KEY_IMPORT on import failure
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 *
 * @warning In production, DO NOT use hardcoded keys! Use secure provisioning.
 */
int ecdh_import_auth_psk(struct ecdh_context *ctx, const uint8_t *psk, size_t psk_len);

/**
 * @brief Generate HMAC-SHA256 tag for authentication
 *
 * Computes HMAC over the provided data using the pre-shared authentication key.
 * This proves the sender knows the PSK and prevents MITM attacks.
 *
 * @param ctx Pointer to ECDH context
 * @param data Data to authenticate
 * @param data_len Length of data in bytes
 * @param hmac_tag Output buffer for HMAC tag (must be HMAC_TAG_SIZE bytes)
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO_HMAC on HMAC failure
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 * @return APP_ERR_NOT_READY if auth PSK not loaded
 */
int ecdh_generate_hmac(struct ecdh_context *ctx,
                       const uint8_t *data, size_t data_len,
                       uint8_t *hmac_tag);

/**
 * @brief Verify HMAC-SHA256 tag
 *
 * Verifies that the HMAC tag on received data is valid.
 * If verification fails, the message is from an attacker who doesn't know
 * the PSK, and the key exchange must be aborted.
 *
 * @param ctx Pointer to ECDH context
 * @param data Data to verify
 * @param data_len Length of data in bytes
 * @param hmac_tag HMAC tag to verify (must be HMAC_TAG_SIZE bytes)
 * @return APP_OK if HMAC is valid
 * @return APP_ERR_CRYPTO_AUTH_FAILED if verification fails
 * @return APP_ERR_CRYPTO_HMAC on other HMAC failures
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 * @return APP_ERR_NOT_READY if auth PSK not loaded
 */
int ecdh_verify_hmac(struct ecdh_context *ctx,
                     const uint8_t *data, size_t data_len,
                     const uint8_t *hmac_tag);
#endif /* ENABLE_PSK_AUTHENTICATION */

/**
 * @brief Cleanup ECDH context and destroy keys
 *
 * Destroys all cryptographic keys and resets the context.
 * Should be called during shutdown or before re-initialization.
 *
 * @param ctx Pointer to ECDH context
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO on cleanup failure
 */
int ecdh_cleanup(struct ecdh_context *ctx);

#endif /* ECDH_H */
