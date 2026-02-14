/**
 * @file message.h
 * @brief Message protocol structures and handling
 *
 * This module defines the message protocol structures for secure P2P
 * communication and provides functions for creating and parsing messages.
 */

#ifndef MESSAGE_H
#define MESSAGE_H

#include "../app_config.h"
#include "../crypto/aes_ccm.h"

/* Forward declarations */
struct ecdh_context;

/**
 * @brief Secure Ping/Pong Message Structure (Protocol v2)
 *
 * This structure provides authenticated encryption for P2P LoRa communication:
 * - Plaintext header enables packet identification and replay detection
 * - Encrypted payload protects sensitive data
 * - Authentication tag prevents tampering
 * - Flags field enables protocol extensibility
 *
 * Total size: 47 bytes
 */
struct secure_message {
	/* ---- PLAINTEXT HEADER (11 bytes) ---- */
	uint8_t version;          /**< Protocol version (PROTOCOL_VERSION) */
	uint8_t type;             /**< Message type (PING/PONG/KEY_ANNOUNCE/etc) */
	uint16_t sender_id;       /**< Device identifier */
	uint32_t msg_counter;     /**< Monotonic message counter (replay protection) */
	uint8_t flags;            /**< Feature flags (encrypted, authenticated, etc) */
	uint16_t payload_len;     /**< Length of encrypted payload */

	/* ---- ENCRYPTED PAYLOAD (variable, max 8 bytes for ping/pong) ---- */
	struct {
		uint16_t seq_num;     /**< Sequence number (test counter) */
		uint32_t timestamp;   /**< Sender timestamp (ms since boot) */
		uint16_t padding;     /**< Reserved for future data */
	} __packed payload;

	/* ---- CRYPTO METADATA (28 bytes) ---- */
	uint8_t nonce[AES_CCM_NONCE_SIZE];   /**< 96-bit nonce for AES-CCM */
	uint8_t auth_tag[AES_CCM_TAG_SIZE];  /**< 128-bit authentication tag */
} __packed;

/**
 * @brief Key Exchange Message Structure
 *
 * Used for exchanging X25519 public keys between devices.
 * Supports optional HMAC authentication to prevent MITM attacks.
 *
 * Total size: 44 bytes (without auth) or 76 bytes (with auth)
 */
struct key_exchange_message {
	/* ---- HEADER (12 bytes) ---- */
	uint8_t version;          /**< Protocol version */
	uint8_t type;             /**< MSG_TYPE_KEY_ANNOUNCE or MSG_TYPE_KEY_ACK */
	uint16_t sender_id;       /**< Device identifier */
	uint32_t timestamp;       /**< Timestamp */
	uint32_t reserved;        /**< Reserved for future use */

	/* ---- PUBLIC KEY (32 bytes) ---- */
	uint8_t public_key[ECDH_PUBLIC_KEY_SIZE];   /**< X25519 public key */

#if ENABLE_PSK_AUTHENTICATION
	/* ---- AUTHENTICATION TAG (32 bytes) ---- */
	uint8_t hmac_tag[HMAC_TAG_SIZE];  /**< HMAC-SHA256 for authentication */
#endif
} __packed;

/**
 * @brief Create a secure ping/pong message
 *
 * Creates and encrypts a ping or pong message with the given parameters.
 *
 * @param ctx Crypto context (contains session key and message counter)
 * @param msg_type Message type (MSG_TYPE_PING or MSG_TYPE_PONG)
 * @param sender_id Local device ID
 * @param seq_num Sequence number for this exchange
 * @param msg Output: Created and encrypted message
 * @param encrypt_time_us Output: Encryption time in microseconds (can be NULL)
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO_ENCRYPT on encryption failure
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 */
int message_create_secure(struct crypto_context *ctx,
                          uint8_t msg_type,
                          uint16_t sender_id,
                          uint16_t seq_num,
                          struct secure_message *msg,
                          uint32_t *encrypt_time_us);

/**
 * @brief Parse and decrypt a secure message
 *
 * Decrypts and authenticates a received secure message.
 *
 * @param ctx Crypto context (contains session key)
 * @param msg Input/Output: Message to decrypt (decrypted in place)
 * @param decrypt_time_us Output: Decryption time in microseconds (can be NULL)
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO_DECRYPT on decryption failure
 * @return APP_ERR_CRYPTO_AUTH_FAILED if authentication fails
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 * @return APP_ERR_PROTOCOL_INVALID_VERSION if version mismatch
 */
int message_parse_secure(struct crypto_context *ctx,
                         struct secure_message *msg,
                         uint32_t *decrypt_time_us);

/**
 * @brief Create a key exchange message
 *
 * Creates a key exchange message with the local public key.
 * Optionally includes HMAC authentication if enabled.
 *
 * @param ecdh_ctx ECDH context (contains public key and auth PSK)
 * @param msg_type Message type (MSG_TYPE_KEY_ANNOUNCE or MSG_TYPE_KEY_ACK)
 * @param sender_id Local device ID
 * @param msg Output: Created key exchange message
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO_HMAC on HMAC generation failure
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 */
int message_create_key_exchange(struct ecdh_context *ecdh_ctx,
                                uint8_t msg_type,
                                uint16_t sender_id,
                                struct key_exchange_message *msg);

/**
 * @brief Parse and verify a key exchange message
 *
 * Parses a received key exchange message and verifies HMAC if enabled.
 *
 * @param ecdh_ctx ECDH context (contains auth PSK for verification)
 * @param msg Input: Message to parse and verify
 * @return APP_OK on success
 * @return APP_ERR_CRYPTO_AUTH_FAILED if HMAC verification fails
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 * @return APP_ERR_PROTOCOL_INVALID_VERSION if version mismatch
 */
int message_parse_key_exchange(struct ecdh_context *ecdh_ctx,
                               const struct key_exchange_message *msg);

/**
 * @brief Get readable string for message type
 *
 * @param msg_type Message type value
 * @return String representation of message type
 */
const char *message_type_to_string(uint8_t msg_type);

#endif /* MESSAGE_H */
