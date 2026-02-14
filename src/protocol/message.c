/**
 * @file message.c
 * @brief Message protocol implementation
 */

#include "message.h"
#include "../crypto/ecdh.h"

LOG_MODULE_REGISTER(message, LOG_LEVEL_PROTOCOL);

int message_create_secure(struct crypto_context *ctx,
                          uint8_t msg_type,
                          uint16_t sender_id,
                          uint16_t seq_num,
                          struct secure_message *msg,
                          uint32_t *encrypt_time_us)
{
	int ret;
	size_t ciphertext_len;

	if (ctx == NULL || msg == NULL) {
		LOG_ERR("Invalid parameters");
		return APP_ERR_INVALID_PARAM;
	}

	/* Initialize message structure */
	memset(msg, 0, sizeof(*msg));

	/* Reserve final counter window to avoid nonce reuse on wraparound. */
	if (ctx->local_msg_counter > (UINT32_MAX - COUNTER_ROLLOVER_WARNING_THRESHOLD)) {
		LOG_ERR("Message counter rollover guard triggered at %u", ctx->local_msg_counter);
		return APP_ERR_PROTOCOL_COUNTER_ROLLOVER;
	}

	/* Fill plaintext header */
	msg->version = PROTOCOL_VERSION;
	msg->type = msg_type;
	msg->sender_id = sender_id;
	msg->msg_counter = ctx->local_msg_counter++;
	msg->flags = MSG_FLAG_ENCRYPTED | MSG_FLAG_AUTHENTICATED;
	msg->payload_len = sizeof(msg->payload);

	/* Fill payload (will be encrypted) */
	msg->payload.seq_num = seq_num;
	msg->payload.timestamp = k_uptime_get_32();
	msg->payload.padding = 0;

	/* Construct nonce for this message */
	crypto_construct_nonce(ctx, msg->msg_counter, msg->nonce);

	/* Encrypt payload with header as AAD */
	size_t aad_len = offsetof(struct secure_message, payload);
	uint8_t ciphertext_with_tag[sizeof(msg->payload) + AES_CCM_TAG_SIZE];

	ret = crypto_aes_ccm_encrypt(ctx,
	                             msg->nonce,
	                             (uint8_t *)msg, aad_len,
	                             (uint8_t *)&msg->payload, sizeof(msg->payload),
	                             ciphertext_with_tag, sizeof(ciphertext_with_tag),
	                             &ciphertext_len,
	                             encrypt_time_us);
	if (ret != APP_OK) {
		LOG_ERR("Encryption failed: %d", ret);
		return ret;
	}

	/* Split ciphertext and tag back into message structure */
	memcpy(&msg->payload, ciphertext_with_tag, sizeof(msg->payload));
	memcpy(msg->auth_tag, ciphertext_with_tag + sizeof(msg->payload), AES_CCM_TAG_SIZE);

	LOG_DBG("Created secure %s (counter=%u, seq=%u)",
	        message_type_to_string(msg_type), msg->msg_counter, seq_num);

	return APP_OK;
}

int message_parse_secure(struct crypto_context *ctx,
                         struct secure_message *msg,
                         uint32_t *decrypt_time_us)
{
	int ret;
	size_t plaintext_len;
	uint8_t ciphertext_with_tag[sizeof(msg->payload) + AES_CCM_TAG_SIZE];
	uint8_t plaintext[sizeof(msg->payload)];

	if (ctx == NULL || msg == NULL) {
		LOG_ERR("Invalid parameters");
		return APP_ERR_INVALID_PARAM;
	}

	/* Validate protocol version */
	if (msg->version != PROTOCOL_VERSION) {
		LOG_WRN("Protocol version mismatch: got %u, expected %u",
		        msg->version, PROTOCOL_VERSION);
		return APP_ERR_PROTOCOL_INVALID_VERSION;
	}

	/* Reconstruct ciphertext + tag format for PSA */
	memcpy(ciphertext_with_tag, &msg->payload, sizeof(msg->payload));
	memcpy(ciphertext_with_tag + sizeof(msg->payload), msg->auth_tag, AES_CCM_TAG_SIZE);

	/* Decrypt and authenticate with header as AAD */
	size_t aad_len = offsetof(struct secure_message, payload);

	ret = crypto_aes_ccm_decrypt(ctx,
	                             msg->nonce,
	                             (uint8_t *)msg, aad_len,
	                             ciphertext_with_tag, sizeof(ciphertext_with_tag),
	                             plaintext, sizeof(plaintext),
	                             &plaintext_len,
	                             decrypt_time_us);
	if (ret != APP_OK) {
		if (ret == APP_ERR_CRYPTO_AUTH_FAILED) {
			LOG_ERR("Authentication failed for message");
		} else {
			LOG_ERR("Decryption failed: %d", ret);
		}
		return ret;
	}

	/* Copy decrypted plaintext back to message structure */
	memcpy(&msg->payload, plaintext, sizeof(msg->payload));

	LOG_DBG("Parsed secure %s (counter=%u, seq=%u)",
	        message_type_to_string(msg->type), msg->msg_counter, msg->payload.seq_num);

	return APP_OK;
}

int message_create_key_exchange(struct ecdh_context *ecdh_ctx,
                                uint8_t msg_type,
                                uint16_t sender_id,
                                struct key_exchange_message *msg)
{
	int ret;

	if (ecdh_ctx == NULL || msg == NULL) {
		LOG_ERR("Invalid parameters");
		return APP_ERR_INVALID_PARAM;
	}

	/* Initialize message structure */
	memset(msg, 0, sizeof(*msg));

	/* Fill header */
	msg->version = PROTOCOL_VERSION;
	msg->type = msg_type;
	msg->sender_id = sender_id;
	msg->timestamp = k_uptime_get_32();
	msg->reserved = 0;

	/* Get local public key */
	ret = ecdh_get_public_key(ecdh_ctx, msg->public_key);
	if (ret != APP_OK) {
		LOG_ERR("Failed to get public key: %d", ret);
		return ret;
	}

#if ENABLE_PSK_AUTHENTICATION
	/* Generate HMAC tag over header + public key */
	size_t data_len = offsetof(struct key_exchange_message, hmac_tag);
	ret = ecdh_generate_hmac(ecdh_ctx, (uint8_t *)msg, data_len, msg->hmac_tag);
	if (ret != APP_OK) {
		LOG_ERR("HMAC generation failed: %d", ret);
		return ret;
	}
	LOG_DBG("HMAC tag generated for key exchange message");
#endif

	LOG_DBG("Created key exchange message: %s", message_type_to_string(msg_type));

	return APP_OK;
}

int message_parse_key_exchange(struct ecdh_context *ecdh_ctx,
                               const struct key_exchange_message *msg)
{
	if (ecdh_ctx == NULL || msg == NULL) {
		LOG_ERR("Invalid parameters");
		return APP_ERR_INVALID_PARAM;
	}

	/* Validate protocol version */
	if (msg->version != PROTOCOL_VERSION) {
		LOG_WRN("Protocol version mismatch: got %u, expected %u",
		        msg->version, PROTOCOL_VERSION);
		return APP_ERR_PROTOCOL_INVALID_VERSION;
	}

#if ENABLE_PSK_AUTHENTICATION
	int ret;

	/* Verify HMAC tag */
	size_t data_len = offsetof(struct key_exchange_message, hmac_tag);
	ret = ecdh_verify_hmac(ecdh_ctx, (uint8_t *)msg, data_len, msg->hmac_tag);
	if (ret != APP_OK) {
		LOG_ERR("HMAC verification failed: %d", ret);
		LOG_ERR("Possible MITM attack detected!");
		return ret;
	}
	LOG_DBG("HMAC verified - sender authenticated");
#endif

	LOG_DBG("Parsed key exchange message: %s from device 0x%04X",
	        message_type_to_string(msg->type), msg->sender_id);

	return APP_OK;
}

const char *message_type_to_string(uint8_t msg_type)
{
	switch (msg_type) {
	case MSG_TYPE_PING:
		return "PING";
	case MSG_TYPE_PONG:
		return "PONG";
	case MSG_TYPE_KEY_ANNOUNCE:
		return "KEY_ANNOUNCE";
	case MSG_TYPE_KEY_ACK:
		return "KEY_ACK";
	case MSG_TYPE_REKEY:
		return "REKEY";
	default:
		return "UNKNOWN";
	}
}
