/**
 * @file pong_mode.c
 * @brief PONG mode implementation
 */

#include "pong_mode.h"

LOG_MODULE_REGISTER(pong_mode, LOG_LEVEL_INF);

int pong_mode_run(struct app_context *ctx)
{
	struct secure_message tx_msg, rx_msg;
	int ret;
	uint32_t pongs_sent = 0;

	if (ctx == NULL || ctx->lora_dev == NULL || ctx->crypto_ctx == NULL ||
	    ctx->peer == NULL || ctx->stats == NULL) {
		LOG_ERR("Invalid context");
		return APP_ERR_INVALID_PARAM;
	}

	LOG_INF("Starting ENCRYPTED PONG mode - listening for PINGs...");
	LOG_INF("Will respond to %u encrypted ping requests", PING_COUNT);
	LOG_INF("Encryption: AES-128-CCM with hardware acceleration");
	LOG_INF("");

	while (pongs_sent < PING_COUNT) {
		int16_t rssi;
		int8_t snr;
		uint32_t encrypt_time_us, decrypt_time_us;

		LOG_INF("Listening for encrypted PING #%u...", pongs_sent + 1);

		/* Wait for PING */
		ret = lora_transport_recv(ctx->lora_dev, (uint8_t *)&rx_msg, sizeof(rx_msg),
		                         K_FOREVER, &rssi, &snr);

		if (ret < 0) {
			LOG_ERR("RX error: %d", ret);
			ctx->stats->rx_error++;
			continue;
		}

		if (ret != (int)sizeof(rx_msg)) {
			LOG_WRN("Dropping truncated/oversized frame (%d bytes, expected %zu)",
			        ret, sizeof(rx_msg));
			ctx->stats->rx_error++;
			continue;
		}

		LOG_INF("Encrypted PING received (%d bytes)", ret);

		/* Validate message type */
		if (rx_msg.type != MSG_TYPE_PING) {
			LOG_WRN("Received non-PING message type: 0x%02X", rx_msg.type);
			ctx->stats->rx_error++;
			continue;
		}

		/* Security validation */
		ret = security_validate_message(ctx->peer, rx_msg.sender_id, rx_msg.msg_counter);
		if (ret != APP_OK) {
			LOG_ERR("Security validation failed: %d", ret);
			if (ret == APP_ERR_PROTOCOL_REPLAY_ATTACK) {
				ctx->stats->crypto_replay_rejected++;
			}
			ctx->stats->rx_error++;
			continue;
		}

		/* Decrypt and authenticate */
		ret = message_parse_secure(ctx->crypto_ctx, &rx_msg, &decrypt_time_us);
		if (ret != APP_OK) {
			LOG_ERR("Decryption/authentication failed: %d", ret);
			if (ret == APP_ERR_CRYPTO_AUTH_FAILED) {
				ctx->stats->crypto_auth_failures++;
			}
			ctx->stats->rx_error++;
			continue;
		}

		ret = security_commit_message(ctx->peer, rx_msg.msg_counter);
		if (ret != APP_OK) {
			LOG_ERR("Replay state commit failed: %d", ret);
			ctx->stats->rx_error++;
			continue;
		}

		ctx->stats->crypto_decrypt_count++;
		ctx->stats->crypto_decrypt_time_us += decrypt_time_us;

		/* PING received and decrypted! */
		ctx->stats->rx_received++;
		statistics_update_rf(ctx->stats, rssi, snr);

		LOG_INF(">>> ENCRYPTED PING #%u received <<<", rx_msg.payload.seq_num);
		LOG_INF("  Sequence:       %u", rx_msg.payload.seq_num);
		LOG_INF("  PING timestamp: %u", rx_msg.payload.timestamp);
		LOG_INF("  Peer counter:   %u", rx_msg.msg_counter);
		LOG_INF("  RSSI:           %d dBm", rssi);
		LOG_INF("  SNR:            %d dB", snr);
		LOG_INF("  Payload decrypted and authenticated!");

		/* Check for counter rollover */
		if (security_counter_approaching_rollover(ctx->crypto_ctx->local_msg_counter)) {
			LOG_WRN("Message counter approaching rollover: %u",
			        ctx->crypto_ctx->local_msg_counter);
		}

		/* Prepare and send PONG response */
		LOG_INF("  Preparing encrypted PONG response...");

		ret = message_create_secure(ctx->crypto_ctx, MSG_TYPE_PONG,
		                            ctx->device_id, rx_msg.payload.seq_num, &tx_msg, &encrypt_time_us);
		if (ret != APP_OK) {
			LOG_ERR("  Failed to create pong message: %d", ret);
			if (ret == APP_ERR_PROTOCOL_COUNTER_ROLLOVER) {
				LOG_ERR("  Message counter rollover guard triggered. Re-key is required.");
				return ret;
			}
			ctx->stats->tx_failed++;
			LOG_INF("");
			continue;
		}

		ctx->stats->crypto_encrypt_count++;
		ctx->stats->crypto_encrypt_time_us += encrypt_time_us;
		LOG_INF("  Payload encrypted (CRACEN accelerated)");

		ret = lora_transport_send(ctx->lora_dev, (uint8_t *)&tx_msg, sizeof(tx_msg));
		if (ret != APP_OK) {
			LOG_ERR("  PONG send failed: %d", ret);
			ctx->stats->tx_failed++;
		} else {
			ctx->stats->tx_sent++;
			pongs_sent++;
			LOG_INF("  ENCRYPTED PONG sent (%u bytes, seq=%u, counter=%u)",
			        sizeof(tx_msg), tx_msg.payload.seq_num, tx_msg.msg_counter);
		}

		LOG_INF("");

		/* Display periodic statistics every 10 exchanges */
		if (pongs_sent > 0 && (pongs_sent % 10) == 0) {
			LOG_INF("--- Progress: %u/%u secure exchanges completed ---",
			        pongs_sent, PING_COUNT);
		}
	}

	/* Display final statistics */
	LOG_INF("Encrypted pong test complete!");
	statistics_display(ctx->stats, ROLE_PONG);

	return APP_OK;
}
