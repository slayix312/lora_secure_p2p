/**
 * @file ping_mode.c
 * @brief PING mode implementation
 */

#include "ping_mode.h"

LOG_MODULE_REGISTER(ping_mode, LOG_LEVEL_INF);

int ping_mode_run(struct app_context *ctx)
{
	struct secure_message tx_msg, rx_msg;
	int ret;

	if (ctx == NULL || ctx->lora_dev == NULL || ctx->crypto_ctx == NULL ||
	    ctx->peer == NULL || ctx->stats == NULL) {
		LOG_ERR("Invalid context");
		return APP_ERR_INVALID_PARAM;
	}

	LOG_INF("Starting ENCRYPTED PING mode - will send %u pings", PING_COUNT);
	LOG_INF("Ping interval: %u ms, Timeout: %u ms", PING_INTERVAL_MS, PONG_TIMEOUT_MS);
	LOG_INF("Encryption: AES-128-CCM with hardware acceleration");
	LOG_INF("");

	for (uint16_t seq = 1; seq <= PING_COUNT; seq++) {
		int16_t rssi;
		int8_t snr;
		uint32_t ping_sent_time;
		uint32_t encrypt_time_us, decrypt_time_us;

		LOG_INF(">>> ENCRYPTED PING #%u <<<", seq);

		/* Check for counter rollover */
		if (security_counter_approaching_rollover(ctx->crypto_ctx->local_msg_counter)) {
			LOG_WRN("Message counter approaching rollover: %u",
			        ctx->crypto_ctx->local_msg_counter);
		}

		/* Create encrypted ping message */
		ret = message_create_secure(ctx->crypto_ctx, MSG_TYPE_PING,
		                            ctx->device_id, seq, &tx_msg, &encrypt_time_us);
		if (ret != APP_OK) {
			LOG_ERR("  Failed to create ping message: %d", ret);
			if (ret == APP_ERR_PROTOCOL_COUNTER_ROLLOVER) {
				LOG_ERR("  Message counter rollover guard triggered. Re-key is required.");
				return ret;
			}
			ctx->stats->tx_failed++;
			k_sleep(K_MSEC(PING_INTERVAL_MS));
			continue;
		}

		ctx->stats->crypto_encrypt_count++;
		ctx->stats->crypto_encrypt_time_us += encrypt_time_us;
		LOG_INF("  Payload encrypted (CRACEN accelerated)");

		/* Send ping */
		ping_sent_time = k_uptime_get_32();
		ret = lora_transport_send(ctx->lora_dev, (uint8_t *)&tx_msg, sizeof(tx_msg));
		if (ret != APP_OK) {
			LOG_ERR("  PING send failed: %d", ret);
			ctx->stats->tx_failed++;
			k_sleep(K_MSEC(PING_INTERVAL_MS));
			continue;
		}

		ctx->stats->tx_sent++;
		LOG_INF("  ENCRYPTED PING sent (%u bytes)", sizeof(tx_msg));

		/* Wait for PONG response */
		LOG_INF("  Waiting for encrypted PONG...");

		ret = lora_transport_recv(ctx->lora_dev, (uint8_t *)&rx_msg, sizeof(rx_msg),
		                         K_MSEC(PONG_TIMEOUT_MS), &rssi, &snr);

		if (ret < 0) {
			if (ret == APP_ERR_LORA_TIMEOUT) {
				LOG_WRN("  TIMEOUT - No PONG received");
				ctx->stats->rx_timeout++;
			} else {
				LOG_ERR("  RX error: %d", ret);
				ctx->stats->rx_error++;
			}
			LOG_INF("");
			k_sleep(K_MSEC(PING_INTERVAL_MS));
			continue;
		}

		if (ret != (int)sizeof(rx_msg)) {
			LOG_WRN("  Dropping truncated/oversized frame (%d bytes, expected %zu)",
			        ret, sizeof(rx_msg));
			ctx->stats->rx_error++;
			LOG_INF("");
			k_sleep(K_MSEC(PING_INTERVAL_MS));
			continue;
		}

		LOG_INF("  Encrypted PONG received (%d bytes)", ret);

		/* Validate message type */
		if (rx_msg.type != MSG_TYPE_PONG) {
			LOG_WRN("  Invalid message type: 0x%02X (expected PONG)", rx_msg.type);
			ctx->stats->rx_error++;
			LOG_INF("");
			k_sleep(K_MSEC(PING_INTERVAL_MS));
			continue;
		}

		/* Security validation */
		ret = security_validate_message(ctx->peer, rx_msg.sender_id, rx_msg.msg_counter);
		if (ret != APP_OK) {
			LOG_ERR("  Security validation failed: %d", ret);
			if (ret == APP_ERR_PROTOCOL_REPLAY_ATTACK) {
				ctx->stats->crypto_replay_rejected++;
			}
			ctx->stats->rx_error++;
			LOG_INF("");
			k_sleep(K_MSEC(PING_INTERVAL_MS));
			continue;
		}

		/* Decrypt and authenticate */
		ret = message_parse_secure(ctx->crypto_ctx, &rx_msg, &decrypt_time_us);
		if (ret != APP_OK) {
			LOG_ERR("  Decryption/authentication failed: %d", ret);
			if (ret == APP_ERR_CRYPTO_AUTH_FAILED) {
				ctx->stats->crypto_auth_failures++;
			}
			ctx->stats->rx_error++;
			LOG_INF("");
			k_sleep(K_MSEC(PING_INTERVAL_MS));
			continue;
		}

		ret = security_commit_message(ctx->peer, rx_msg.msg_counter);
		if (ret != APP_OK) {
			LOG_ERR("  Failed to commit replay state: %d", ret);
			ctx->stats->rx_error++;
			LOG_INF("");
			k_sleep(K_MSEC(PING_INTERVAL_MS));
			continue;
		}

		ctx->stats->crypto_decrypt_count++;
		ctx->stats->crypto_decrypt_time_us += decrypt_time_us;
		LOG_INF("  Payload decrypted and authenticated!");

		/* Calculate RTT */
		uint32_t rtt_ms = k_uptime_get_32() - ping_sent_time;

		/* Validate sequence number */
		if (rx_msg.payload.seq_num != seq) {
			LOG_WRN("  Sequence mismatch: got %u, expected %u",
			        rx_msg.payload.seq_num, seq);
		}

		/* Success! */
		ctx->stats->rx_received++;
		statistics_update_rf(ctx->stats, rssi, snr);
		statistics_update_rtt(ctx->stats, rtt_ms);

		LOG_INF("  Secure exchange complete!");
		LOG_INF("    Sequence:       %u", rx_msg.payload.seq_num);
		LOG_INF("    Round-trip:     %u ms", rtt_ms);
		LOG_INF("    RSSI:           %d dBm", rssi);
		LOG_INF("    SNR:            %d dB", snr);
		LOG_INF("    PONG timestamp: %u", rx_msg.payload.timestamp);
		LOG_INF("    Peer counter:   %u", rx_msg.msg_counter);
		LOG_INF("");

		/* Delay before next ping */
		if (seq < PING_COUNT) {
			k_sleep(K_MSEC(PING_INTERVAL_MS));
		}
	}

	/* Display final statistics */
	LOG_INF("Encrypted ping test complete!");
	statistics_display(ctx->stats, ROLE_PING);

	return APP_OK;
}
