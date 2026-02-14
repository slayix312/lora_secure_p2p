/**
 * @file statistics.c
 * @brief Statistics tracking implementation
 */

#include "statistics.h"

LOG_MODULE_REGISTER(statistics, LOG_LEVEL_PROTOCOL);

void statistics_init(struct statistics *stats)
{
	if (stats == NULL) {
		return;
	}

	memset(stats, 0, sizeof(*stats));
	stats->rtt_min_ms = UINT32_MAX;
	stats->rtt_max_ms = 0;
	stats->rssi_min = 0;
	stats->rssi_max = -200;
	stats->snr_min = 127;
	stats->snr_max = -128;

	LOG_DBG("Statistics initialized");
}

void statistics_update_rf(struct statistics *stats, int16_t rssi, int8_t snr)
{
	if (stats == NULL) {
		return;
	}

	if (rssi < stats->rssi_min) {
		stats->rssi_min = rssi;
	}
	if (rssi > stats->rssi_max) {
		stats->rssi_max = rssi;
	}
	stats->rssi_sum += rssi;

	if (snr < stats->snr_min) {
		stats->snr_min = snr;
	}
	if (snr > stats->snr_max) {
		stats->snr_max = snr;
	}
	stats->snr_sum += snr;
}

void statistics_update_rtt(struct statistics *stats, uint32_t rtt_ms)
{
	if (stats == NULL) {
		return;
	}

	if (rtt_ms < stats->rtt_min_ms) {
		stats->rtt_min_ms = rtt_ms;
	}
	if (rtt_ms > stats->rtt_max_ms) {
		stats->rtt_max_ms = rtt_ms;
	}
	stats->rtt_sum_ms += rtt_ms;
}

void statistics_display(const struct statistics *stats, board_role_t role)
{
	if (stats == NULL) {
		return;
	}

	LOG_INF("");
	LOG_INF("========================================");
	LOG_INF("    PING/PONG TEST RESULTS");
	LOG_INF("========================================");

	if (role == ROLE_PING) {
		uint32_t total_exchanges = stats->tx_sent;
		uint32_t successful = stats->rx_received;

		LOG_INF("Mode: PING (Initiator)");
		LOG_INF("");
		LOG_INF("Transmission:");
		LOG_INF("  Total PINGs sent:     %u", stats->tx_sent);
		LOG_INF("  Failed to send:       %u", stats->tx_failed);
		LOG_INF("");
		LOG_INF("Reception:");
		LOG_INF("  PONGs received:       %u", stats->rx_received);
		LOG_INF("  Timeouts:             %u", stats->rx_timeout);
		LOG_INF("  Errors:               %u", stats->rx_error);
		LOG_INF("");

		/* Success rate */
		if (total_exchanges > 0) {
			uint32_t success_rate = (100 * successful) / total_exchanges;
			LOG_INF("Success Rate:           %u%%", success_rate);
			uint32_t packet_loss = total_exchanges - successful;
			LOG_INF("Packet Loss:            %u packets", packet_loss);
		}

		/* Round-trip time statistics */
		if (stats->rx_received > 0) {
			uint32_t rtt_avg = (uint32_t)(stats->rtt_sum_ms / stats->rx_received);
			LOG_INF("");
			LOG_INF("Round-Trip Time (RTT):");
			LOG_INF("  Minimum:  %u ms", stats->rtt_min_ms);
			LOG_INF("  Maximum:  %u ms", stats->rtt_max_ms);
			LOG_INF("  Average:  %u ms", rtt_avg);
		}

	} else { /* ROLE_PONG */
		LOG_INF("Mode: PONG (Responder)");
		LOG_INF("");
		LOG_INF("Reception:");
		LOG_INF("  PINGs received:       %u", stats->rx_received);
		LOG_INF("  RX errors:            %u", stats->rx_error);
		LOG_INF("");
		LOG_INF("Transmission:");
		LOG_INF("  PONGs sent:           %u", stats->tx_sent);
		LOG_INF("  Failed to send:       %u", stats->tx_failed);
		LOG_INF("");

		/* Success rate */
		if (stats->rx_received > 0) {
			uint32_t response_rate = (100 * stats->tx_sent) / stats->rx_received;
			LOG_INF("Response Rate:          %u%%", response_rate);
		}
	}

	/* RF Quality statistics (both modes) */
	if (stats->rx_received > 0) {
		int16_t rssi_avg = (int16_t)(stats->rssi_sum / (int64_t)stats->rx_received);
		int8_t snr_avg = (int8_t)(stats->snr_sum / (int64_t)stats->rx_received);

		LOG_INF("");
		LOG_INF("RF Signal Quality:");
		LOG_INF("  RSSI: %d dBm (min: %d, max: %d)",
		        rssi_avg, stats->rssi_min, stats->rssi_max);
		LOG_INF("  SNR:  %d dB  (min: %d, max: %d)",
		        snr_avg, stats->snr_min, stats->snr_max);
	}

	/* Cryptography Statistics */
	LOG_INF("");
	LOG_INF("Cryptography (AES-128-CCM, CRACEN):");
	LOG_INF("  Encryptions:          %u", stats->crypto_encrypt_count);
	LOG_INF("  Decryptions:          %u", stats->crypto_decrypt_count);
	LOG_INF("  Auth failures:        %u", stats->crypto_auth_failures);
	LOG_INF("  Replay attacks:       %u", stats->crypto_replay_rejected);

	/* Calculate average crypto performance */
	if (stats->crypto_encrypt_count > 0) {
		uint32_t avg_encrypt_us = (uint32_t)(stats->crypto_encrypt_time_us /
		                                      stats->crypto_encrypt_count);
		LOG_INF("  Avg encrypt time:     %u us", avg_encrypt_us);
	}
	if (stats->crypto_decrypt_count > 0) {
		uint32_t avg_decrypt_us = (uint32_t)(stats->crypto_decrypt_time_us /
		                                      stats->crypto_decrypt_count);
		LOG_INF("  Avg decrypt time:     %u us", avg_decrypt_us);
	}

	/* Security Status */
	if (stats->crypto_auth_failures == 0 && stats->crypto_replay_rejected == 0) {
		LOG_INF("  Security Status:      ALL CHECKS PASSED");
	} else {
		LOG_WRN("  Security Status:      THREATS DETECTED!");
	}

	LOG_INF("========================================");
	LOG_INF("");
}
