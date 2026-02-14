/**
 * @file statistics.h
 * @brief Statistics tracking for ping/pong communication
 *
 * This module tracks various performance and security metrics
 */

#ifndef STATISTICS_H
#define STATISTICS_H

#include "../app_config.h"

/**
 * @brief Statistics structure
 */
struct statistics {
	/* Transmission stats */
	uint32_t tx_sent;
	uint32_t tx_failed;

	/* Reception stats */
	uint32_t rx_received;
	uint32_t rx_timeout;
	uint32_t rx_error;

	/* Round-trip time (PING mode only) */
	uint32_t rtt_min_ms;
	uint32_t rtt_max_ms;
	uint64_t rtt_sum_ms;

	/* RF quality */
	int16_t rssi_min;
	int16_t rssi_max;
	int64_t rssi_sum;
	int8_t snr_min;
	int8_t snr_max;
	int64_t snr_sum;

	/* Cryptography stats */
	uint32_t crypto_encrypt_count;
	uint32_t crypto_decrypt_count;
	uint32_t crypto_auth_failures;
	uint32_t crypto_replay_rejected;
	uint64_t crypto_encrypt_time_us;
	uint64_t crypto_decrypt_time_us;
};

/**
 * @brief Initialize statistics
 */
void statistics_init(struct statistics *stats);

/**
 * @brief Update RF quality statistics
 */
void statistics_update_rf(struct statistics *stats, int16_t rssi, int8_t snr);

/**
 * @brief Update RTT statistics
 */
void statistics_update_rtt(struct statistics *stats, uint32_t rtt_ms);

/**
 * @brief Display final statistics report
 */
void statistics_display(const struct statistics *stats, board_role_t role);

#endif /* STATISTICS_H */
