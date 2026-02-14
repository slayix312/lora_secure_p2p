/**
 * @file security.h
 * @brief Security validation and replay protection
 *
 * This module provides security checks for received messages including:
 * - Device identity verification
 * - Replay attack detection
 * - Message counter management
 */

#ifndef SECURITY_H
#define SECURITY_H

#include "../app_config.h"

/**
 * @brief Peer state for security tracking
 */
struct peer_state {
	uint16_t device_id;        /**< Expected peer device ID */
	uint32_t last_rx_counter;  /**< Last received message counter */
	bool initialized;          /**< Peer state initialized after first message */
};

/**
 * @brief Initialize peer state
 *
 * @param peer Pointer to peer state structure
 * @param expected_device_id Expected peer device ID
 */
void security_peer_init(struct peer_state *peer, uint16_t expected_device_id);

/**
 * @brief Validate message security
 *
 * Performs security checks on received messages:
 * 1. Verify sender_id matches expected peer
 * 2. Check msg_counter for replay protection
 *
 * This function validates only. Counter state must be committed with
 * security_commit_message() after payload authentication succeeds.
 *
 * @param peer Pointer to peer state
 * @param sender_id Sender device ID from message
 * @param msg_counter Message counter from message
 * @return APP_OK if valid
 * @return APP_ERR_PROTOCOL_DEVICE_ID_MISMATCH if device ID doesn't match
 * @return APP_ERR_PROTOCOL_REPLAY_ATTACK if replay detected
 */
int security_validate_message(struct peer_state *peer,
                              uint16_t sender_id,
                              uint32_t msg_counter);

/**
 * @brief Commit a validated/authenticated message counter
 *
 * @param peer Pointer to peer state
 * @param msg_counter Authenticated message counter from message
 * @return APP_OK on success
 * @return APP_ERR_INVALID_PARAM if parameters are invalid
 */
int security_commit_message(struct peer_state *peer, uint32_t msg_counter);

/**
 * @brief Check if message counter is approaching rollover
 *
 * @param counter Current message counter value
 * @return true if counter is within warning threshold of UINT32_MAX
 * @return false if counter has sufficient remaining values
 */
bool security_counter_approaching_rollover(uint32_t counter);

#endif /* SECURITY_H */
