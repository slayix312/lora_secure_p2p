/**
 * @file security.c
 * @brief Security validation implementation
 */

#include "security.h"

LOG_MODULE_REGISTER(security, LOG_LEVEL_PROTOCOL);

void security_peer_init(struct peer_state *peer, uint16_t expected_device_id)
{
	if (peer == NULL) {
		return;
	}

	peer->device_id = expected_device_id;
	peer->last_rx_counter = 0;
	peer->initialized = false;

	LOG_DBG("Peer state initialized (expected_id=0x%04X)", expected_device_id);
}

int security_validate_message(struct peer_state *peer,
                              uint16_t sender_id,
                              uint32_t msg_counter)
{
	if (peer == NULL) {
		LOG_ERR("Invalid peer state");
		return APP_ERR_INVALID_PARAM;
	}

	/* Check 1: Device Identity Verification */
	if (sender_id != peer->device_id) {
		LOG_WRN("Device ID mismatch! Got 0x%04X, expected 0x%04X",
		        sender_id, peer->device_id);
		LOG_WRN("  Possible spoofing attempt or misconfiguration!");
		return APP_ERR_PROTOCOL_DEVICE_ID_MISMATCH;
	}

	/* Check 2: Replay Protection */
	if (peer->initialized && msg_counter <= peer->last_rx_counter) {
		LOG_WRN("Replay attack detected!");
		LOG_WRN("  Received counter: %u, last valid: %u",
		        msg_counter, peer->last_rx_counter);
		return APP_ERR_PROTOCOL_REPLAY_ATTACK;
	}

	/* Check 3: Detect large counter jumps (possible desync) */
	if (peer->initialized) {
		uint32_t jump = msg_counter - peer->last_rx_counter;
		if (jump > 100) {
			LOG_WRN("Large counter jump detected: %u (may indicate packet loss)", jump);
		}
	}

	return APP_OK;
}

int security_commit_message(struct peer_state *peer, uint32_t msg_counter)
{
	if (peer == NULL) {
		LOG_ERR("Invalid peer state");
		return APP_ERR_INVALID_PARAM;
	}

	peer->last_rx_counter = msg_counter;

	if (!peer->initialized) {
		LOG_INF("Peer state initialized (first authenticated message received)");
		peer->initialized = true;
	}

	return APP_OK;
}

bool security_counter_approaching_rollover(uint32_t counter)
{
	return (counter > (UINT32_MAX - COUNTER_ROLLOVER_WARNING_THRESHOLD));
}
