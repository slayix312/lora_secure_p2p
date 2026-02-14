/**
 * @file ping_mode.h
 * @brief PING mode (initiator) application logic
 *
 * This module implements the PING device behavior:
 * - Sends ping messages
 * - Waits for pong responses
 * - Measures round-trip time
 * - Tracks statistics
 */

#ifndef PING_MODE_H
#define PING_MODE_H

#include "../app_config.h"
#include "app_context.h"
#include "../crypto/aes_ccm.h"
#include "../protocol/message.h"
#include "../protocol/security.h"
#include "../protocol/statistics.h"
#include "../lora/lora_transport.h"

/**
 * @brief Run ping mode
 *
 * Executes the ping mode loop:
 * - Sends PING_COUNT encrypted ping messages
 * - Waits for pong response after each ping
 * - Measures RTT and RF quality
 * - Displays final statistics
 *
 * @param ctx Application context
 * @return APP_OK on success
 * @return APP_ERR_* on failure
 */
int ping_mode_run(struct app_context *ctx);

#endif /* PING_MODE_H */
