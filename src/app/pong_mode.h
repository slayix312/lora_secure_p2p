/**
 * @file pong_mode.h
 * @brief PONG mode (responder) application logic
 *
 * This module implements the PONG device behavior:
 * - Listens for ping messages
 * - Responds with pong messages
 * - Tracks statistics
 */

#ifndef PONG_MODE_H
#define PONG_MODE_H

#include "../app_config.h"
#include "app_context.h"
#include "../crypto/aes_ccm.h"
#include "../protocol/message.h"
#include "../protocol/security.h"
#include "../protocol/statistics.h"
#include "../lora/lora_transport.h"

/**
 * @brief Run pong mode
 *
 * Executes the pong mode loop:
 * - Listens for encrypted ping messages
 * - Validates and decrypts each ping
 * - Responds with encrypted pong
 * - Displays final statistics after PING_COUNT exchanges
 *
 * @param ctx Application context
 * @return APP_OK on success
 * @return APP_ERR_* on failure
 */
int pong_mode_run(struct app_context *ctx);

#endif /* PONG_MODE_H */
