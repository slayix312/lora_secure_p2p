/**
 * @file app_context.h
 * @brief Shared application context for ping/pong modes
 */

#ifndef APP_CONTEXT_H
#define APP_CONTEXT_H

#include "../app_config.h"

/* Forward declarations to avoid heavy include coupling */
struct crypto_context;
struct peer_state;
struct statistics;

/**
 * @brief Application context shared by PING and PONG modes
 */
struct app_context {
	const struct device *lora_dev;      /**< LoRa device */
	struct crypto_context *crypto_ctx;  /**< Crypto context */
	struct peer_state *peer;            /**< Peer tracking */
	struct statistics *stats;           /**< Statistics */
	uint16_t device_id;                 /**< Local device ID */
};

#endif /* APP_CONTEXT_H */
