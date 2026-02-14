/**
 * @file main.c
 * @brief LoRa Encrypted P2P Communication - Main Application
 *
 * XIAO nRF54L15 + Wio-SX1262 (US 915 MHz)
 * Refactored architecture with modular design for maintainability and scalability
 *
 * Board Role: Set via BOARD_ROLE in app_config.h or CMake build flag
 * - ROLE_PING: Initiator - sends pings, measures RTT
 * - ROLE_PONG: Responder - receives pings, sends pongs
 */

#include "app_config.h"
#include "crypto/crypto_init.h"
#include "crypto/aes_ccm.h"
#include "crypto/ecdh.h"
#include "crypto/key_storage.h"
#include "protocol/message.h"
#include "protocol/security.h"
#include "protocol/statistics.h"
#include "lora/lora_hal.h"
#include "lora/lora_transport.h"
#include "app/ping_mode.h"
#include "app/pong_mode.h"

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

/* Global contexts */
static struct crypto_context crypto_ctx;
static struct ecdh_context ecdh_ctx;
static struct peer_state peer;
static struct statistics stats;
static struct app_context app_ctx;

#if ENABLE_ECDH_KEY_EXCHANGE
/**
 * @brief Perform ECDH key exchange with peer device
 *
 * @param lora_dev LoRa device handle
 * @return APP_OK on success
 * @return APP_ERR_* on failure
 */
static int perform_key_exchange(const struct device *lora_dev)
{
	struct key_exchange_message kex_msg;
	int ret;
	int16_t rssi;
	int8_t snr;

	LOG_INF("==================================================");
	LOG_INF("  ECDH KEY EXCHANGE (X25519 + HKDF-SHA256)");
#if ENABLE_PSK_AUTHENTICATION
	LOG_INF("  WITH PSK AUTHENTICATION (MITM PROTECTION)");
#else
	LOG_WRN("  NO AUTHENTICATION - VULNERABLE TO MITM!");
#endif
	LOG_INF("==================================================");
	LOG_INF("");

#if BOARD_ROLE == ROLE_PING
	/* PING: Announce our public key */
	LOG_INF("PING: Waiting 3 seconds to allow PONG to enter RX mode...");
	k_sleep(K_SECONDS(3));

	LOG_INF("PING: Announcing public key...");

	ret = message_create_key_exchange(&ecdh_ctx, MSG_TYPE_KEY_ANNOUNCE,
	                                  crypto_ctx.local_device_id, &kex_msg);
	if (ret != APP_OK) {
		LOG_ERR("Failed to create key exchange message: %d", ret);
		return ret;
	}

	ret = lora_transport_send(lora_dev, (uint8_t *)&kex_msg, sizeof(kex_msg));
	if (ret != APP_OK) {
		LOG_ERR("Failed to send KEY_ANNOUNCE: %d", ret);
		return ret;
	}

	LOG_INF("  KEY_ANNOUNCE sent (%u bytes)", sizeof(kex_msg));

	/* Wait for KEY_ACK from PONG */
	LOG_INF("  Waiting for KEY_ACK from peer...");

	ret = lora_transport_recv(lora_dev, (uint8_t *)&kex_msg, sizeof(kex_msg),
	                         K_MSEC(KEY_EXCHANGE_TIMEOUT_MS), &rssi, &snr);
	if (ret < 0) {
		LOG_ERR("Failed to receive KEY_ACK: %d", ret);
		return ret;
	}
	if (ret != (int)sizeof(kex_msg)) {
		LOG_ERR("Invalid KEY_ACK length: %d (expected %zu)", ret, sizeof(kex_msg));
		return APP_ERR_PROTOCOL_INVALID_MSG;
	}

	if (kex_msg.type != MSG_TYPE_KEY_ACK) {
		LOG_ERR("Expected KEY_ACK, got type 0x%02X", kex_msg.type);
		return APP_ERR_PROTOCOL_INVALID_TYPE;
	}

	LOG_INF("  KEY_ACK received from device 0x%04X", kex_msg.sender_id);

	ret = message_parse_key_exchange(&ecdh_ctx, &kex_msg);
	if (ret != APP_OK) {
		LOG_ERR("Key exchange validation failed: %d", ret);
		return ret;
	}

	/* Store peer's public key and derive session key */
	ret = ecdh_set_peer_public_key(&ecdh_ctx, kex_msg.public_key);
	if (ret != APP_OK) {
		return ret;
	}

	ret = ecdh_derive_session_key(&ecdh_ctx);
	if (ret != APP_OK) {
		return ret;
	}

#else /* ROLE_PONG */
	/* PONG: Wait for KEY_ANNOUNCE */
	LOG_INF("PONG: Listening for KEY_ANNOUNCE...");

	k_sleep(K_MSEC(100));  /* Small delay to ensure RX mode is active */
	LOG_INF("  RX mode active, waiting for packet...");

	ret = lora_transport_recv(lora_dev, (uint8_t *)&kex_msg, sizeof(kex_msg),
	                         K_MSEC(30000), &rssi, &snr);
	if (ret < 0) {
		LOG_ERR("Failed to receive KEY_ANNOUNCE: %d", ret);
		return ret;
	}
	if (ret != (int)sizeof(kex_msg)) {
		LOG_ERR("Invalid KEY_ANNOUNCE length: %d (expected %zu)", ret, sizeof(kex_msg));
		return APP_ERR_PROTOCOL_INVALID_MSG;
	}

	if (kex_msg.type != MSG_TYPE_KEY_ANNOUNCE) {
		LOG_ERR("Expected KEY_ANNOUNCE, got type 0x%02X", kex_msg.type);
		return APP_ERR_PROTOCOL_INVALID_TYPE;
	}

	LOG_INF("  KEY_ANNOUNCE received from device 0x%04X", kex_msg.sender_id);

	ret = message_parse_key_exchange(&ecdh_ctx, &kex_msg);
	if (ret != APP_OK) {
		LOG_ERR("Key exchange validation failed: %d", ret);
		return ret;
	}

	/* Store peer's public key and derive session key */
	ret = ecdh_set_peer_public_key(&ecdh_ctx, kex_msg.public_key);
	if (ret != APP_OK) {
		return ret;
	}

	ret = ecdh_derive_session_key(&ecdh_ctx);
	if (ret != APP_OK) {
		return ret;
	}

	/* Send KEY_ACK with our public key */
	LOG_INF("  Sending KEY_ACK...");

	ret = message_create_key_exchange(&ecdh_ctx, MSG_TYPE_KEY_ACK,
	                                  crypto_ctx.local_device_id, &kex_msg);
	if (ret != APP_OK) {
		LOG_ERR("Failed to create KEY_ACK: %d", ret);
		return ret;
	}

	ret = lora_transport_send(lora_dev, (uint8_t *)&kex_msg, sizeof(kex_msg));
	if (ret != APP_OK) {
		LOG_ERR("Failed to send KEY_ACK: %d", ret);
		return ret;
	}

	LOG_INF("  KEY_ACK sent (%u bytes)", sizeof(kex_msg));
#endif

	/* Get session key handle and set it in crypto context */
	psa_key_id_t session_key_handle;
	ret = ecdh_get_session_key_handle(&ecdh_ctx, &session_key_handle);
	if (ret != APP_OK) {
		LOG_ERR("Failed to get session key: %d", ret);
		return ret;
	}

	ret = crypto_set_session_key(&crypto_ctx, session_key_handle);
	if (ret != APP_OK) {
		LOG_ERR("Failed to set session key: %d", ret);
		return ret;
	}

	/*
	 * Session key handle is now owned by crypto_ctx.
	 * Drop ECDH private key and auth PSK to reduce key exposure in memory.
	 */
	ret = ecdh_cleanup_exchange_material(&ecdh_ctx);
	if (ret != APP_OK) {
		LOG_ERR("Failed to cleanup ECDH exchange material: %d", ret);
		return ret;
	}

	LOG_INF("");
	LOG_INF("Key exchange complete!");
	LOG_INF("  ECDH shared secret computed");
	LOG_INF("  Session key derived (AES-128)");
#if ENABLE_PSK_AUTHENTICATION
	LOG_INF("  Peer authenticated via HMAC-SHA256");
#endif
	LOG_INF("==================================================");
	LOG_INF("");

	return APP_OK;
}
#endif /* ENABLE_ECDH_KEY_EXCHANGE */

int main(void)
{
	int ret;
	const struct device *lora_dev = DEFAULT_RADIO;

	/* Display banner */
	LOG_INF("===========================================");
	LOG_INF("  LoRa Encrypted P2P Communication");
	LOG_INF("  XIAO nRF54L15 + Wio-SX1262");
#if BOARD_ROLE == ROLE_PING
	LOG_INF("  Mode: PING (Initiator)");
	const uint16_t local_device_id = DEVICE_ID_PING;
	const uint16_t peer_device_id = DEVICE_ID_PONG;
#else
	LOG_INF("  Mode: PONG (Responder)");
	const uint16_t local_device_id = DEVICE_ID_PONG;
	const uint16_t peer_device_id = DEVICE_ID_PING;
#endif
	LOG_INF("  Device ID: 0x%04X", local_device_id);
	LOG_INF("  Peer ID: 0x%04X", peer_device_id);
	LOG_INF("  Frequency: 915 MHz (US Band)");
	LOG_INF("  Power: +%d dBm", LORA_TX_POWER);
	LOG_INF("  Encryption: AES-128-CCM (CRACEN accelerated)");
	LOG_INF("===========================================");
	LOG_INF("");

	/* Initialize crypto subsystem */
	LOG_INF("Initializing cryptography...");
	ret = crypto_init();
	if (ret != APP_OK) {
		LOG_ERR("Crypto initialization failed: %d", ret);
		return ret;
	}

	/* Initialize crypto context */
	crypto_context_init(&crypto_ctx, local_device_id);

	/* Initialize peer state */
	security_peer_init(&peer, peer_device_id);

	/* Initialize statistics */
	statistics_init(&stats);

#if ENABLE_ECDH_KEY_EXCHANGE
	/* Initialize ECDH context and generate keypair */
	ecdh_context_init(&ecdh_ctx);

	ret = ecdh_generate_keypair(&ecdh_ctx);
	if (ret != APP_OK) {
		LOG_ERR("Keypair generation failed: %d", ret);
		return ret;
	}
	LOG_INF("");

#if ENABLE_PSK_AUTHENTICATION
	/* Import authentication PSK for MITM protection */
	static const uint8_t auth_psk[HMAC_KEY_SIZE_BYTES] = APP_AUTH_PSK_BYTES;
#if defined(APP_AUTH_PSK_IS_DEFAULT_TEST_KEY)
	LOG_WRN("*** USING DEFAULT HARD-CODED TEST PSK ***");
	LOG_WRN("*** FOR LAB TESTING ONLY - NOT FOR PRODUCTION ***");
#else
	LOG_INF("Using externally provisioned authentication PSK");
#endif

	ret = ecdh_import_auth_psk(&ecdh_ctx, auth_psk, sizeof(auth_psk));
	if (ret != APP_OK) {
		LOG_ERR("Auth PSK import failed: %d", ret);
		return ret;
	}
	LOG_INF("");
#endif
#endif /* ENABLE_ECDH_KEY_EXCHANGE */

	/* Initialize LoRa hardware */
	ret = lora_hal_init(lora_dev);
	if (ret != APP_OK) {
		LOG_ERR("LoRa initialization failed: %d", ret);
		return ret;
	}
	LOG_INF("");

#if ENABLE_ECDH_KEY_EXCHANGE
	/* Perform ECDH key exchange with retry logic */
	for (int attempt = 1; attempt <= KEY_EXCHANGE_MAX_RETRIES; attempt++) {
		LOG_INF("Key exchange attempt %d/%d...", attempt, KEY_EXCHANGE_MAX_RETRIES);
		LOG_INF("");

		ret = perform_key_exchange(lora_dev);
		if (ret == APP_OK) {
			LOG_INF("Key exchange successful!");
			break;
		}

		LOG_WRN("Key exchange failed: %d", ret);
		if (attempt < KEY_EXCHANGE_MAX_RETRIES) {
			LOG_INF("Retrying in 2 seconds...");
			LOG_INF("");
			k_sleep(K_SECONDS(2));
		}
	}

	if (ret != APP_OK) {
		LOG_ERR("Key exchange failed after %d attempts", KEY_EXCHANGE_MAX_RETRIES);
		return ret;
	}

	/* Small delay before starting ping/pong */
	k_sleep(K_MSEC(500));
#endif

	/* Setup application context */
	app_ctx.lora_dev = lora_dev;
	app_ctx.crypto_ctx = &crypto_ctx;
	app_ctx.peer = &peer;
	app_ctx.stats = &stats;
	app_ctx.device_id = local_device_id;

	/* Run appropriate mode */
#if BOARD_ROLE == ROLE_PING
	ret = ping_mode_run(&app_ctx);
#else
	ret = pong_mode_run(&app_ctx);
#endif

	if (ret != APP_OK) {
		LOG_ERR("Application mode failed: %d", ret);
	}

	/* Test session is complete; destroy remaining key material. */
#if ENABLE_ECDH_KEY_EXCHANGE
	(void)ecdh_cleanup(&ecdh_ctx);
#endif

	/* Test complete - enter idle loop */
	LOG_INF("Test complete. System idle.");
	while (1) {
		k_sleep(K_FOREVER);
	}

	return 0;
}
