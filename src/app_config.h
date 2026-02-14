/**
 * @file app_config.h
 * @brief Central configuration and common definitions for LoRa P2P Secure Communication
 *
 * This header provides:
 * - Application-wide configuration constants
 * - Error code definitions
 * - Board role definitions
 * - Common includes
 * - Feature flags
 *
 * @note This file should be included by all source files in the project
 */

#ifndef APP_CONFIG_H
#define APP_CONFIG_H

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>

/* ============================================================================
 * Error Code Definitions
 * ============================================================================ */

/**
 * @brief Application error codes
 *
 * All functions return 0 on success, negative values on error.
 * Error codes are organized by subsystem for easier debugging.
 */
typedef enum {
	/* Success */
	APP_OK = 0,

	/* Generic errors (-1 to -99) */
	APP_ERR_GENERIC = -1,
	APP_ERR_INVALID_PARAM = -2,
	APP_ERR_NULL_POINTER = -3,
	APP_ERR_TIMEOUT = -4,
	APP_ERR_NOT_READY = -5,

	/* Cryptography errors (-1000 to -1099) */
	APP_ERR_CRYPTO = -1000,
	APP_ERR_CRYPTO_INIT = -1001,
	APP_ERR_CRYPTO_ENCRYPT = -1002,
	APP_ERR_CRYPTO_DECRYPT = -1003,
	APP_ERR_CRYPTO_AUTH_FAILED = -1004,
	APP_ERR_CRYPTO_KEY_GEN = -1005,
	APP_ERR_CRYPTO_KEY_IMPORT = -1006,
	APP_ERR_CRYPTO_KEY_EXPORT = -1007,
	APP_ERR_CRYPTO_DERIVE = -1008,
	APP_ERR_CRYPTO_HMAC = -1009,

	/* LoRa/Radio errors (-2000 to -2099) */
	APP_ERR_LORA = -2000,
	APP_ERR_LORA_INIT = -2001,
	APP_ERR_LORA_CONFIG = -2002,
	APP_ERR_LORA_TX = -2003,
	APP_ERR_LORA_RX = -2004,
	APP_ERR_LORA_TIMEOUT = -2005,
	APP_ERR_LORA_BUSY = -2006,

	/* Protocol errors (-3000 to -3099) */
	APP_ERR_PROTOCOL = -3000,
	APP_ERR_PROTOCOL_INVALID_MSG = -3001,
	APP_ERR_PROTOCOL_INVALID_TYPE = -3002,
	APP_ERR_PROTOCOL_INVALID_VERSION = -3003,
	APP_ERR_PROTOCOL_REPLAY_ATTACK = -3004,
	APP_ERR_PROTOCOL_DEVICE_ID_MISMATCH = -3005,
	APP_ERR_PROTOCOL_COUNTER_ROLLOVER = -3006,

	/* Key storage errors (-4000 to -4099) */
	APP_ERR_STORAGE = -4000,
	APP_ERR_STORAGE_INIT = -4001,
	APP_ERR_STORAGE_READ = -4002,
	APP_ERR_STORAGE_WRITE = -4003,
	APP_ERR_STORAGE_NOT_FOUND = -4004,
	APP_ERR_STORAGE_CORRUPTED = -4005,
} app_error_t;

/* ============================================================================
 * Board Role Configuration
 * ============================================================================ */

/**
 * @brief Device role in P2P communication (Preprocessor-compatible definitions)
 *
 * NOTE: These must be #define macros (not enum) to work with preprocessor conditionals (#if).
 * The C preprocessor cannot see enum values - they are replaced with 0 during preprocessing,
 * causing both PING and PONG builds to compile identical code.
 */
#define ROLE_PING  1  /**< Initiator - sends pings, receives pongs */
#define ROLE_PONG  2  /**< Responder - receives pings, sends pongs */

/**
 * @brief Optional enum for runtime type safety
 *
 * This enum provides type checking for runtime code while maintaining
 * preprocessor compatibility via the #define macros above.
 */
typedef enum {
	BOARD_ROLE_PING = ROLE_PING,  /**< Initiator role (value: 1) */
	BOARD_ROLE_PONG = ROLE_PONG,  /**< Responder role (value: 2) */
} board_role_t;

/**
 * @brief Current board role
 *
 * Set via CMake build configuration:
 * -DBOARD_ROLE=1 (PING) or -DBOARD_ROLE=2 (PONG)
 * -DBOARD_ROLE=ROLE_PING or -DBOARD_ROLE=ROLE_PONG (converted by CMake)
 *
 * Defaults to PONG if not specified at build time.
 */
#ifndef BOARD_ROLE
#define BOARD_ROLE  ROLE_PONG   /* Default role if not specified at build time */
#endif

/**
 * @brief Compile-time validation of BOARD_ROLE
 *
 * This check ensures BOARD_ROLE is set to a valid value at compile time.
 * Without this, incorrect values would cause silent failures.
 */
#if (BOARD_ROLE != ROLE_PING) && (BOARD_ROLE != ROLE_PONG)
#error "BOARD_ROLE must be either ROLE_PING (1) or ROLE_PONG (2)"
#endif

/* ============================================================================
 * Device Identity Configuration
 * ============================================================================ */

/**
 * @brief Device IDs for P2P communication
 *
 * Each device in the network must have a unique ID.
 * These IDs are used for message routing and security validation.
 */
#define DEVICE_ID_PING   0x0001  /**< Device ID for PING board */
#define DEVICE_ID_PONG   0x0002  /**< Device ID for PONG board */

/* ============================================================================
 * Feature Flags
 * ============================================================================ */

/**
 * @brief Enable ECDH key exchange
 *
 * When enabled: Uses X25519 ECDH for session key derivation (forward secrecy)
 * When disabled: Falls back to PSK mode (for testing/legacy compatibility)
 */
#ifndef ENABLE_ECDH_KEY_EXCHANGE
#define ENABLE_ECDH_KEY_EXCHANGE  1  /* Enabled by default */
#endif

/**
 * @brief Enable PSK authentication for key exchange
 *
 * When enabled: HMAC-SHA256 authentication prevents MITM attacks during key exchange
 * When disabled: Key exchange is unauthenticated (vulnerable to MITM)
 *
 * @note Only relevant when ENABLE_ECDH_KEY_EXCHANGE is enabled
 */
#ifndef ENABLE_PSK_AUTHENTICATION
#define ENABLE_PSK_AUTHENTICATION  1  /* Enabled by default */
#endif

/**
 * @brief Authentication PSK bytes for ECDH message authentication
 *
 * DEFAULT: hardcoded test key for lab bring-up only.
 *
 * For real deployments, override via build flag:
 *   -DAPP_AUTH_PSK_BYTES='{0x.., ... 32 bytes ...}'
 */
#ifndef APP_AUTH_PSK_BYTES
#define APP_AUTH_PSK_BYTES \
	{ \
		0xFB, 0x9C, 0x81, 0x30, 0x29, 0xEF, 0x2A, 0xBD, \
		0x6E, 0xBC, 0x7E, 0xA6, 0x90, 0x8A, 0x9F, 0x2C, \
		0x77, 0xFA, 0x97, 0x27, 0x5E, 0x6D, 0xE3, 0x68, \
		0x38, 0xF6, 0xFE, 0x46, 0xB9, 0x4B, 0x2D, 0xA9 \
	}
#define APP_AUTH_PSK_IS_DEFAULT_TEST_KEY 1
#endif

/**
 * @brief Enable persistent key storage
 *
 * When enabled: Keys stored in ITS/KMU (survive reboots)
 * When disabled: Volatile keys (lost on reboot, must re-exchange)
 */
#ifndef ENABLE_PERSISTENT_STORAGE
#define ENABLE_PERSISTENT_STORAGE  0  /* Disabled by default (Phase 3 feature) */
#endif

/* ============================================================================
 * Application Parameters
 * ============================================================================ */

/**
 * @brief Ping/Pong test parameters
 */
#define PING_COUNT          100     /**< Number of ping/pong exchanges to perform */
#define PING_INTERVAL_MS    1000    /**< Delay between pings (milliseconds) */
#define PONG_TIMEOUT_MS     3000    /**< How long to wait for pong response (milliseconds) */

/**
 * @brief Key exchange timeout
 */
#define KEY_EXCHANGE_TIMEOUT_MS  10000  /**< Timeout for key exchange handshake (10 seconds) */
#define KEY_EXCHANGE_MAX_RETRIES 3      /**< Maximum key exchange retry attempts */

/**
 * @brief Counter rollover warning threshold
 *
 * When message counter approaches UINT32_MAX, we need to re-key to avoid
 * nonce reuse (which would break AES-CCM security).
 */
#define COUNTER_ROLLOVER_WARNING_THRESHOLD  1000  /**< Warn when counter has 1000 remaining */

/* ============================================================================
 * LoRa Configuration
 * ============================================================================ */

/**
 * @brief LoRa device from device tree
 */
#define DEFAULT_RADIO_NODE DT_ALIAS(lora0)
#define DEFAULT_RADIO DEVICE_DT_GET(DEFAULT_RADIO_NODE)

/**
 * @brief LoRa RF parameters for US 915 MHz band
 */
#define LORA_FREQUENCY      915000000   /**< 915 MHz center frequency */
#define LORA_BANDWIDTH      BW_125_KHZ  /**< 125 kHz bandwidth */
#define LORA_DATARATE       SF_7        /**< Spreading Factor 7 (fastest) */
#define LORA_CODING_RATE    CR_4_5      /**< Coding rate 4/5 */
#define LORA_PREAMBLE_LEN   8           /**< 8 symbol preamble */
#define LORA_TX_POWER       22          /**< +22 dBm output power (maximum) */

/* ============================================================================
 * Protocol Configuration
 * ============================================================================ */

/**
 * @brief Protocol version
 *
 * Version 2: Current protocol with explicit versioning and extensibility flags.
 * Older protocol versions are intentionally rejected by message parsers.
 */
#define PROTOCOL_VERSION   0x02   /**< Current protocol version */

/**
 * @brief Message Types
 */
#define MSG_TYPE_PING          0x50  /**< 'P' - Encrypted ping message */
#define MSG_TYPE_PONG          0x4F  /**< 'O' - Encrypted pong response */
#define MSG_TYPE_KEY_ANNOUNCE  0xA0  /**< Public key announcement */
#define MSG_TYPE_KEY_ACK       0xA1  /**< Key acknowledgment */
#define MSG_TYPE_REKEY         0xA2  /**< Key rotation request (planned for Phase 3) */

/**
 * @brief Message flags (for protocol v2)
 */
#define MSG_FLAG_ENCRYPTED     (1 << 0)  /**< Message payload is encrypted */
#define MSG_FLAG_AUTHENTICATED (1 << 1)  /**< Message includes HMAC authentication */
#define MSG_FLAG_REKEY_REQUEST (1 << 2)  /**< Sender requests key rotation */

/* ============================================================================
 * Cryptography Configuration
 * ============================================================================ */

/**
 * @brief AES-CCM parameters
 */
#define AES_CCM_NONCE_SIZE    12  /**< 96-bit nonce (CCM standard) */
#define AES_CCM_TAG_SIZE      16  /**< 128-bit authentication tag */
#define AES_KEY_SIZE_BITS     128 /**< 128-bit AES key */
#define AES_KEY_SIZE_BYTES    16  /**< 128-bit = 16 bytes */

/**
 * @brief ECDH parameters
 */
#define ECDH_PUBLIC_KEY_SIZE  32  /**< X25519 public key size (32 bytes) */
#define ECDH_PRIVATE_KEY_BITS 255 /**< Curve25519 = 255 bits */

/**
 * @brief HMAC parameters
 */
#define HMAC_KEY_SIZE_BITS    256 /**< 256-bit HMAC key */
#define HMAC_KEY_SIZE_BYTES   32  /**< 256-bit = 32 bytes */
#define HMAC_TAG_SIZE         32  /**< 256-bit HMAC-SHA256 tag */

/**
 * @brief Key storage IDs (for persistent storage)
 */
#define PSA_KEY_ID_SESSION       1  /**< Session key (AES-128) */
#define PSA_KEY_ID_ECDH_PRIVATE  2  /**< ECDH private key (X25519) */
#define PSA_KEY_ID_AUTH_PSK      3  /**< Authentication PSK (HMAC) */

/* ============================================================================
 * Logging Configuration
 * ============================================================================ */

/**
 * @brief Module-specific log level control
 *
 * Can be overridden in prj.conf or via Kconfig
 */
#ifndef LOG_LEVEL_CRYPTO
#define LOG_LEVEL_CRYPTO  LOG_LEVEL_INF
#endif

#ifndef LOG_LEVEL_PROTOCOL
#define LOG_LEVEL_PROTOCOL  LOG_LEVEL_INF
#endif

#ifndef LOG_LEVEL_LORA
#define LOG_LEVEL_LORA  LOG_LEVEL_INF
#endif

/* ============================================================================
 * Compile-Time Safety Checks
 * ============================================================================ */

/* Ensure board role is valid */
#if (BOARD_ROLE != ROLE_PING) && (BOARD_ROLE != ROLE_PONG)
#error "BOARD_ROLE must be either ROLE_PING or ROLE_PONG"
#endif

/* Warn if using unauthenticated key exchange */
#if ENABLE_ECDH_KEY_EXCHANGE && !ENABLE_PSK_AUTHENTICATION
#warning "ECDH key exchange without authentication is vulnerable to MITM attacks!"
#warning "Consider enabling ENABLE_PSK_AUTHENTICATION for production use."
#endif

#if ENABLE_PSK_AUTHENTICATION && defined(APP_AUTH_PSK_IS_DEFAULT_TEST_KEY)
#warning "Using built-in DEFAULT TEST PSK. FOR LAB TESTING ONLY."
#warning "For production, override APP_AUTH_PSK_BYTES via build flags or secure provisioning."
#endif

/* Warn if using PSK fallback mode */
#if !ENABLE_ECDH_KEY_EXCHANGE
#warning "ECDH is disabled - using PSK mode (no forward secrecy)"
#warning "This is for testing/legacy compatibility only. Enable ECDH for production."
#endif

#if ENABLE_PERSISTENT_STORAGE
#warning "ENABLE_PERSISTENT_STORAGE is experimental and requires counter persistence/rekey policy."
#endif

/* ============================================================================
 * Utility Macros
 * ============================================================================ */

/**
 * @brief Convert PSA status to app error code
 */
#define PSA_TO_APP_ERROR(psa_status) \
	((psa_status) == PSA_SUCCESS ? APP_OK : APP_ERR_CRYPTO)

/**
 * @brief Check if error is a crypto error
 */
#define IS_CRYPTO_ERROR(err) \
	((err) <= APP_ERR_CRYPTO && (err) > APP_ERR_CRYPTO - 100)

/**
 * @brief Check if error is a LoRa error
 */
#define IS_LORA_ERROR(err) \
	((err) <= APP_ERR_LORA && (err) > APP_ERR_LORA - 100)

/**
 * @brief Check if error is a protocol error
 */
#define IS_PROTOCOL_ERROR(err) \
	((err) <= APP_ERR_PROTOCOL && (err) > APP_ERR_PROTOCOL - 100)

/**
 * @brief Get error category name
 */
static inline const char *app_error_category(app_error_t err)
{
	if (err == APP_OK) return "SUCCESS";
	if (IS_CRYPTO_ERROR(err)) return "CRYPTO";
	if (IS_LORA_ERROR(err)) return "LORA";
	if (IS_PROTOCOL_ERROR(err)) return "PROTOCOL";
	if (err <= APP_ERR_STORAGE && err > APP_ERR_STORAGE - 100) return "STORAGE";
	return "GENERIC";
}

#endif /* APP_CONFIG_H */
