/**
 * @file key_storage.h
 * @brief Persistent key storage using ITS/KMU
 *
 * This module provides persistent storage for cryptographic keys using:
 * - Internal Trusted Storage (ITS) with HUK encryption
 * - Key Management Unit (KMU) for hardware-protected storage
 *
 * NOTE: This is a placeholder for Phase 3 implementation.
 * Currently returns "not implemented" errors.
 */

#ifndef KEY_STORAGE_H
#define KEY_STORAGE_H

#include "../app_config.h"

/**
 * @brief Key types for storage
 */
typedef enum {
	KEY_TYPE_SESSION,      /**< AES session key */
	KEY_TYPE_ECDH_PRIVATE, /**< ECDH private key */
	KEY_TYPE_AUTH_PSK,     /**< Authentication PSK */
} key_type_t;

/**
 * @brief Initialize key storage subsystem
 *
 * Initializes ITS/KMU storage for cryptographic keys.
 *
 * @return APP_OK on success
 * @return APP_ERR_STORAGE_INIT on initialization failure
 *
 * @note This is a Phase 3 feature - currently not implemented
 */
int key_storage_init(void);

/**
 * @brief Save a key to persistent storage
 *
 * Stores a cryptographic key handle in persistent storage (ITS or KMU).
 * The key survives reboots and can be loaded later.
 *
 * @param key_type Type of key to store
 * @param key_handle PSA key handle to save
 * @return APP_OK on success
 * @return APP_ERR_STORAGE_WRITE on write failure
 *
 * @note This is a Phase 3 feature - currently not implemented
 */
int key_storage_save(key_type_t key_type, psa_key_id_t key_handle);

/**
 * @brief Load a key from persistent storage
 *
 * Loads a previously stored cryptographic key from persistent storage.
 *
 * @param key_type Type of key to load
 * @param key_handle Output: PSA key handle for loaded key
 * @return APP_OK on success
 * @return APP_ERR_STORAGE_NOT_FOUND if key doesn't exist
 * @return APP_ERR_STORAGE_READ on read failure
 *
 * @note This is a Phase 3 feature - currently not implemented
 */
int key_storage_load(key_type_t key_type, psa_key_id_t *key_handle);

/**
 * @brief Delete a key from persistent storage
 *
 * Removes a key from persistent storage.
 *
 * @param key_type Type of key to delete
 * @return APP_OK on success
 * @return APP_ERR_STORAGE_NOT_FOUND if key doesn't exist
 *
 * @note This is a Phase 3 feature - currently not implemented
 */
int key_storage_delete(key_type_t key_type);

/**
 * @brief Check if a key exists in persistent storage
 *
 * @param key_type Type of key to check
 * @return true if key exists
 * @return false if key doesn't exist
 *
 * @note This is a Phase 3 feature - currently returns false
 */
bool key_storage_exists(key_type_t key_type);

#endif /* KEY_STORAGE_H */
