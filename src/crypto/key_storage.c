/**
 * @file key_storage.c
 * @brief Persistent key storage stub implementation
 *
 * NOTE: This is a placeholder for Phase 3 implementation.
 * Persistent storage is currently disabled.
 */

#include "key_storage.h"

LOG_MODULE_REGISTER(key_storage, LOG_LEVEL_CRYPTO);

int key_storage_init(void)
{
#if ENABLE_PERSISTENT_STORAGE
	LOG_INF("Initializing persistent key storage...");
	/* TODO: Phase 3 - Implement ITS/KMU initialization */
	LOG_WRN("Persistent storage not yet implemented");
	return APP_ERR_STORAGE_INIT;
#else
	LOG_DBG("Persistent storage disabled (using volatile keys)");
	return APP_OK;
#endif
}

int key_storage_save(key_type_t key_type, psa_key_id_t key_handle)
{
#if ENABLE_PERSISTENT_STORAGE
	LOG_INF("Saving key (type=%d, handle=%u)...", key_type, key_handle);
	/* TODO: Phase 3 - Implement key save to ITS/KMU */
	LOG_WRN("Persistent storage not yet implemented");
	return APP_ERR_STORAGE_WRITE;
#else
	(void)key_type;
	(void)key_handle;
	LOG_DBG("Persistent storage disabled - keys are volatile");
	return APP_OK;
#endif
}

int key_storage_load(key_type_t key_type, psa_key_id_t *key_handle)
{
#if ENABLE_PERSISTENT_STORAGE
	LOG_INF("Loading key (type=%d)...", key_type);
	/* TODO: Phase 3 - Implement key load from ITS/KMU */
	LOG_WRN("Persistent storage not yet implemented");
	return APP_ERR_STORAGE_NOT_FOUND;
#else
	(void)key_type;
	(void)key_handle;
	LOG_DBG("Persistent storage disabled");
	return APP_ERR_STORAGE_NOT_FOUND;
#endif
}

int key_storage_delete(key_type_t key_type)
{
#if ENABLE_PERSISTENT_STORAGE
	LOG_INF("Deleting key (type=%d)...", key_type);
	/* TODO: Phase 3 - Implement key delete from ITS/KMU */
	LOG_WRN("Persistent storage not yet implemented");
	return APP_ERR_STORAGE_NOT_FOUND;
#else
	(void)key_type;
	LOG_DBG("Persistent storage disabled");
	return APP_OK;
#endif
}

bool key_storage_exists(key_type_t key_type)
{
#if ENABLE_PERSISTENT_STORAGE
	/* TODO: Phase 3 - Check if key exists in ITS/KMU */
	(void)key_type;
	return false;
#else
	(void)key_type;
	return false;
#endif
}
