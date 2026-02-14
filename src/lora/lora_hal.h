/**
 * @file lora_hal.h
 * @brief LoRa Hardware Abstraction Layer
 *
 * Provides a thin wrapper around the Zephyr LoRa driver
 */

#ifndef LORA_HAL_H
#define LORA_HAL_H

#include "../app_config.h"
#include <zephyr/drivers/lora.h>

/**
 * @brief Initialize LoRa hardware
 *
 * @param lora_dev LoRa device pointer
 * @return APP_OK on success
 * @return APP_ERR_LORA_INIT if device not ready
 */
int lora_hal_init(const struct device *lora_dev);

/**
 * @brief Configure LoRa modem for TX
 *
 * @param lora_dev LoRa device pointer
 * @return APP_OK on success
 * @return APP_ERR_LORA_CONFIG on failure
 */
int lora_hal_config_tx(const struct device *lora_dev);

/**
 * @brief Configure LoRa modem for RX
 *
 * @param lora_dev LoRa device pointer
 * @return APP_OK on success
 * @return APP_ERR_LORA_CONFIG on failure
 */
int lora_hal_config_rx(const struct device *lora_dev);

/**
 * @brief Send data over LoRa
 *
 * @param lora_dev LoRa device pointer
 * @param data Data to send
 * @param len Length of data
 * @return APP_OK on success
 * @return APP_ERR_LORA_TX on failure
 */
int lora_hal_send(const struct device *lora_dev, const uint8_t *data, size_t len);

/**
 * @brief Receive data over LoRa
 *
 * @param lora_dev LoRa device pointer
 * @param data Buffer for received data
 * @param max_len Maximum buffer size
 * @param timeout Timeout for reception
 * @param rssi Output: RSSI value
 * @param snr Output: SNR value
 * @return Number of bytes received on success
 * @return APP_ERR_LORA_RX on failure
 * @return APP_ERR_LORA_TIMEOUT on timeout
 */
int lora_hal_recv(const struct device *lora_dev, uint8_t *data, size_t max_len,
                  k_timeout_t timeout, int16_t *rssi, int8_t *snr);

#endif /* LORA_HAL_H */
