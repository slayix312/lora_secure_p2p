/**
 * @file lora_transport.h
 * @brief High-level LoRa transport functions
 *
 * Provides send/receive with automatic retry and error handling
 * NOTE: Currently this is kept minimal - most functionality is in lora_hal
 */

#ifndef LORA_TRANSPORT_H
#define LORA_TRANSPORT_H

#include "lora_hal.h"

/**
 * @brief Send message with automatic TX configuration
 *
 * @param lora_dev LoRa device pointer
 * @param data Data to send
 * @param len Length of data
 * @return APP_OK on success
 * @return APP_ERR_LORA_* on failure
 */
int lora_transport_send(const struct device *lora_dev, const uint8_t *data, size_t len);

/**
 * @brief Receive message with automatic RX configuration
 *
 * @param lora_dev LoRa device pointer
 * @param data Buffer for received data
 * @param max_len Maximum buffer size
 * @param timeout Timeout for reception
 * @param rssi Output: RSSI value
 * @param snr Output: SNR value
 * @return Number of bytes received on success
 * @return APP_ERR_LORA_* on failure
 */
int lora_transport_recv(const struct device *lora_dev, uint8_t *data, size_t max_len,
                        k_timeout_t timeout, int16_t *rssi, int8_t *snr);

#endif /* LORA_TRANSPORT_H */
