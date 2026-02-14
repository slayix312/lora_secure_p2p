/**
 * @file lora_hal.c
 * @brief LoRa Hardware Abstraction Layer implementation
 */

#include "lora_hal.h"

LOG_MODULE_REGISTER(lora_hal, LOG_LEVEL_LORA);

int lora_hal_init(const struct device *lora_dev)
{
	if (lora_dev == NULL) {
		LOG_ERR("Invalid LoRa device");
		return APP_ERR_INVALID_PARAM;
	}

	if (!device_is_ready(lora_dev)) {
		LOG_ERR("LoRa device %s is not ready!", lora_dev->name);
		return APP_ERR_LORA_INIT;
	}

	LOG_INF("LoRa device %s ready", lora_dev->name);
	return APP_OK;
}

int lora_hal_config_tx(const struct device *lora_dev)
{
	struct lora_modem_config config;

	if (lora_dev == NULL) {
		return APP_ERR_INVALID_PARAM;
	}

	config.frequency = LORA_FREQUENCY;
	config.bandwidth = LORA_BANDWIDTH;
	config.datarate = LORA_DATARATE;
	config.preamble_len = LORA_PREAMBLE_LEN;
	config.coding_rate = LORA_CODING_RATE;
	config.tx_power = LORA_TX_POWER;
	config.tx = true;
	config.iq_inverted = false;
	config.public_network = false;

	int ret = lora_config(lora_dev, &config);
	if (ret < 0) {
		LOG_ERR("LoRa TX config failed: %d", ret);
		return APP_ERR_LORA_CONFIG;
	}

	LOG_DBG("LoRa configured for TX");
	return APP_OK;
}

int lora_hal_config_rx(const struct device *lora_dev)
{
	struct lora_modem_config config;

	if (lora_dev == NULL) {
		return APP_ERR_INVALID_PARAM;
	}

	config.frequency = LORA_FREQUENCY;
	config.bandwidth = LORA_BANDWIDTH;
	config.datarate = LORA_DATARATE;
	config.preamble_len = LORA_PREAMBLE_LEN;
	config.coding_rate = LORA_CODING_RATE;
	config.tx_power = LORA_TX_POWER;
	config.tx = false;
	config.iq_inverted = false;
	config.public_network = false;

	int ret = lora_config(lora_dev, &config);
	if (ret < 0) {
		LOG_ERR("LoRa RX config failed: %d", ret);
		return APP_ERR_LORA_CONFIG;
	}

	LOG_DBG("LoRa configured for RX");
	return APP_OK;
}

int lora_hal_send(const struct device *lora_dev, const uint8_t *data, size_t len)
{
	if (lora_dev == NULL || data == NULL) {
		return APP_ERR_INVALID_PARAM;
	}

	/* Cast away const - Zephyr API limitation (driver doesn't modify data) */
	int ret = lora_send(lora_dev, (uint8_t *)data, len);
	if (ret < 0) {
		LOG_ERR("LoRa send failed: %d", ret);
		return APP_ERR_LORA_TX;
	}

	LOG_DBG("LoRa sent %u bytes", len);
	return APP_OK;
}

int lora_hal_recv(const struct device *lora_dev, uint8_t *data, size_t max_len,
                  k_timeout_t timeout, int16_t *rssi, int8_t *snr)
{
	if (lora_dev == NULL || data == NULL) {
		return APP_ERR_INVALID_PARAM;
	}

	int ret = lora_recv(lora_dev, data, max_len, timeout, rssi, snr);
	if (ret < 0) {
		if (ret == -EAGAIN) {
			LOG_DBG("LoRa receive timeout");
			return APP_ERR_LORA_TIMEOUT;
		}
		LOG_ERR("LoRa receive failed: %d", ret);
		return APP_ERR_LORA_RX;
	}

	LOG_DBG("LoRa received %d bytes (RSSI=%d dBm, SNR=%d dB)", ret, *rssi, *snr);
	return ret;  /* Return number of bytes received */
}
