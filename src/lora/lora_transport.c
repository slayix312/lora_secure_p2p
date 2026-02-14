/**
 * @file lora_transport.c
 * @brief LoRa transport implementation
 */

#include "lora_transport.h"

LOG_MODULE_REGISTER(lora_transport, LOG_LEVEL_LORA);

enum radio_mode {
	RADIO_MODE_UNKNOWN = 0,
	RADIO_MODE_TX,
	RADIO_MODE_RX,
};

static enum radio_mode s_radio_mode = RADIO_MODE_UNKNOWN;

int lora_transport_send(const struct device *lora_dev, const uint8_t *data, size_t len)
{
	int ret;

	if (s_radio_mode != RADIO_MODE_TX) {
		/* Configure for TX only when changing mode */
		ret = lora_hal_config_tx(lora_dev);
		if (ret != APP_OK) {
			return ret;
		}
		s_radio_mode = RADIO_MODE_TX;
	}

	/* Send data */
	ret = lora_hal_send(lora_dev, data, len);
	if (ret != APP_OK) {
		return ret;
	}

	return APP_OK;
}

int lora_transport_recv(const struct device *lora_dev, uint8_t *data, size_t max_len,
                        k_timeout_t timeout, int16_t *rssi, int8_t *snr)
{
	int ret;

	if (s_radio_mode != RADIO_MODE_RX) {
		/* Configure for RX only when changing mode */
		ret = lora_hal_config_rx(lora_dev);
		if (ret != APP_OK) {
			return ret;
		}
		s_radio_mode = RADIO_MODE_RX;
	}

	/* Receive data */
	ret = lora_hal_recv(lora_dev, data, max_len, timeout, rssi, snr);
	return ret;  /* Returns number of bytes or error code */
}
