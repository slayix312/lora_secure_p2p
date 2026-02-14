# LoRa Secure P2P (XIAO nRF54L15)

## Requirements

- 2x Seeed XIAO nRF54L15
- 2x Wio-SX1262
- nRF Connect SDK v3.1.1 (`west` in `PATH`)
- https://github.com/Seeed-Studio/platform-seeedboards

## Build and Flash (PowerShell)

Run from this repo root:

```powershell
$APP = (Resolve-Path .).Path.Replace('\','/')
$SEEED = "C:/path/to/platform-seeedboards"
$BR = "$SEEED/zephyr;$APP"

Remove-Item -Recurse -Force "$APP/build_ping_no_mcuboot","$APP/build_pong_no_mcuboot" -ErrorAction SilentlyContinue

# BOARD_ROLE=1 (PING, board 1)
west build -s "$APP" -b xiao_nrf54l15/nrf54l15/cpuapp --no-sysbuild -d "$APP/build_ping_no_mcuboot" -p always -- "-DBOARD_ROOT=$BR" -DBOARD_ROLE=1 "-DEXTRA_CONF_FILE=overlay-bt-no-fota.conf"
west flash -d "$APP/build_ping_no_mcuboot" --runner openocd

# BOARD_ROLE=2 (PONG, board 2)
west build -s "$APP" -b xiao_nrf54l15/nrf54l15/cpuapp --no-sysbuild -d "$APP/build_pong_no_mcuboot" -p always -- "-DBOARD_ROOT=$BR" -DBOARD_ROLE=2 "-DEXTRA_CONF_FILE=overlay-bt-no-fota.conf"
west flash -d "$APP/build_pong_no_mcuboot" --runner openocd
```

## Logs

- Open each board COM port at `115200` baud.

## If Flash Is Stuck

Use Seeed recovery + direct hex flash:

```powershell
nrfutil device list

$REC = "C:/path/to/platform-seeedboards/scripts/factory_reset"
cd $REC
.\factory_reset.bat

.\.venv\Scripts\python.exe .\xiao_nrf54l15_recover_flash.py --probe <PING_PROBE_SERIAL> --hex "$APP/build_ping_no_mcuboot/zephyr/zephyr.hex" --mass-erase
.\.venv\Scripts\python.exe .\xiao_nrf54l15_recover_flash.py --probe <PONG_PROBE_SERIAL> --hex "$APP/build_pong_no_mcuboot/zephyr/zephyr.hex" --mass-erase
```

## Note

- Default test PSK is intentionally enabled in `src/app_config.h` for lab testing.
