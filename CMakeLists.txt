# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(lora_secure_p2p)

#
# Board Role Configuration
# Set BOARD_ROLE at build time to select device role:
#   Numeric values:   -DBOARD_ROLE=1 (PING) or -DBOARD_ROLE=2 (PONG)
#   Symbolic names:   -DBOARD_ROLE=ROLE_PING or -DBOARD_ROLE=ROLE_PONG
#
# Without sysbuild: west build --no-sysbuild -d build_ping -- -DBOARD_ROLE=1
# With sysbuild:    west build -d build_ping -- -Dlora_secure_p2p_BOARD_ROLE=1
#
# Try to get from sysbuild namespace first (available after find_package)
if(SYSBUILD)
    zephyr_get(BOARD_ROLE SYSBUILD GLOBAL)
endif()

# Convert symbolic names to numeric values for preprocessor compatibility
if(DEFINED BOARD_ROLE AND NOT "${BOARD_ROLE}" STREQUAL "")
    # Convert symbolic role names to numeric values
    if(BOARD_ROLE STREQUAL "ROLE_PING")
        set(BOARD_ROLE_VALUE 1)
        set(BOARD_ROLE_NAME "PING")
    elseif(BOARD_ROLE STREQUAL "ROLE_PONG")
        set(BOARD_ROLE_VALUE 2)
        set(BOARD_ROLE_NAME "PONG")
    elseif(BOARD_ROLE STREQUAL "1")
        set(BOARD_ROLE_VALUE 1)
        set(BOARD_ROLE_NAME "PING")
    elseif(BOARD_ROLE STREQUAL "2")
        set(BOARD_ROLE_VALUE 2)
        set(BOARD_ROLE_NAME "PONG")
    else()
        message(FATAL_ERROR "Invalid BOARD_ROLE: ${BOARD_ROLE}. Must be ROLE_PING, ROLE_PONG, 1, or 2")
    endif()

    message(STATUS "Board role set to: ${BOARD_ROLE_NAME} (BOARD_ROLE=${BOARD_ROLE_VALUE})")
    add_compile_definitions(BOARD_ROLE=${BOARD_ROLE_VALUE})
else()
    message(STATUS "Board role not specified, using default from app_config.h (ROLE_PONG)")
endif()

# Main application
target_sources(app PRIVATE src/main.c)

# Crypto modules
target_sources(app PRIVATE
    src/crypto/crypto_init.c
    src/crypto/aes_ccm.c
    src/crypto/ecdh.c
    src/crypto/key_storage.c
)

# Protocol modules
target_sources(app PRIVATE
    src/protocol/message.c
    src/protocol/security.c
    src/protocol/statistics.c
)

# LoRa modules
target_sources(app PRIVATE
    src/lora/lora_hal.c
    src/lora/lora_transport.c
)

# Application modules
target_sources(app PRIVATE
    src/app/ping_mode.c
    src/app/pong_mode.c
)
