/*
 * Goodix Moc driver for libfprint
 * Copyright (C) 2019 Shenzhen Goodix Technology Co., Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include "fpi-device.h"
#include "fpi-ssm.h"

G_DECLARE_FINAL_TYPE (FpiDeviceGoodixMoc, fpi_device_goodixmoc, FPI, DEVICE_GOODIXMOC, FpDevice)

typedef enum {
  GOODIX_CMD_SEND = 0,
  GOODIX_CMD_GET_ACK,
  GOODIX_CMD_GET_DATA,
  GOODIX_CMD_NUM_STATES,
} GoodixCmdState;


typedef enum {
  GOODIX_INIT_VERSION = 0,
  GOODIX_INIT_CONFIG,
  GOODIX_INIT_TEMPLATE_LIST,
  GOODIX_INIT_RESET_DEVICE,
  GOODIX_INIT_NUM_STATES,
} GoodixInitState;


typedef enum {
  GOODIX_ENROLL_PWR_BTN_SHIELD_ON = 0,
  GOODIX_ENROLL_ENUM,
  GOODIX_ENROLL_CREATE,
  GOODIX_ENROLL_CAPTURE,
  GOODIX_ENROLL_UPDATE,
  GOODIX_ENROLL_WAIT_FINGER_UP,
  GOODIX_ENROLL_CHECK_DUPLICATE,
  GOODIX_ENROLL_COMMIT,
  GOODIX_ENROLL_PWR_BTN_SHIELD_OFF,
  GOODIX_ENROLL_NUM_STATES,
} GoodixEnrollState;

typedef enum {
  GOODIX_VERIFY_PWR_BTN_SHIELD_ON = 0,
  GOODIX_VERIFY_CAPTURE,
  GOODIX_VERIFY_IDENTIFY,
  GOODIX_VERIFY_PWR_BTN_SHIELD_OFF,
  GOODIX_VERIFY_NUM_STATES,
} GoodixVerifyState;
