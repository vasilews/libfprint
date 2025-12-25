/* fpc_a921.c - FPC Fingerprint Scanner Driver for libfprint
 * 
 * Based on FpDevice (not FpImageDevice) for full control
 * Uses custom SIFT-based matching algorithm
 * 
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "fpc_a921"

#include "fpi-log.h"
#include "fpi-device.h"
#include "fpi-usb-transfer.h"
#include "fpi-print.h"
#include "fpi-image.h"
#include "fpi-custom-match.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

#include <string.h>

/* ============== Constants ============== */

#define FPC_VID 0x10A5
#define FPC_PID 0xA921

#define SENSOR_DPI      508.0

/* Event types */
#define EVT_HELLO                    0x01  /* Приветствие при подключении */
#define EVT_INIT_RESULT              0x02  /* Результат инициализации */
#define EVT_ARM_RESULT               0x03  /* Результат команды ARM */
#define EVT_DEAD_PIXEL_REPORT        0x04  /* Отчёт о мёртвых пикселях */
#define EVT_TLS                      0x05  /* Данные TLS handshake */
#define EVT_FINGER_DWN               0x06  /* Палец приложен к сенсору */
#define EVT_FINGER_UP                0x07  /* Палец убран с сенсора */
#define EVT_IMG                      0x08  /* Изображение отпечатка готово */
#define EVT_USB_LOGS                 0x09  /* Отладочные USB логи */
#define EVT_TLS_KEY                  0x0A  /* TLS ключ */
/* 0x0B - 0x1F - не используется */
#define EVT_REFRESH_SENSOR           0x20  /* Сенсор обновлён */

/* Commands */
#define  CMD_INIT                     0x01  /* Инициализация сенсора */
#define  CMD_ARM                      0x02  /* Подготовка к захвату (ожидание пальца) */
#define  CMD_ABORT                    0x03  /* Прерывание текущей операции */
#define  CMD_BOOT0_REQ                0x04  /* Запрос загрузчика */
#define  CMD_TLS_INIT                 0x05  /* Инициализация TLS сессии */
#define  CMD_TLS_DATA                 0x06  /* Передача данных TLS handshake */
/* 0x07 - не используется */      
#define  CMD_INDICATE_S_STATE         0x08  /* Индикация S-состояния (sleep states) */
#define  CMD_GET_IMG                  0x09  /* Получить изображение отпечатка */
#define  CMD_GET_DEAD_PIXELS          0x0A  /* Получить карту мёртвых пикселей */
#define  CMD_GET_TLS_KEY              0x0B  /* Получить TLS ключ */
#define  CMD_GET_KPI                  0x0C  /* Получить метрики качества сенсора ? */
#define  CMD_SET_TLS_KEY              0x0D  /* Установить TLS ключ */
/* 0x0E - 0x0F - не используется */
#define  CMD_FUSE_DEVICE              0x10  /* Прожечь OTP fuses (одноразово) */
#define  CMD_CLR_IMG                  0x11  /* Очистить изображение из памяти */
/* 0x12 - 0x1F - не используется */
#define  CMD_REFRESH_SENSOR           0x20  /* Обновить состояние сенсора */
/* 0x21 - 0x2F - не используется */
/* Информационные команды */
#define  CMD_GET_FW_VERSION           0x30  /* Получить версию прошивки */
#define  CMD_GET_HW_UNIQUE_ID         0x31  /* Получить уникальный ID оборудования */
#define  CMD_FLUSH_KEYS               0x32  /* Сбросить все ключи */
/* 0x33 - 0x3F - не используется */
/* Passthrough команды (прямой доступ к SPI) */
#define  CMD_PASSTHRU_INT_CONTROL     0x40  /* Управление прерыванием */
#define  CMD_PASSTHRU_CS_CONTROL      0x41  /* Управление Chip Select */
#define  CMD_PASSTHRU_INT_VALUE_OUT   0x42  /* Значение прерывания (выход) */
#define  CMD_PASSTHRU_TO_SPI          0x43  /* Отправить данные в SPI */
#define  CMD_PASSTHRU_FROM_SPI        0x44  /* Прочитать данные из SPI */
#define  CMD_PASSTHRU_INT_VALUE_IN    0x45  /* Значение прерывания (вход) */
/* 0x46 - 0x4F - не используется */
/* Системные команды */
#define  CMD_GET_STATE                     0x50  /* Получить состояние устройства */
/* 0x51 - 0xA9 - не используется */
#define  CMD_GET_MSOS                  0xAA  /* Получить MS OS дескриптор */
/* 0xAB - 0xF0 - не используется */
#define  CMD_EC_STATE                  0xF1  /* Состояние Embedded Controller */

/* Timeouts (ms) */
#define USB_TIMEOUT_MS      1000
#define FINGER_TIMEOUT_MS   15000
#define IMAGE_TIMEOUT_MS    2000
#define TLS_TIMEOUT_MS      2000

/* Buffer sizes */
#define MAX_TLS_BUF         16384
#define USB_BULK_BUF_SIZE   4096
#define TLS_CHUNK_SIZE      56

/* Image parameters */
#define IMAGE_HEADER_SIZE   24
#define IMAGE_RAW_WIDTH     64
#define IMAGE_RAW_HEIGHT    176
#define IMAGE_WIDTH         176
#define IMAGE_HEIGHT        64

/* USB Endpoint */
#define EP_IN               0x81

/* Max iterations */
#define MAX_HANDSHAKE_ITERATIONS    20
#define MAX_IMAGE_PACKETS           100

/* Enroll stages */
#define ENROLL_STAGES       8

/* PSK data */
static const guint8 FPC_PSK[32] = {
    0x9D, 0xB8, 0x3C, 0xC9, 0xFA, 0x51, 0xFE, 0xFE,
    0x25, 0x29, 0x2D, 0x16, 0x82, 0x61, 0xEC, 0x17,
    0x39, 0xB2, 0x92, 0x64, 0xFD, 0x3C, 0x6E, 0xE0,
    0x74, 0xF5, 0x36, 0xBD, 0x1C, 0xC6, 0x18, 0x55
};

static const gchar PSK_IDENTITY[] = "Disum PSK";

static const guint8 TLS_KEY_DATA[] = {
    0xed, 0x0d, 0xec, 0x0d, 0x1c, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0x57, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00,
    0xf0, 0x7b, 0x7f, 0xe5, 0x2e, 0x29, 0xa1, 0x04,
    0x98, 0x95, 0x97, 0x2b, 0x18, 0xcc, 0xba, 0xc2,
    0x5b, 0x02, 0xd2, 0x98, 0xfd, 0x3f, 0xe5, 0x67,
    0x2a, 0x26, 0x33, 0xe6, 0xae, 0xee, 0x4c, 0x21,
    0x73, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x61, 0x00,
    0x74, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00,
    0x46, 0x50, 0x43, 0x5f, 0x4b, 0x45, 0x59, 0x5f,
    0x41, 0x41, 0x44, 0x38, 0x35, 0x1c, 0x1c, 0xaf,
    0xc5, 0x5a, 0xa5, 0xd0, 0x2f, 0x02, 0x5b, 0x3d,
    0x2d, 0x13, 0xe7, 0x33, 0x72, 0x58, 0x1d, 0x44,
    0x74, 0x0a, 0x54, 0x95, 0xc9, 0x8a, 0x30, 0xdf,
    0x44, 0x6f, 0x0e
};

/* ============== State Machine ============== */

typedef enum {
    FPC_STATE_NONE = 0,

    /* Device initialization */
    FPC_STATE_INIT_INDICATE,
    FPC_STATE_INIT_GET_STATE,
    FPC_STATE_INIT_SEND_SESSION,
    FPC_STATE_INIT_RECV_SESSION,
    FPC_STATE_INIT_SET_TLS_KEY,

    /* TLS Handshake */
    FPC_STATE_TLS_INIT_CMD,
    FPC_STATE_TLS_HANDSHAKE_START,
    FPC_STATE_TLS_SEND_DATA,
    FPC_STATE_TLS_SEND_CHUNK,
    FPC_STATE_TLS_RECV_DATA,
    FPC_STATE_TLS_HANDSHAKE_CHECK,

    /* Image capture */
    FPC_STATE_CAPTURE_ARM,
    FPC_STATE_CAPTURE_WAIT_FINGER,
    FPC_STATE_CAPTURE_GET_IMAGE,
    FPC_STATE_CAPTURE_RECV_IMAGE,
    FPC_STATE_CAPTURE_CLEAR_IMAGE,
    FPC_STATE_CAPTURE_PROCESS,
} FpcState;

/* Current operation */
typedef enum {
    FPC_OP_NONE = 0,
    FPC_OP_OPEN,
    FPC_OP_ENROLL,
    FPC_OP_VERIFY,
    FPC_OP_IDENTIFY,
    FPC_OP_CAPTURE,
} FpcOperation;

static const gchar *
fpc_state_to_string(FpcState state)
{
    switch (state) {
    case FPC_STATE_NONE:               return "NONE";
    case FPC_STATE_INIT_INDICATE:      return "INIT_INDICATE";
    case FPC_STATE_INIT_GET_STATE:     return "INIT_GET_STATE";
    case FPC_STATE_INIT_SEND_SESSION:  return "INIT_SEND_SESSION";
    case FPC_STATE_INIT_RECV_SESSION:  return "INIT_RECV_SESSION";
    case FPC_STATE_INIT_SET_TLS_KEY:   return "INIT_SET_TLS_KEY";
    case FPC_STATE_TLS_INIT_CMD:       return "TLS_INIT_CMD";
    case FPC_STATE_TLS_HANDSHAKE_START: return "TLS_HANDSHAKE_START";
    case FPC_STATE_TLS_SEND_DATA:      return "TLS_SEND_DATA";
    case FPC_STATE_TLS_SEND_CHUNK:     return "TLS_SEND_CHUNK";
    case FPC_STATE_TLS_RECV_DATA:      return "TLS_RECV_DATA";
    case FPC_STATE_TLS_HANDSHAKE_CHECK: return "TLS_HANDSHAKE_CHECK";
    case FPC_STATE_CAPTURE_ARM:        return "CAPTURE_ARM";
    case FPC_STATE_CAPTURE_WAIT_FINGER: return "CAPTURE_WAIT_FINGER";
    case FPC_STATE_CAPTURE_GET_IMAGE:  return "CAPTURE_GET_IMAGE";
    case FPC_STATE_CAPTURE_RECV_IMAGE: return "CAPTURE_RECV_IMAGE";
    case FPC_STATE_CAPTURE_CLEAR_IMAGE: return "CAPTURE_CLEAR_IMAGE";
    case FPC_STATE_CAPTURE_PROCESS:    return "CAPTURE_PROCESS";
    default:                           return "UNKNOWN";
    }
}

static const gchar *
fpc_op_to_string(FpcOperation op)
{
    switch (op) {
    case FPC_OP_NONE:     return "NONE";
    case FPC_OP_OPEN:     return "OPEN";
    case FPC_OP_ENROLL:   return "ENROLL";
    case FPC_OP_VERIFY:   return "VERIFY";
    case FPC_OP_IDENTIFY: return "IDENTIFY";
    case FPC_OP_CAPTURE:  return "CAPTURE";
    default:              return "UNKNOWN";
    }
}

/* ============== Device Structure ============== */

#define FPI_TYPE_DEVICE_FPC_A921 (fpi_device_fpc_a921_get_type())
G_DECLARE_FINAL_TYPE(FpiDeviceFpcA921, fpi_device_fpc_a921, FPI, 
                     DEVICE_FPC_A921, FpDevice)

struct _FpiDeviceFpcA921
{
    FpDevice parent;

    /* State machine */
    FpcState      state;
    FpcOperation  current_op;
    gboolean      cancelling;

    /* USB */
    guint8        session_id[4];

    /* OpenSSL TLS */
    SSL_CTX      *ssl_ctx;
    SSL          *ssl;
    BIO          *rbio;
    BIO          *wbio;
    gboolean      tls_ready;
    gint          handshake_iterations;

    /* TLS send buffer */
    guint8       *tls_send_buf;
    gsize         tls_send_len;
    gsize         tls_send_offset;

    /* Image buffer */
    guint8       *image_buffer;
    gsize         image_buffer_len;
    gsize         image_buffer_alloc;
    gint          image_packet_count;

    /* Device info */
    guint8        version[4];
    gchar         model[8];

    /* Enroll data */
    GPtrArray    *enroll_samples;
    gint          enroll_stage;
};

G_DEFINE_TYPE(FpiDeviceFpcA921, fpi_device_fpc_a921, FP_TYPE_DEVICE)

/* ============== Prototypes ============== */

static void fpc_ssm_next_state(FpiDeviceFpcA921 *self);
static void fpc_ssm_run_state(FpiDeviceFpcA921 *self);
static void fpc_complete_with_error(FpiDeviceFpcA921 *self, GError *error);
static void fpc_tls_cleanup(FpiDeviceFpcA921 *self);
static gboolean fpc_tls_init(FpiDeviceFpcA921 *self, GError **error);
static void fpc_process_captured_image(FpiDeviceFpcA921 *self);
static void fpc_dev_capture(FpDevice *device);


/* ============== Logging Macros ============== */

#define fpc_dbg(_self, fmt, ...) \
    fp_dbg("[%s:%s] " fmt, \
           fpc_state_to_string((_self)->state), \
           fpc_op_to_string((_self)->current_op), \
           ##__VA_ARGS__)

#define fpc_info(_self, fmt, ...) \
    fp_info("[%s:%s] " fmt, \
            fpc_state_to_string((_self)->state), \
            fpc_op_to_string((_self)->current_op), \
            ##__VA_ARGS__)

#define fpc_warn(_self, fmt, ...) \
    fp_warn("[%s:%s] " fmt, \
            fpc_state_to_string((_self)->state), \
            fpc_op_to_string((_self)->current_op), \
            ##__VA_ARGS__)

#define fpc_err(_self, fmt, ...) \
    fp_err("[%s:%s] " fmt, \
           fpc_state_to_string((_self)->state), \
           fpc_op_to_string((_self)->current_op), \
           ##__VA_ARGS__)

/* ============== Utility Functions ============== */

static void
fpc_log_hex(FpiDeviceFpcA921 *self, const gchar *prefix, 
            const guint8 *data, gsize len)
{
    g_autoptr(GString) hex = g_string_new(NULL);
    gsize max_len = MIN(len, 32);

    for (gsize i = 0; i < max_len; i++)
        g_string_append_printf(hex, "%02X ", data[i]);

    if (len > max_len)
        g_string_append_printf(hex, "... (+%zu)", len - max_len);

    fpc_dbg(self, "%s[%zu]: %s", prefix, len, hex->str);
}

static void
fpc_set_state(FpiDeviceFpcA921 *self, FpcState new_state)
{
    if (self->state != new_state)
    {
        fp_dbg("State: %s -> %s", 
               fpc_state_to_string(self->state),
               fpc_state_to_string(new_state));
        self->state = new_state;
    }
}

/* Rotate image 90° CCW: (64x176) -> (176x64) */
static void
fpc_rotate_90_ccw(const guint8 *src, guint8 *dst,
                  int raw_width, int raw_height)
{
    for (int y = 0; y < raw_height; y++)
    {
        for (int x = 0; x < raw_width; x++)
        {
            int src_idx = y * raw_width + x;
            int dst_idx = (raw_width - 1 - x) * raw_height + y;
            dst[dst_idx] = src[src_idx];
        }
    }
}

/* ============== Error Handling ============== */

static void
fpc_complete_with_error(FpiDeviceFpcA921 *self, GError *error)
{
    FpDevice *device = FP_DEVICE(self);
    FpcOperation op = self->current_op;

    fpc_err(self, "Error: %s", error->message);

    self->current_op = FPC_OP_NONE;
    fpc_set_state(self, FPC_STATE_NONE);

    switch (op)
    {
        case FPC_OP_OPEN:
            fpi_device_open_complete(device, error);
            break;
        case FPC_OP_ENROLL:
            fpi_device_enroll_complete(device, NULL, error);
            break;
        case FPC_OP_VERIFY:
            fpi_device_verify_complete(device, error);
            break;
        case FPC_OP_IDENTIFY:
            fpi_device_identify_complete(device, error);
            break;
        case FPC_OP_CAPTURE:
            fpi_device_capture_complete(device, NULL, error);
            break;
        default:
            g_error_free(error);
            break;
    }
}

/* ============== OpenSSL PSK Callback ============== */

static unsigned int
psk_client_cb(SSL *ssl, const char *hint,
              char *identity, unsigned int max_identity_len,
              unsigned char *psk, unsigned int max_psk_len)
{
    (void)ssl;
    (void)hint;

    fp_dbg("PSK callback: hint='%s'", hint ? hint : "(null)");

    if (max_identity_len < sizeof(PSK_IDENTITY) ||
        max_psk_len < sizeof(FPC_PSK))
    {
        fp_err("PSK buffer too small");
        return 0;
    }

    strncpy(identity, PSK_IDENTITY, max_identity_len);
    memcpy(psk, FPC_PSK, sizeof(FPC_PSK));

    return sizeof(FPC_PSK);
}

/* ============== TLS Functions ============== */

static gboolean
fpc_tls_init(FpiDeviceFpcA921 *self, GError **error)
{
    fpc_dbg(self, "Initializing OpenSSL TLS");

    self->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (self->ssl_ctx == NULL)
    {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "SSL_CTX_new failed");
        return FALSE;
    }

    SSL_CTX_set_min_proto_version(self->ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(self->ssl_ctx, TLS1_2_VERSION);

    if (SSL_CTX_set_cipher_list(self->ssl_ctx, 
            "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:PSK-AES128-CBC-SHA256") != 1)
    {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to set cipher list");
        SSL_CTX_free(self->ssl_ctx);
        self->ssl_ctx = NULL;
        return FALSE;
    }

    SSL_CTX_set_psk_client_callback(self->ssl_ctx, psk_client_cb);

    self->ssl = SSL_new(self->ssl_ctx);
    if (self->ssl == NULL)
    {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "SSL_new failed");
        SSL_CTX_free(self->ssl_ctx);
        self->ssl_ctx = NULL;
        return FALSE;
    }

    self->rbio = BIO_new(BIO_s_mem());
    self->wbio = BIO_new(BIO_s_mem());

    if (self->rbio == NULL || self->wbio == NULL)
    {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "BIO_new failed");
        if (self->rbio) BIO_free(self->rbio);
        if (self->wbio) BIO_free(self->wbio);
        self->rbio = NULL;
        self->wbio = NULL;
        SSL_free(self->ssl);
        self->ssl = NULL;
        SSL_CTX_free(self->ssl_ctx);
        self->ssl_ctx = NULL;
        return FALSE;
    }

    SSL_set_bio(self->ssl, self->rbio, self->wbio);
    SSL_set_connect_state(self->ssl);

    self->tls_ready = FALSE;
    self->handshake_iterations = 0;

    fpc_dbg(self, "TLS initialized (OpenSSL %s)", 
             OpenSSL_version(OPENSSL_VERSION));

    return TRUE;
}

static void
fpc_tls_cleanup(FpiDeviceFpcA921 *self)
{
    fpc_dbg(self, "Cleaning up TLS");

    if (self->ssl != NULL)
    {
        SSL_free(self->ssl);
        self->ssl = NULL;
        self->rbio = NULL;
        self->wbio = NULL;
    }

    if (self->ssl_ctx != NULL)
    {
        SSL_CTX_free(self->ssl_ctx);
        self->ssl_ctx = NULL;
    }

    self->tls_ready = FALSE;

    g_clear_pointer(&self->tls_send_buf, g_free);
    self->tls_send_len = 0;
    self->tls_send_offset = 0;
}

/* ============== USB Operations ============== */

static void
fpc_send_ctrl_cmd(FpiDeviceFpcA921 *self, guint8 request,
                  guint16 value, guint16 index,
                  const guint8 *data, gsize len,
                  FpiUsbTransferCallback callback)
{
    FpiUsbTransfer *transfer;
    GCancellable *cancellable = NULL;

    fpc_dbg(self, "CTRL OUT: req=0x%02X val=0x%04X idx=0x%04X len=%zu",
            request, value, index, len);

    if (data != NULL && len > 0)
        fpc_log_hex(self, "TX", data, len);

    transfer = fpi_usb_transfer_new(FP_DEVICE(self));
    transfer->short_is_error = FALSE;

    fpi_usb_transfer_fill_control(transfer,
                                  G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                  G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                  G_USB_DEVICE_RECIPIENT_DEVICE,
                                  request, value, index, len);

    if (data != NULL && len > 0)
        memcpy(transfer->buffer, data, len);

    cancellable = fpi_device_get_cancellable (FP_DEVICE(self));
    fpi_usb_transfer_submit(transfer, USB_TIMEOUT_MS, cancellable, callback, NULL);
}

static void
fpc_recv_ctrl(FpiDeviceFpcA921 *self, guint8 request,
              guint16 value, guint16 index, gsize len,
              FpiUsbTransferCallback callback)
{
    FpiUsbTransfer *transfer;
    GCancellable *cancellable = NULL;

    fpc_dbg(self, "CTRL IN: req=0x%02X val=0x%04X idx=0x%04X len=%zu",
            request, value, index, len);

    transfer = fpi_usb_transfer_new(FP_DEVICE(self));
    transfer->short_is_error = FALSE;

    fpi_usb_transfer_fill_control(transfer,
                                  G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                  G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                  G_USB_DEVICE_RECIPIENT_DEVICE,
                                  request, value, index, len);

    cancellable = fpi_device_get_cancellable (FP_DEVICE(self));
    fpi_usb_transfer_submit(transfer, USB_TIMEOUT_MS, cancellable, callback, NULL);
}

static void
fpc_recv_bulk(FpiDeviceFpcA921 *self, gsize len, guint timeout_ms,
              FpiUsbTransferCallback callback)
{
    FpiUsbTransfer *transfer;
    GCancellable *cancellable = NULL;

    fpc_dbg(self, "BULK IN: len=%zu timeout=%u", len, timeout_ms);

    transfer = fpi_usb_transfer_new(FP_DEVICE(self));
    transfer->short_is_error = FALSE;

    fpi_usb_transfer_fill_bulk(transfer, EP_IN, len);

    cancellable = fpi_device_get_cancellable (FP_DEVICE(self));
    fpi_usb_transfer_submit(transfer, timeout_ms, cancellable, callback, NULL);
}

/* ============== USB Callbacks ============== */

static void
fpc_ctrl_cmd_cb(FpiUsbTransfer *transfer, FpDevice *device,
                gpointer user_data, GError *error)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    if (error != NULL)
    {
        fpc_complete_with_error(self, error);
        return;
    }

    fpc_dbg(self, "Control OUT OK");


    fpc_ssm_next_state(self);
}


static void
fpc_abort_cmd_cb(FpiUsbTransfer *transfer, FpDevice *device,
                gpointer user_data, GError *error)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    if (error != NULL)
    {
        fpc_dbg(self, "ABORTED ERROR");
        fpc_complete_with_error(self, error);
        return;
    }

    fpc_dbg(self, "ABORTED");

    fpc_set_state(self, FPC_STATE_NONE);
    fpc_ssm_run_state(self);
}

static void
fpc_clr_img_cmd_cb(FpiUsbTransfer *transfer, FpDevice *device,
                      gpointer user_data, GError *error)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    if (error != NULL)
    {
        fpc_complete_with_error(self, error);
        return;
    }

    fpc_ssm_next_state(self);
}

static void
fpc_init_get_state_cb(FpiUsbTransfer *transfer, FpDevice *device,
                      gpointer user_data, GError *error)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    if (error != NULL)
    {
        fpc_complete_with_error(self, error);
        return;
    }

    if (transfer->actual_length >= 34)
    {
        const guint8 *state = transfer->buffer;

        memcpy(self->version, state, 4);
        memcpy(self->model, &state[19], 7);
        self->model[7] = '\0';

        guint16 vid = state[30] | ((guint16)state[31] << 8);
        guint16 pid = state[32] | ((guint16)state[33] << 8);

        fpc_dbg(self, "Device: %s v%d.%d.%d.%d (VID:PID=%04X:%04X)",
                 self->model,
                 self->version[0], self->version[1],
                 self->version[2], self->version[3],
                 vid, pid);
    }

    fpc_send_ctrl_cmd(self, CMD_CLR_IMG, 0, 0, NULL, 0, fpc_clr_img_cmd_cb);
}

static void
fpc_init_session_cb(FpiUsbTransfer *transfer, FpDevice *device,
                    gpointer user_data, GError *error)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    if (error != NULL)
    {
        if (g_error_matches(error, G_USB_DEVICE_ERROR,
                            G_USB_DEVICE_ERROR_TIMED_OUT))
        {
            fpc_dbg(self, "Session read timeout (OK)");
            g_error_free(error);
        }
        else
        {
            fpc_complete_with_error(self, error);
            return;
        }
    }

    fpc_ssm_next_state(self);
}

static void
fpc_tls_send_chunk_cb(FpiUsbTransfer *transfer, FpDevice *device,
                      gpointer user_data, GError *error)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    if (error != NULL)
    {
        fpc_complete_with_error(self, error);
        return;
    }

    fpc_dbg(self, "TLS chunk sent, offset=%zu/%zu",
            self->tls_send_offset, self->tls_send_len);

    if (self->tls_send_offset < self->tls_send_len)
    {
        fpc_ssm_run_state(self);
    }
    else
    {
        g_clear_pointer(&self->tls_send_buf, g_free);
        self->tls_send_len = 0;
        self->tls_send_offset = 0;
        fpc_ssm_next_state(self);
    }
}

static void
fpc_tls_recv_cb(FpiUsbTransfer *transfer, FpDevice *device,
                gpointer user_data, GError *error)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    if (error != NULL)
    {
        if (g_error_matches(error, G_USB_DEVICE_ERROR,
                            G_USB_DEVICE_ERROR_TIMED_OUT))
        {
            fpc_dbg(self, "TLS recv timeout, checking handshake");
            g_error_free(error);
            fpc_set_state(self, FPC_STATE_TLS_HANDSHAKE_CHECK);
            fpc_ssm_run_state(self);
            return;
        }
        fpc_complete_with_error(self, error);
        return;
    }

    if (transfer->actual_length > 0)
    {
        const guint8 *data = transfer->buffer;
        gsize len = transfer->actual_length;

        if (len >= 12 && data[0] == EVT_TLS)
        {
            fpc_dbg(self, "TLS event: %zu payload bytes", len - 12);
            BIO_write(self->rbio, data + 12, (int)(len - 12));
        }
        else
        {
            fpc_dbg(self, "Raw data: %zu bytes", len);
            BIO_write(self->rbio, data, (int)len);
        }
    }

    fpc_ssm_next_state(self);
}

static void
fpc_wait_finger_cb(FpiUsbTransfer *transfer, FpDevice *device,
                   gpointer user_data, GError *error)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    if (self->cancelling)
    {
        if (error) g_error_free(error);

        self->cancelling = FALSE;
        GError *cancel_error = g_error_new(G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                           "Operation cancelled");

        fpc_complete_with_error(self, cancel_error);
        //fpc_send_ctrl_cmd(self, CMD_ABORT, 0x0001, 0, NULL, 0, fpc_abort_cmd_cb);
        return;
    }

    if (error != NULL)
    {
        if (g_error_matches(error, G_USB_DEVICE_ERROR,
                            G_USB_DEVICE_ERROR_TIMED_OUT))
        {
            fpc_dbg(self, "Waiting for finger...");
            g_error_free(error);
            fpc_ssm_run_state(self);
            return;
        }
        fpc_complete_with_error(self, error);
        return;
    }

    if (transfer->actual_length > 0)
    {
        guint8 event_type = transfer->buffer[0];

        fpc_dbg(self, "Event: type=%d", event_type);

        switch (event_type)
        {
            case EVT_TLS:
                if (transfer->actual_length >= 12)
                {
                    BIO_write(self->rbio,
                              transfer->buffer + 12,
                              (int)(transfer->actual_length - 12));

                    guint8 buf[256];
                    SSL_read(self->ssl, buf, sizeof(buf));
                }
                fpc_ssm_run_state(self);
                break;

            case EVT_FINGER_DWN:
                fpc_dbg(self, "Finger detected!");
                fpc_ssm_next_state(self);
                break;

            case EVT_FINGER_UP:
                fpc_dbg(self, "Finger removed");
                fpc_ssm_run_state(self);
                break;

            default:
                fpc_dbg(self, "Unknown event: %d", event_type);
                fpc_ssm_run_state(self);
                break;
        }
    }
    else
    {
        fpc_ssm_run_state(self);
    }
}

static void
fpc_recv_image_cb(FpiUsbTransfer *transfer, FpDevice *device,
                  gpointer user_data, GError *error)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);
    const gsize expected_size = IMAGE_HEADER_SIZE + 
                                (gsize)IMAGE_RAW_WIDTH * IMAGE_RAW_HEIGHT;


    if (self->cancelling)
    {
        if (error) g_error_free(error);

        self->cancelling = FALSE;
        GError *cancel_error = g_error_new(G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                           "Operation cancelled");

        fpc_complete_with_error(self, cancel_error);
        //fpc_send_ctrl_cmd(self, CMD_ABORT, 0x0001, 0, NULL, 0, fpc_abort_cmd_cb);
        return;
    }

    if (error != NULL)
    {
        if (g_error_matches(error, G_USB_DEVICE_ERROR,
                            G_USB_DEVICE_ERROR_TIMED_OUT))
        {
            fpc_dbg(self, "Image recv timeout");
            g_error_free(error);
            fpc_ssm_next_state(self);
            return;
        }
        fpc_complete_with_error(self, error);
        return;
    }

    self->image_packet_count++;

    if (transfer->actual_length > 0)
    {
        const guint8 *data = transfer->buffer;
        gsize len = transfer->actual_length;

        fpc_dbg(self, "Image packet #%d: %zu bytes",
                self->image_packet_count, len);

        if (len >= 12 && data[0] == EVT_TLS)
        {
            BIO_write(self->rbio, data + 12, (int)(len - 12));

            guint8 plain[4096];
            int n = SSL_read(self->ssl, plain, sizeof(plain));

            if (n > 0)
            {
                fpc_dbg(self, "Decrypted: %d bytes (total: %zu/%zu)",
                        n, self->image_buffer_len + n, expected_size);

                /* Grow buffer if needed */
                if (self->image_buffer_len + (gsize)n > self->image_buffer_alloc)
                {
                    self->image_buffer_alloc = MAX(
                        self->image_buffer_alloc * 2,
                        self->image_buffer_len + (gsize)n + 4096
                    );
                    self->image_buffer = g_realloc(self->image_buffer,
                                                   self->image_buffer_alloc);
                }

                memcpy(self->image_buffer + self->image_buffer_len, 
                       plain, (gsize)n);
                self->image_buffer_len += (gsize)n;

                /* Check if complete */
                if (self->image_buffer_len >= expected_size)
                {
                    fpc_dbg(self, "Image complete: %zu bytes", 
                             self->image_buffer_len);
                    fpc_ssm_next_state(self);
                    return;
                }
            }
        }

        if (self->image_packet_count >= MAX_IMAGE_PACKETS)
        {
            fpc_warn(self, "Max image packets reached");
            fpc_ssm_next_state(self);
            return;
        }

        fpc_ssm_run_state(self);
    }
    else
    {
        fpc_ssm_next_state(self);
    }
}

/* ============== State Machine ============== */

static void
fpc_ssm_next_state(FpiDeviceFpcA921 *self)
{
    FpcState next;

    switch (self->state)
    {
        case FPC_STATE_INIT_INDICATE:
            next = FPC_STATE_INIT_GET_STATE;
            break;
        case FPC_STATE_INIT_GET_STATE:
            next = FPC_STATE_INIT_SEND_SESSION;
            break;
        case FPC_STATE_INIT_SEND_SESSION:
            next = FPC_STATE_INIT_RECV_SESSION;
            break;
        case FPC_STATE_INIT_RECV_SESSION:
            next = FPC_STATE_INIT_SET_TLS_KEY;
            break;
        case FPC_STATE_INIT_SET_TLS_KEY:
            next = FPC_STATE_TLS_INIT_CMD;
            break;
        case FPC_STATE_TLS_INIT_CMD:
            next = FPC_STATE_TLS_HANDSHAKE_START;
            break;
        case FPC_STATE_TLS_HANDSHAKE_START:
        case FPC_STATE_TLS_HANDSHAKE_CHECK:
            return;  /* Handled in run_state */
        case FPC_STATE_TLS_SEND_DATA:
            next = FPC_STATE_TLS_SEND_CHUNK;
            break;
        case FPC_STATE_TLS_SEND_CHUNK:
            next = FPC_STATE_TLS_RECV_DATA;
            break;
        case FPC_STATE_TLS_RECV_DATA:
            next = FPC_STATE_TLS_HANDSHAKE_CHECK;
            break;
        case FPC_STATE_CAPTURE_ARM:
            next = FPC_STATE_CAPTURE_WAIT_FINGER;
            break;
        case FPC_STATE_CAPTURE_WAIT_FINGER:
            next = FPC_STATE_CAPTURE_GET_IMAGE;
            break;
        case FPC_STATE_CAPTURE_GET_IMAGE:
            next = FPC_STATE_CAPTURE_RECV_IMAGE;
            break;
        case FPC_STATE_CAPTURE_RECV_IMAGE:
            next = FPC_STATE_CAPTURE_CLEAR_IMAGE;
            break;
        case FPC_STATE_CAPTURE_CLEAR_IMAGE:
            next = FPC_STATE_CAPTURE_PROCESS;
            break;
        case FPC_STATE_CAPTURE_PROCESS:
            next = FPC_STATE_NONE;
            break;
        default:
            next = FPC_STATE_NONE;
            break;
    }

    fpc_set_state(self, next);
    fpc_ssm_run_state(self);
}

static void
fpc_ssm_run_state(FpiDeviceFpcA921 *self)
{
    GError *error = NULL;

    fpc_dbg(self, "Running state");

    switch (self->state)
    {
        /* ===== Initialization ===== */

        case FPC_STATE_INIT_INDICATE:
            fpc_send_ctrl_cmd(self, CMD_INDICATE_S_STATE, 0x0010, 0,
                              NULL, 0, fpc_ctrl_cmd_cb);
            break;

        case FPC_STATE_INIT_GET_STATE:
            fpc_recv_ctrl(self, CMD_GET_STATE, 0, 0, 76, 
                          fpc_init_get_state_cb);
            break;

        case FPC_STATE_INIT_SEND_SESSION:
            RAND_bytes(self->session_id, sizeof(self->session_id));
            fpc_log_hex(self, "Session ID", self->session_id, 
                        sizeof(self->session_id));
            fpc_send_ctrl_cmd(self, CMD_INIT, 0x0001, 0,
                              self->session_id, sizeof(self->session_id),
                              fpc_ctrl_cmd_cb);
            break;

        case FPC_STATE_INIT_RECV_SESSION:
            fpc_recv_bulk(self, 64, USB_TIMEOUT_MS, fpc_init_session_cb);
            break;

        case FPC_STATE_INIT_SET_TLS_KEY:
            fpc_dbg(self, "Setting TLS key");
            fpc_send_ctrl_cmd(self, CMD_SET_TLS_KEY, 0, 0,
                              TLS_KEY_DATA, sizeof(TLS_KEY_DATA),
                              fpc_ctrl_cmd_cb);
            break;

        /* ===== TLS Handshake ===== */

        case FPC_STATE_TLS_INIT_CMD:
            if (!fpc_tls_init(self, &error))
            {
                fpc_complete_with_error(self, error);
                return;
            }
            fpc_send_ctrl_cmd(self, CMD_TLS_INIT, 0x0001, 0,
                              NULL, 0, fpc_ctrl_cmd_cb);
            break;

        case FPC_STATE_TLS_HANDSHAKE_START:
        case FPC_STATE_TLS_HANDSHAKE_CHECK:
            {
                int ret, ssl_err;

                self->handshake_iterations++;
                fpc_dbg(self, "Handshake iteration %d", 
                        self->handshake_iterations);

                if (self->handshake_iterations > MAX_HANDSHAKE_ITERATIONS)
                {
                    g_set_error(&error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                                "TLS handshake timeout");
                    fpc_complete_with_error(self, error);
                    return;
                }

                ret = SSL_do_handshake(self->ssl);
                ssl_err = SSL_get_error(self->ssl, ret);

                fpc_dbg(self, "SSL_do_handshake: ret=%d err=%d", ret, ssl_err);

                if (ret == 1)
                {
                    self->tls_ready = TRUE;
                    fpc_dbg(self, "TLS handshake complete! Cipher: %s",
                             SSL_get_cipher(self->ssl));

                    /* Handshake done - complete the current operation */
                    if (self->current_op == FPC_OP_OPEN)
                    {
                        self->current_op = FPC_OP_NONE;
                        fpc_set_state(self, FPC_STATE_NONE);
                        fpi_device_open_complete(FP_DEVICE(self), NULL);
                    }
                    else
                    {
                        /* Start capture for verify/identify/enroll */
                        fpc_set_state(self, FPC_STATE_CAPTURE_ARM);
                        fpc_ssm_run_state(self);
                    }
                    return;
                }

                if (ssl_err == SSL_ERROR_WANT_WRITE ||
                    BIO_ctrl_pending(self->wbio) > 0)
                {
                    fpc_set_state(self, FPC_STATE_TLS_SEND_DATA);
                    fpc_ssm_run_state(self);
                    return;
                }

                if (ssl_err == SSL_ERROR_WANT_READ)
                {
                    fpc_set_state(self, FPC_STATE_TLS_RECV_DATA);
                    fpc_ssm_run_state(self);
                    return;
                }

                g_set_error(&error, G_IO_ERROR, G_IO_ERROR_FAILED,
                            "SSL handshake failed: ssl_err=%d", ssl_err);
                ERR_print_errors_fp(stderr);
                fpc_complete_with_error(self, error);
            }
            break;

        case FPC_STATE_TLS_SEND_DATA:
            {
                int pending = BIO_ctrl_pending(self->wbio);

                if (pending > 0)
                {
                    self->tls_send_buf = g_malloc((gsize)pending);
                    self->tls_send_len = (gsize)BIO_read(self->wbio,
                                                         self->tls_send_buf,
                                                         pending);
                    self->tls_send_offset = 0;

                    fpc_dbg(self, "TLS data to send: %zu bytes", 
                            self->tls_send_len);

                    fpc_set_state(self, FPC_STATE_TLS_SEND_CHUNK);
                    fpc_ssm_run_state(self);
                }
                else
                {
                    fpc_set_state(self, FPC_STATE_TLS_RECV_DATA);
                    fpc_ssm_run_state(self);
                }
            }
            break;

        case FPC_STATE_TLS_SEND_CHUNK:
            {
                gsize remaining = self->tls_send_len - self->tls_send_offset;
                gsize chunk_size = MIN(remaining, TLS_CHUNK_SIZE);

                fpc_dbg(self, "Sending chunk: offset=%zu size=%zu",
                        self->tls_send_offset, chunk_size);

                fpc_send_ctrl_cmd(self, CMD_TLS_DATA, 0x0001, 0,
                                  self->tls_send_buf + self->tls_send_offset,
                                  chunk_size, fpc_tls_send_chunk_cb);

                self->tls_send_offset += chunk_size;
            }
            break;

        case FPC_STATE_TLS_RECV_DATA:
            fpc_recv_bulk(self, USB_BULK_BUF_SIZE, TLS_TIMEOUT_MS, 
                          fpc_tls_recv_cb);
            break;

        /* ===== Image Capture ===== */

        case FPC_STATE_CAPTURE_ARM:
            fpc_dbg(self, "Arming sensor");
            fpc_send_ctrl_cmd(self, CMD_ARM, 0x0001, 0,
                              self->session_id, sizeof(self->session_id),
                              fpc_ctrl_cmd_cb);
            break;

        case FPC_STATE_CAPTURE_WAIT_FINGER:
            fpc_recv_bulk(self, 64, FINGER_TIMEOUT_MS, fpc_wait_finger_cb);
            break;

        case FPC_STATE_CAPTURE_GET_IMAGE:
            fpc_dbg(self, "Getting image");
            self->image_buffer_len = 0;
            self->image_packet_count = 0;
            fpc_send_ctrl_cmd(self, CMD_GET_IMG, 0, 0, NULL, 0, 
                              fpc_ctrl_cmd_cb);
            break;

        case FPC_STATE_CAPTURE_RECV_IMAGE:
            fpc_recv_bulk(self, USB_BULK_BUF_SIZE, IMAGE_TIMEOUT_MS, 
                          fpc_recv_image_cb);
            break;

        case FPC_STATE_CAPTURE_CLEAR_IMAGE:
            fpc_send_ctrl_cmd(self, CMD_CLR_IMG, 0, 0, NULL, 0, 
                              fpc_ctrl_cmd_cb);
            break;

        case FPC_STATE_CAPTURE_PROCESS:
            fpc_process_captured_image(self);
            break;

        case FPC_STATE_NONE:
            break;
    }
}

/* ============== Image Capture ============== */
static void
fpc_dev_capture(FpDevice *device)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    fpc_dbg(self, "Starting capture");

    self->current_op = FPC_OP_CAPTURE;

    if (self->tls_ready)
    {
        fpc_set_state(self, FPC_STATE_CAPTURE_ARM);
        fpc_ssm_run_state(self);
    }
    else
    {
        fpc_set_state(self, FPC_STATE_INIT_INDICATE);
        fpc_ssm_run_state(self);
    }
}
/* ============== Image Processing & Matching ============== */

static void
fpc_process_captured_image(FpiDeviceFpcA921 *self)
{
    FpDevice *device = FP_DEVICE(self);
    const gsize expected_size = IMAGE_HEADER_SIZE + 
                                (gsize)IMAGE_RAW_WIDTH * IMAGE_RAW_HEIGHT;
    GError *error = NULL;

    fpc_dbg(self, "Processing image: %zu bytes", self->image_buffer_len);

    /* Validate image size */
    if (self->image_buffer_len < expected_size)
    {
        g_set_error(&error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                    "Incomplete image: %zu < %zu",
                    self->image_buffer_len, expected_size);
        fpc_complete_with_error(self, error);
        return;
    }

    /* Allocate and rotate image */
    guint8 *rotated = g_malloc(IMAGE_WIDTH * IMAGE_HEIGHT);
    const guint8 *raw_data = self->image_buffer + IMAGE_HEADER_SIZE;
    fpc_rotate_90_ccw(raw_data, rotated, IMAGE_RAW_WIDTH, IMAGE_RAW_HEIGHT);


    /* Handle based on current operation */
    switch (self->current_op)
    {
        case FPC_OP_CAPTURE:
            {
                FpImage *img = fp_image_new(IMAGE_WIDTH, IMAGE_HEIGHT);
                
                memcpy(img->data, rotated, IMAGE_WIDTH * IMAGE_HEIGHT);
                
                img->ppmm = SENSOR_DPI / 25.4;
                
                g_free(rotated);
                
                self->current_op = FPC_OP_NONE;
                fpc_set_state(self, FPC_STATE_NONE);
                
                fpi_device_capture_complete(device, img, NULL);
                return;
            }
        case FPC_OP_ENROLL:
            {
                /* Extract features */
                FpiCustomFeatures *features = fpi_custom_extract_features(
                    rotated, IMAGE_WIDTH, IMAGE_HEIGHT
                );

                gsize feature_count = features ? fpi_custom_features_get_count(features) : 0;
                fpc_dbg(self, "Extracted %zu features", feature_count);

                if (feature_count < FPI_CUSTOM_MIN_FEATURES)
                {
                    fpi_custom_features_free(features);
                    g_free(rotated);

                    fpc_warn(self, "Not enough features, retrying");
                    fpi_device_enroll_progress(device, self->enroll_stage, NULL,
                        g_error_new(FP_DEVICE_ERROR,
                                    FP_DEVICE_ERROR_DATA_NOT_FOUND,
                                    "Poor image quality, please try again"));

                    /* Retry capture */
                    fpc_set_state(self, FPC_STATE_CAPTURE_ARM);
                    fpc_ssm_run_state(self);
                    return;
                }

                /* Add sample */
                g_ptr_array_add(self->enroll_samples, features);
                self->enroll_stage++;

                fpc_dbg(self, "Enroll stage %d/%d complete",
                         self->enroll_stage, ENROLL_STAGES);

                if (self->enroll_stage >= ENROLL_STAGES)
                {
                    /* Select best sample */
                    FpiCustomFeatures *best = NULL;
                    gsize best_count = 0;

                    for (guint i = 0; i < self->enroll_samples->len; i++)
                    {
                        FpiCustomFeatures *f = g_ptr_array_index(
                            self->enroll_samples, i
                        );
                        gsize count = fpi_custom_features_get_count(f);
                        if (count > best_count)
                        {
                            best_count = count;
                            best = f;
                        }
                    }

                    if (!best)
                    {
                        g_set_error(&error, FP_DEVICE_ERROR,
                                    FP_DEVICE_ERROR_GENERAL,
                                    "No valid samples");
                        g_free(rotated);
                        fpc_complete_with_error(self, error);
                        return;
                    }

                    GBytes *data = fpi_custom_features_serialize(best);

                    FpPrint *print = NULL;
                    fpi_device_get_enroll_data(device, &print);

                    fpi_print_set_type(print, FPI_PRINT_RAW);
                    
                    GVariant *variant = g_variant_new_from_bytes(
                        G_VARIANT_TYPE_BYTESTRING, data, TRUE
                    );
                    g_object_set(print, "fpi-data", variant, NULL);

                    g_bytes_unref(data);
                    g_ptr_array_set_size(self->enroll_samples, 0);

                    self->current_op = FPC_OP_NONE;
                    fpc_set_state(self, FPC_STATE_NONE);
                    fpi_device_enroll_complete(device, g_object_ref(print), NULL);
                }
                else
                {
                    /* Continue enrollment */
                    fpi_device_enroll_progress(device, self->enroll_stage, 
                                               NULL, NULL);
                    fpc_set_state(self, FPC_STATE_CAPTURE_ARM);
                    fpc_ssm_run_state(self);
                }
            }
            break;

        case FPC_OP_VERIFY:
            {
                FpPrint *enrolled = NULL;
                GVariant *enrolled_data = NULL;
                FpiMatchResult result = FPI_MATCH_FAIL;

                /* Extract features */
                FpiCustomFeatures *features = fpi_custom_extract_features(
                    rotated, IMAGE_WIDTH, IMAGE_HEIGHT
                );

                gsize feature_count = features ? fpi_custom_features_get_count(features) : 0;
                fpc_dbg(self, "Extracted %zu features", feature_count);

                if (!features || feature_count < FPI_CUSTOM_MIN_FEATURES)
                {
                    fpi_custom_features_free(features);
                    g_free(rotated);

                    fpi_device_verify_report(device, FPI_MATCH_ERROR, NULL,
                        g_error_new(FP_DEVICE_ERROR,
                                    FP_DEVICE_ERROR_DATA_NOT_FOUND,
                                    "Could not extract features"));
                    
                    self->current_op = FPC_OP_NONE;
                    fpc_set_state(self, FPC_STATE_NONE);
                    fpi_device_verify_complete(device, NULL);
                    return;
                }

                fpi_device_get_verify_data(device, &enrolled);
                g_object_get(enrolled, "fpi-data", &enrolled_data, NULL);

                if (!enrolled_data)
                {
                    fpi_custom_features_free(features);
                    g_free(rotated);

                    fpi_device_verify_report(device, FPI_MATCH_ERROR, NULL,
                        g_error_new(FP_DEVICE_ERROR,
                                    FP_DEVICE_ERROR_DATA_INVALID,
                                    "Enrolled print has no data"));
                    
                    self->current_op = FPC_OP_NONE;
                    fpc_set_state(self, FPC_STATE_NONE);
                    fpi_device_verify_complete(device, NULL);
                    return;
                }

                GBytes *bytes = g_variant_get_data_as_bytes(enrolled_data);
                FpiCustomFeatures *enrolled_features = 
                    fpi_custom_features_deserialize(bytes);

                if (enrolled_features)
                {
                    gint score = fpi_custom_match(enrolled_features, features);
                    fpc_dbg(self, "Verify score: %d (threshold: %d)",
                             score, FPI_CUSTOM_MATCH_THRESHOLD);

                    result = (score >= FPI_CUSTOM_MATCH_THRESHOLD) 
                             ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL;

                    fpi_custom_features_free(enrolled_features);
                }

                g_bytes_unref(bytes);
                fpi_custom_features_free(features);

                fpi_device_verify_report(device, result,
                    (result == FPI_MATCH_SUCCESS) ? enrolled : NULL, NULL);

                self->current_op = FPC_OP_NONE;
                fpc_set_state(self, FPC_STATE_NONE);
                fpi_device_verify_complete(device, NULL);
            }
            break;

        case FPC_OP_IDENTIFY:
            {
                GPtrArray *prints = NULL;
                FpPrint *match = NULL;
                gint best_score = 0;

                /* Extract features */
                FpiCustomFeatures *features = fpi_custom_extract_features(
                    rotated, IMAGE_WIDTH, IMAGE_HEIGHT
                );

                gsize feature_count = features ? fpi_custom_features_get_count(features) : 0;
                fpc_dbg(self, "Extracted %zu features", feature_count);

                if (!features || feature_count < FPI_CUSTOM_MIN_FEATURES)
                {
                    fpi_custom_features_free(features);
                    g_free(rotated);

                    fpi_device_identify_report(device, NULL, NULL,
                        g_error_new(FP_DEVICE_ERROR,
                                    FP_DEVICE_ERROR_DATA_NOT_FOUND,
                                    "Could not extract features"));
                    
                    self->current_op = FPC_OP_NONE;
                    fpc_set_state(self, FPC_STATE_NONE);
                    fpi_device_identify_complete(device, NULL);
                    return;
                }

                fpi_device_get_identify_data(device, &prints);

                if (!prints || prints->len == 0)
                {
                    fpi_custom_features_free(features);
                    g_free(rotated);

                    fpi_device_identify_report(device, NULL, NULL, NULL);
                    
                    self->current_op = FPC_OP_NONE;
                    fpc_set_state(self, FPC_STATE_NONE);
                    fpi_device_identify_complete(device, NULL);
                    return;
                }

                fpc_dbg(self, "Identifying against %u prints", prints->len);

                for (guint i = 0; i < prints->len; i++)
                {
                    FpPrint *print = g_ptr_array_index(prints, i);
                    GVariant *data = NULL;

                    g_object_get(print, "fpi-data", &data, NULL);
                    if (!data) continue;

                    GBytes *bytes = g_variant_get_data_as_bytes(data);
                    FpiCustomFeatures *enrolled = 
                        fpi_custom_features_deserialize(bytes);

                    if (enrolled)
                    {
                        gint score = fpi_custom_match(enrolled, features);
                        fpc_dbg(self, "Print %u: score=%d", i, score);

                        if (score > best_score)
                        {
                            best_score = score;
                            match = print;
                        }

                        fpi_custom_features_free(enrolled);
                    }

                    g_bytes_unref(bytes);
                }

                fpc_dbg(self, "Best score: %d", best_score);
                fpi_custom_features_free(features);

                if (best_score >= FPI_CUSTOM_MATCH_THRESHOLD && match)
                {
                    fpi_device_identify_report(device, match, match, NULL);
                }
                else
                {
                    fpi_device_identify_report(device, NULL, NULL, NULL);
                }
                self->current_op = FPC_OP_NONE;
                fpc_set_state(self, FPC_STATE_NONE);
                fpi_device_identify_complete(device, NULL);
            }
            break;

        default:
            fpc_warn(self, "Unexpected operation in CAPTURE_PROCESS");
            break;
    }

    g_free(rotated);
}

/* ============== FpDevice Operations ============== */

static void
fpc_dev_open(FpDevice *device)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);
    GError *error = NULL;
    GUsbDevice *usb_dev;

    fpc_dbg(self, "Opening device");

    usb_dev = fpi_device_get_usb_device(device);

    if (!g_usb_device_claim_interface(usb_dev, 0, 0, &error))
    {
        fpi_device_open_complete(device, error);
        return;
    }

    /* Allocate buffers */
    self->image_buffer_alloc = MAX_TLS_BUF;
    self->image_buffer = g_malloc(self->image_buffer_alloc);
    self->image_buffer_len = 0;

    /* Initialize enroll samples array */
    self->enroll_samples = g_ptr_array_new_with_free_func(
        (GDestroyNotify)fpi_custom_features_free
    );

    //  /* Reset USB port */
    if (!g_usb_device_reset(usb_dev, &error))
    {
        fpc_warn(self, "USB reset failed: %s", error->message);
        g_error_free(error);
    }

    /* Start initialization and TLS handshake */
    self->current_op = FPC_OP_OPEN;
    fpc_set_state(self, FPC_STATE_INIT_INDICATE);
    fpc_ssm_run_state(self);
}

static void
fpc_dev_close(FpDevice *device)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);
    GError *error = NULL;
    GUsbDevice *usb_dev;

    fpc_dbg(self, "Closing device");

    /* Cleanup TLS */
    fpc_tls_cleanup(self);

    /* Free buffers */
    g_clear_pointer(&self->image_buffer, g_free);
    self->image_buffer_alloc = 0;
    self->image_buffer_len = 0;

    /* Free enroll samples */
    if (self->enroll_samples)
    {
        g_ptr_array_free(self->enroll_samples, TRUE);
        self->enroll_samples = NULL;
    }

    /* Release USB interface */
    usb_dev = fpi_device_get_usb_device(device);
    g_usb_device_release_interface(usb_dev, 0, 0, &error);

    fpi_device_close_complete(device, error);
}

static void
fpc_dev_enroll(FpDevice *device)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    FpPrint *print = NULL;

    fpc_dbg(self, "Starting enroll");

    fpi_device_get_enroll_data(device, &print);
    if (print)
    {
        const gchar *username = fp_print_get_username(print);
        FpFinger finger = fp_print_get_finger(print);
        
        fpc_dbg(self, "Enroll template from fprintd:");
        fpc_dbg(self, "  username: '%s'", username ? username : "(NULL)");
        fpc_dbg(self, "  finger: %d (0x%x)", finger, finger);
    }
    else
    {
        fpc_warn(self, "No enroll template from fprintd!");
    }
    /* Reset enroll state */
    g_ptr_array_set_size(self->enroll_samples, 0);
    self->enroll_stage = 0;

    self->current_op = FPC_OP_ENROLL;

    /* Check if TLS is ready */
    if (self->tls_ready)
    {
        fpc_set_state(self, FPC_STATE_CAPTURE_ARM);
        fpc_ssm_run_state(self);
    }
    else
    {
        /* Need to initialize first */
        fpc_set_state(self, FPC_STATE_INIT_INDICATE);
        fpc_ssm_run_state(self);
    }
}

static void
fpc_dev_verify(FpDevice *device)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    fpc_dbg(self, "Starting verify");

    self->current_op = FPC_OP_VERIFY;

    if (self->tls_ready)
    {
        fpc_set_state(self, FPC_STATE_CAPTURE_ARM);
        fpc_ssm_run_state(self);
    }
    else
    {
        fpc_set_state(self, FPC_STATE_INIT_INDICATE);
        fpc_ssm_run_state(self);
    }
}

static void
fpc_dev_identify(FpDevice *device)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    fpc_dbg(self, "Starting identify");

    self->current_op = FPC_OP_IDENTIFY;

    if (self->tls_ready)
    {
        fpc_set_state(self, FPC_STATE_CAPTURE_ARM);
        fpc_ssm_run_state(self);
    }
    else
    {
        fpc_set_state(self, FPC_STATE_INIT_INDICATE);
        fpc_ssm_run_state(self);
    }
}

static void
fpc_dev_cancel(FpDevice *device)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

    fpc_dbg(self, "Cancelling operation");

    self->cancelling = TRUE;


}

/* ============== GObject Implementation ============== */

static void
fpi_device_fpc_a921_init(FpiDeviceFpcA921 *self)
{
    /* State machine */
    self->state = FPC_STATE_NONE;
    self->current_op = FPC_OP_NONE;
    self->cancelling = FALSE;

    /* USB */
    memset(self->session_id, 0, sizeof(self->session_id));

    /* TLS */
    self->ssl_ctx = NULL;
    self->ssl = NULL;
    self->rbio = NULL;
    self->wbio = NULL;
    self->tls_ready = FALSE;
    self->handshake_iterations = 0;

    /* TLS send buffer */
    self->tls_send_buf = NULL;
    self->tls_send_len = 0;
    self->tls_send_offset = 0;

    /* Image buffer */
    self->image_buffer = NULL;
    self->image_buffer_len = 0;
    self->image_buffer_alloc = 0;
    self->image_packet_count = 0;

    /* Device info */
    memset(self->version, 0, sizeof(self->version));
    memset(self->model, 0, sizeof(self->model));

    /* Enroll */
    self->enroll_samples = NULL;
    self->enroll_stage = 0;
}

static void
fpi_device_fpc_a921_finalize(GObject *object)
{
    FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(object);

    fpc_tls_cleanup(self);

    g_clear_pointer(&self->image_buffer, g_free);
    g_clear_pointer(&self->tls_send_buf, g_free);

    if (self->enroll_samples)
    {
        g_ptr_array_free(self->enroll_samples, TRUE);
        self->enroll_samples = NULL;
    }

    G_OBJECT_CLASS(fpi_device_fpc_a921_parent_class)->finalize(object);
}

static const FpIdEntry fpc_id_table[] = {
    { .vid = FPC_VID, .pid = FPC_PID },
    { .vid = 0,       .pid = 0       },
};

static void
fpi_device_fpc_a921_class_init(FpiDeviceFpcA921Class *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    FpDeviceClass *dev_class = FP_DEVICE_CLASS(klass);

    object_class->finalize = fpi_device_fpc_a921_finalize;

    dev_class->id = "fpc_a921";
    dev_class->full_name = "FPC Fingerprint Scanner A921";
    dev_class->type = FP_DEVICE_TYPE_USB;
    dev_class->id_table = fpc_id_table;
    dev_class->scan_type = FP_SCAN_TYPE_PRESS;
    dev_class->nr_enroll_stages = ENROLL_STAGES;

  /*
    FP_DEVICE_FEATURE_NONE: Device does not support any feature
    FP_DEVICE_FEATURE_CAPTURE: Supports image capture
    FP_DEVICE_FEATURE_VERIFY: Supports finger verification
    FP_DEVICE_FEATURE_IDENTIFY: Supports finger identification
    FP_DEVICE_FEATURE_STORAGE: Device has a persistent storage
    FP_DEVICE_FEATURE_STORAGE_LIST: Supports listing the storage templates
    FP_DEVICE_FEATURE_STORAGE_DELETE: Supports deleting stored templates
    FP_DEVICE_FEATURE_STORAGE_CLEAR: Supports clearing the whole storage
    FP_DEVICE_FEATURE_DUPLICATES_CHECK: Natively supports duplicates detection
    FP_DEVICE_FEATURE_ALWAYS_ON: Whether the device can run continuously
    FP_DEVICE_FEATURE_UPDATE_PRINT: Supports updating an existing print record using new scans
    */

    dev_class->features = FP_DEVICE_FEATURE_CAPTURE |
                          FP_DEVICE_FEATURE_IDENTIFY |
                          FP_DEVICE_FEATURE_VERIFY;

    dev_class->open = fpc_dev_open;
    dev_class->close = fpc_dev_close;
    dev_class->enroll = fpc_dev_enroll;
    dev_class->verify = fpc_dev_verify;
    dev_class->identify = fpc_dev_identify;
    dev_class->capture = fpc_dev_capture;
    dev_class->cancel = fpc_dev_cancel;
}


