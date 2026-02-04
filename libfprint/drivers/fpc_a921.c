/* fpc_a921.c - Драйвер сканера отпечатков пальцев FPC для libfprint
 *
 * Драйвер основан на FpDevice (а не FpImageDevice) для полного контроля над протоколом.
 * Использует пользовательский алгоритм сопоставления на основе SIFT.
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

/* ============== Константы ============== */

#define FPC_VID 0x10A5
#define FPC_PID 0xA921

#define SENSOR_DPI 508.0

/* --- Типы событий (Events) --- */
#define EVT_HELLO 0x01 /* Приветствие при подключении */
#define EVT_INIT_RESULT 0x02 /* Результат инициализации */
#define EVT_ARM_RESULT 0x03 /* Результат команды ARM (подготовка к скану) */
#define EVT_DEAD_PIXEL_REPORT 0x04 /* Отчет о битых пикселях */
#define EVT_TLS 0x05 /* Данные TLS handshake */
#define EVT_FINGER_DWN 0x06 /* Палец обнаружен на сенсоре */
#define EVT_FINGER_UP 0x07 /* Палец убран с сенсора */
#define EVT_IMG 0x08 /* Изображение готово (часто внутри TLS пакета) */
#define EVT_USB_LOGS 0x09 /* Отладочные логи */
#define EVT_TLS_KEY 0x0A /* Ключ TLS */
#define EVT_REFRESH_SENSOR 0x20 /* Состояние сенсора обновлено */

/* --- Команды управления (Commands) --- */
#define CMD_INIT 0x01 /* Инициализация сенсора */
#define CMD_ARM 0x02 /* Подготовка к захвату (войти в режим ожидания пальца) */
#define CMD_ABORT 0x03 /* Прерывание текущей операции */
#define CMD_BOOT0_REQ 0x04 /* Запрос загрузчика (Bootloader) */
#define CMD_TLS_INIT 0x05 /* Запуск инициализации TLS */
#define CMD_TLS_DATA 0x06 /* Передача данных TLS handshake */
#define CMD_INDICATE_S_STATE 0x08 /* Индикация состояния сна/энергосбережения */
#define CMD_GET_IMG 0x09 /* Запрос получения изображения */
#define CMD_GET_DEAD_PIXELS 0x0A /* Запрос карты битых пикселей */
#define CMD_GET_TLS_KEY 0x0B /* Запрос TLS ключа */
#define CMD_GET_KPI 0x0C /* Получение метрик качества (?) */
#define CMD_SET_TLS_KEY 0x0D /* Установка TLS ключа */
#define CMD_FUSE_DEVICE 0x10 /* Прожиг OTP fuses (одноразовое действие) */
#define CMD_CLR_IMG 0x11 /* Очистка буфера изображения */
#define CMD_REFRESH_SENSOR 0x20 /* Обновить состояние сенсора */
#define CMD_GET_FW_VERSION 0x30 /* Получение версии прошивки */
#define CMD_GET_HW_UNIQUE_ID 0x31 /* Получение уникального ID железа */
#define CMD_FLUSH_KEYS 0x32 /* Сброс всех ключей */
#define CMD_PASSTHRU_INT_CONTROL 0x40 /* Прямой доступ к SPI: управление прерыванием */
#define CMD_PASSTHRU_CS_CONTROL 0x41 /* Прямой доступ к SPI: Chip Select */
#define CMD_PASSTHRU_INT_VALUE_OUT 0x42 /* Прямой доступ к SPI: значение прерывания (out) */
#define CMD_PASSTHRU_TO_SPI 0x43 /* Прямой доступ к SPI: отправка данных */
#define CMD_PASSTHRU_FROM_SPI 0x44 /* Прямой доступ к SPI: чтение данных */
#define CMD_PASSTHRU_INT_VALUE_IN 0x45 /* Прямой доступ к SPI: значение прерывания (in) */
#define CMD_GET_STATE 0x50 /* Получение текущего состояния устройства */
#define CMD_GET_MSOS 0xAA /* Получение MS OS дескриптора */
#define CMD_EC_STATE 0xF1 /* Состояние Embedded Controller */

/* --- Тайм-ауты (мс) --- */
#define USB_TIMEOUT_MS 1000 /* Тайм-аут для стандартных USB команд */
#define FINGER_TIMEOUT_MS 15000 /* Время ожидания пальца */
#define IMAGE_TIMEOUT_MS 2000 /* Тайм-аут получения пакета изображения */
#define TLS_TIMEOUT_MS 2000 /* Тайм-аут обмена TLS данными */

/* --- Размеры буферов --- */
#define MAX_TLS_BUF 16384 /* Максимальный размер TLS буфера */
#define USB_BULK_BUF_SIZE 4096 /* Размер пакета для Bulk чтения */
#define TLS_CHUNK_SIZE 56 /* Размер чанка для отправки TLS данных (ограничение устройства) */

/* --- Параметры изображения --- */
#define IMAGE_HEADER_SIZE 24 /* Размер заголовка пакета изображения */
#define IMAGE_RAW_WIDTH 64 /* Ширина "сырого" изображения (как приходит с сенсора) */
#define IMAGE_RAW_HEIGHT 176 /* Высота "сырого" изображения */
#define IMAGE_WIDTH 176 /* Ширина после поворота (нормализованная) */
#define IMAGE_HEIGHT 64 /* Высота после поворота */

/* --- USB Endpoint --- */
#define EP_IN 0x81 /* Адрес входной конечной точки для чтения данных */

/* --- Лимиты --- */
#define MAX_HANDSHAKE_ITERATIONS 20 /* Макс. кол-во итераций handshake перед тайм-аутом */
#define MAX_IMAGE_PACKETS 100 /* Макс. кол-во пакетов на одно изображение */

/* --- Регистрация --- */
#define ENROLL_STAGES 8 /* Количество этапов для записи отпечатка */

/* --- PSK данные (Предварительно общий ключ) --- */
/* Ключ и идентификатор для TLS соединения */
static const guint8 FPC_PSK[32] = {
  0x9D, 0xB8, 0x3C, 0xC9, 0xFA, 0x51, 0xFE, 0xFE,
  0x25, 0x29, 0x2D, 0x16, 0x82, 0x61, 0xEC, 0x17,
  0x39, 0xB2, 0x92, 0x64, 0xFD, 0x3C, 0x6E, 0xE0,
  0x74, 0xF5, 0x36, 0xBD, 0x1C, 0xC6, 0x18, 0x55
};

static const gchar PSK_IDENTITY[] = "Disum PSK";

/* Блоб данных для установки TLS ключа на устройстве */
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

/* ============== Машина состояний (State Machine) ============== */

typedef enum {
  FPC_STATE_NONE = 0, /* Состояние покоя */

  /* --- Инициализация устройства --- */
  FPC_STATE_INIT_INDICATE, /* Отправка команды индикации состояния */
  FPC_STATE_INIT_GET_STATE, /* Запрос текущего состояния устройства */
  FPC_STATE_INIT_SEND_SESSION, /* Отправка ID сессии */
  FPC_STATE_INIT_RECV_SESSION, /* Ожидание подтверждения сессии */
  FPC_STATE_INIT_SET_TLS_KEY, /* Установка TLS ключа */

  /* --- TLS Рукопожатие (Handshake) --- */
  FPC_STATE_TLS_INIT_CMD, /* Запуск локальной структуры TLS */
  FPC_STATE_TLS_HANDSHAKE_START, /* Начало процесса обмена */
  FPC_STATE_TLS_SEND_DATA, /* Подготовка данных к отправке */
  FPC_STATE_TLS_SEND_CHUNK, /* Отправка чанка данных */
  FPC_STATE_TLS_RECV_DATA, /* Чтение ответа от устройства */
  FPC_STATE_TLS_HANDSHAKE_CHECK, /* Проверка статуса завершения handshake */

  /* --- Захват изображения --- */
  FPC_STATE_CAPTURE_ARM, /* Команда ARM: перейти в режим ожидания пальца */
  FPC_STATE_CAPTURE_WAIT_FINGER, /* Ожидание события нажатия */
  FPC_STATE_CAPTURE_GET_IMAGE, /* Запрос передачи изображения */
  FPC_STATE_CAPTURE_RECV_IMAGE, /* Прием пакетов изображения */
  FPC_STATE_CAPTURE_CLEAR_IMAGE, /* Очистка буфера устройства */
  FPC_STATE_CAPTURE_PROCESS, /* Обработка полученного изображения */

  /* --- Прочее --- */
  FPC_STATE_ABORTING, /* Процесс отмены операции */
} FpcState;

/* --- Текущая операция --- */
typedef enum {
  FPC_OP_NONE = 0, /* Нет операции */
  FPC_OP_OPEN, /* Открытие устройства */
  FPC_OP_ENROLL, /* Запись нового отпечатка */
  FPC_OP_VERIFY, /* Сверка с сохраненным отпечатком */
  FPC_OP_IDENTIFY, /* Поиск в базе отпечатков */
  FPC_OP_CAPTURE, /* Простой захват изображения */
} FpcOperation;

/* Преобразование состояния в строку для логов */
static const gchar *
fpc_state_to_string(FpcState state)
{
  switch (state) {
    case FPC_STATE_NONE: return "NONE";
    case FPC_STATE_INIT_INDICATE: return "INIT_INDICATE";
    case FPC_STATE_INIT_GET_STATE: return "INIT_GET_STATE";
    case FPC_STATE_INIT_SEND_SESSION: return "INIT_SEND_SESSION";
    case FPC_STATE_INIT_RECV_SESSION: return "INIT_RECV_SESSION";
    case FPC_STATE_INIT_SET_TLS_KEY: return "INIT_SET_TLS_KEY";
    case FPC_STATE_TLS_INIT_CMD: return "TLS_INIT_CMD";
    case FPC_STATE_TLS_HANDSHAKE_START: return "TLS_HANDSHAKE_START";
    case FPC_STATE_TLS_SEND_DATA: return "TLS_SEND_DATA";
    case FPC_STATE_TLS_SEND_CHUNK: return "TLS_SEND_CHUNK";
    case FPC_STATE_TLS_RECV_DATA: return "TLS_RECV_DATA";
    case FPC_STATE_TLS_HANDSHAKE_CHECK: return "TLS_HANDSHAKE_CHECK";
    case FPC_STATE_CAPTURE_ARM: return "CAPTURE_ARM";
    case FPC_STATE_CAPTURE_WAIT_FINGER: return "CAPTURE_WAIT_FINGER";
    case FPC_STATE_CAPTURE_GET_IMAGE: return "CAPTURE_GET_IMAGE";
    case FPC_STATE_CAPTURE_RECV_IMAGE: return "CAPTURE_RECV_IMAGE";
    case FPC_STATE_CAPTURE_CLEAR_IMAGE: return "CAPTURE_CLEAR_IMAGE";
    case FPC_STATE_CAPTURE_PROCESS: return "CAPTURE_PROCESS";
    case FPC_STATE_ABORTING: return "ABORTING";
    default: return "UNKNOWN";
  }
}

/* Преобразование операции в строку для логов */
static const gchar *
fpc_op_to_string(FpcOperation op)
{
  switch (op) {
    case FPC_OP_NONE: return "NONE";
    case FPC_OP_OPEN: return "OPEN";
    case FPC_OP_ENROLL: return "ENROLL";
    case FPC_OP_VERIFY: return "VERIFY";
    case FPC_OP_IDENTIFY: return "IDENTIFY";
    case FPC_OP_CAPTURE: return "CAPTURE";
    default: return "UNKNOWN";
  }
}

/* ============== Структура устройства ============== */

#define FPI_TYPE_DEVICE_FPC_A921 (fpi_device_fpc_a921_get_type())
G_DECLARE_FINAL_TYPE(FpiDeviceFpcA921, fpi_device_fpc_a921, FPI,
                     DEVICE_FPC_A921, FpDevice)

struct _FpiDeviceFpcA921
{
  FpDevice parent;

  /* --- Машина состояний --- */
  FpcState state; /* Текущее состояние */
  FpcOperation current_op; /* Текущая высокоуровневая операция */
  gboolean cancelling; /* Флаг запроса отмены */

  /* --- USB --- */
  guint8 session_id[4]; /* Идентификатор текущей сессии */

  /* --- OpenSSL TLS --- */
  SSL_CTX *ssl_ctx; /* Контекст SSL */
  SSL *ssl; /* Структура SSL соединения */
  BIO *rbio; /* BIO для чтения (шифрованные данные от устройства) */
  BIO *wbio; /* BIO для записи (шифрованные данные к устройству) */
  gboolean tls_ready; /* Флаг готовности TLS туннеля */
  gint handshake_iterations; /* Счетчик итераций handshake */

  /* --- Буфер отправки TLS --- */
  guint8 *tls_send_buf; /* Буфер данных для отправки */
  gsize tls_send_len; /* Общая длина */
  gsize tls_send_offset; /* Текущая позиция отправки */

  /* --- Буфер изображения --- */
  guint8 *image_buffer; /* Буфер для сырых данных изображения */
  gsize image_buffer_len; /* Текущая длина принятых данных */
  gsize image_buffer_alloc; /* Выделенный размер буфера */
  gint image_packet_count; /* Счетчик пакетов изображения */

  /* Временный буфер для чтения из TLS (избегаем аллокации на стеке) */
  guint8 tls_read_buf[4096]; 

  FpiUsbTransfer *active_transfer; /* Активный USB трансфер (для отслеживания) */

  /* --- Информация об устройстве --- */
  guint8 version[4]; /* Версия прошивки */
  gchar model[8]; /* Модель устройства */

  /* --- Данные для записи (Enroll) --- */
  GPtrArray *enroll_samples; /* Массив собранных отпечатков */
  gint enroll_stage; /* Текущий этап записи */
};

G_DEFINE_TYPE(FpiDeviceFpcA921, fpi_device_fpc_a921, FP_TYPE_DEVICE)

/* ============== Прототипы функций ============== */

static void fpc_ssm_next_state(FpiDeviceFpcA921 *self);
static void fpc_ssm_run_state(FpiDeviceFpcA921 *self);
static void fpc_complete_with_error(FpiDeviceFpcA921 *self, GError *error);
static void fpc_tls_cleanup(FpiDeviceFpcA921 *self);
static gboolean fpc_tls_init(FpiDeviceFpcA921 *self, GError **error);
static void fpc_process_captured_image(FpiDeviceFpcA921 *self);
static void fpc_dev_capture(FpDevice *device);
static void fpc_dev_cancel(FpDevice *device);

/* ============== Макросы логирования ============== */

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

/* ============== Вспомогательные функции ============== */

/* Вывод дампа данных в hex-виде */
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

/* Установка нового состояния с логированием перехода */
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

/* Поворот изображения на 90° против часовой стрелки: (64x176) -> (176x64)
 * Сырой датчик считывает строку вертикально, поэтому нужна трансформация.
 */
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

/* ============== Обработка ошибок ============== */

/* Завершение текущей операции с ошибкой */
static void
fpc_complete_with_error(FpiDeviceFpcA921 *self, GError *error)
{
  FpDevice *device = FP_DEVICE(self);
  FpcOperation op = self->current_op;

  fpc_err(self, "Error: %s", error->message);

  /* Сбрасываем флаги состояния */
  self->current_op = FPC_OP_NONE;
  self->cancelling = FALSE;
  fpc_set_state(self, FPC_STATE_NONE);

  /* Вызываем соответствующий callback завершения */
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

/* Колбэк для получения PSK ключа при рукопожатии */
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

/* ============== TLS Функции ============== */

/* Инициализация структуры OpenSSL для TLS соединения */
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

  /* Фиксируем версию TLS 1.2 */
  SSL_CTX_set_min_proto_version(self->ssl_ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(self->ssl_ctx, TLS1_2_VERSION);

  /* Устанавливаем допустимые шифры */
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

  /* Создаем BIO буферы в памяти */
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
  SSL_set_connect_state(self->ssl); /* Режим клиента */

  self->tls_ready = FALSE;
  self->handshake_iterations = 0;

  fpc_dbg(self, "TLS initialized (OpenSSL %s)",
          OpenSSL_version(OPENSSL_VERSION));

  return TRUE;
}

/* Очистка ресурсов TLS */
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

/* ============== USB Операции ============== */

/* Отправка Control команды (Host -> Device) */
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
  transfer->short_is_error = FALSE; /* Короткие пакеты не считаются ошибкой */

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

/* Чтение Control команды (Device -> Host) */
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

/* Чтение Bulk данных (Device -> Host) */
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

/* Общий колбэк завершения отправки команды */
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

/* Колбэк завершения команды ABORT */
static void
fpc_abort_cmd_cb(FpiUsbTransfer *transfer, FpDevice *device,
                 gpointer user_data, GError *error)
{
  FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

  if (error != NULL)
  {
    fpc_warn(self, "ABORT command failed: %s (continuing)", error->message);
    g_error_free(error);
  }

  fpc_dbg(self, "ABORTED");
  fpc_set_state(self, FPC_STATE_NONE);
  fpc_ssm_run_state(self);
}

/* Колбэк завершения команды CLR_IMG */
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

/* Обработка ответа на CMD_GET_STATE (инициализация) */
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

  /* Перед началом сессии очищаем буфер изображения от мусора */
  fpc_send_ctrl_cmd(self, CMD_CLR_IMG, 0, 0, NULL, 0, fpc_clr_img_cmd_cb);
}

/* Обработка ответа на инициализацию сессии */
static void
fpc_init_session_cb(FpiUsbTransfer *transfer, FpDevice *device,
                    gpointer user_data, GError *error)
{
  FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

  if (error != NULL)
  {
    /* Таймаут здесь нормален, устройство может ничего не ответить сразу */
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

/* Колбэк завершения отправки чанка TLS данных */
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
    /* Отправляем следующий чанк */
    fpc_ssm_run_state(self);
  }
  else
{
    /* Все данные отправлены, чистим буфер */
    g_clear_pointer(&self->tls_send_buf, g_free);
    self->tls_send_len = 0;
    self->tls_send_offset = 0;
    fpc_ssm_next_state(self);
  }
}

/* Прием TLS данных от устройства */
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
      /* Если данных нет, проверяем состояние handshake */
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

    /* Пакет может быть обернут в событие EVT_TLS */
    if (len >= 12 && data[0] == EVT_TLS)
    {
      fpc_dbg(self, "TLS event: %zu payload bytes", len - 12);
      BIO_write(self->rbio, data + 12, (int)(len - 12));
    }
    else
  {
      /* Или приходить сырым */
      fpc_dbg(self, "Raw data: %zu bytes", len);
      BIO_write(self->rbio, data, (int)len);
    }
  }

  fpc_ssm_next_state(self);
}

/* Ожидание нажатия пальца */
static void
fpc_wait_finger_cb(FpiUsbTransfer *transfer, FpDevice *device,
                   gpointer user_data, GError *error)
{
  FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

  /* Если была нажата отмена */
  if (self->cancelling)
  {
    fpc_dbg(self, "Operation cancelled");
    GError *cancel_err = g_error_new(G_IO_ERROR, G_IO_ERROR_CANCELLED, "Cancelled");
    fpc_complete_with_error(self, cancel_err);
    return;
  }

  if (error != NULL)
  {
    /* Обычный таймаут ожидания пальца - просто перезапускаем чтение */
    if (g_error_matches(error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT))
    {
      g_error_free(error);
      fpc_ssm_run_state(self);
      return;
    }

    /* Если это ошибка связи (кабель, отключение) - пробуем переинициализировать */
    fpc_warn(self, "USB Error waiting for finger: %s. Reinitializing.", error->message);
    fpc_tls_cleanup(self);
    fpc_set_state(self, FPC_STATE_INIT_INDICATE);
    fpc_ssm_run_state(self);
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
          /* Записываем зашифрованные данные в BIO */
          BIO_write(self->rbio,
                    transfer->buffer + 12,
                    (int)(transfer->actual_length - 12));

          /* Пытаемся расшифровать */
          SSL_read(self->ssl, self->tls_read_buf, sizeof(self->tls_read_buf));
        }
        fpc_ssm_run_state(self);
        break;

      case EVT_FINGER_DWN:
        fpc_dbg(self, "Finger detected!");
        /* Переходим к захвату изображения */
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

/* Прием пакетов изображения */
static void
fpc_recv_image_cb(FpiUsbTransfer *transfer, FpDevice *device,
                  gpointer user_data, GError *error)
{
  FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);
  const gsize expected_size = IMAGE_HEADER_SIZE +
    (gsize)IMAGE_RAW_WIDTH * IMAGE_RAW_HEIGHT;

  /* Если операция отменена */
  if (self->cancelling)
  {
    GError *cancel_error = g_error_new(G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                       "Operation cancelled");
    fpc_complete_with_error(self, cancel_error);
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
      /* Записываем шифротекст в BIO */
      int written = BIO_write(self->rbio, data + 12, (int)(len - 12));
      if (written <= 0) {
        fpc_warn(self, "BIO_write failed");
      }

      /* Читаем расшифрованные данные в цикле */
      int n;
      while ((n = SSL_read(self->ssl, self->tls_read_buf, sizeof(self->tls_read_buf))) > 0)
      {
        /* Расширяем буфер если нужно */
        if (self->image_buffer_len + (gsize)n > self->image_buffer_alloc)
        {
          gsize new_alloc = MAX(self->image_buffer_alloc * 2,
                                self->image_buffer_len + (gsize)n + 4096);
          guint8 *new_buf = g_realloc(self->image_buffer, new_alloc);
          if (!new_buf) {
            fpc_complete_with_error(self, g_error_new(G_IO_ERROR, G_IO_ERROR_FAILED, "OOM"));
            return;
          }
          self->image_buffer = new_buf;
          self->image_buffer_alloc = new_alloc;
        }

        /* Копируем данные */
        memcpy(self->image_buffer + self->image_buffer_len, self->tls_read_buf, (gsize)n);
        self->image_buffer_len += (gsize)n;
      }

      /* Проверка ошибок SSL */
      int ssl_err = SSL_get_error(self->ssl, n);
      if (n < 0 && ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
        fpc_warn(self, "SSL decryption error: %d", ssl_err);
        self->tls_ready = FALSE;
      }

      /* Проверка завершения приема изображения */
      if (self->image_buffer_len >= expected_size)
      {
        fpc_ssm_next_state(self);
        return;
      }
    }

    if (self->image_packet_count >= MAX_IMAGE_PACKETS)
    {
      fpc_warn(self, "Max image packets reached");
      fpc_ssm_next_state(self);
      return;
    }

    /* Читаем следующий пакет */
    fpc_ssm_run_state(self);
  }
  else
{
    fpc_ssm_next_state(self);
  }
}

/* ============== Машина состояний ============== */

/* Переход к следующему логическому состоянию */
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
      return; /* Логика переходов сложная, обрабатывается в run_state */
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

/* Исполнение текущего состояния (выполняет действия) */
static void
fpc_ssm_run_state(FpiDeviceFpcA921 *self)
{
  GError *error = NULL;

  fpc_dbg(self, "Running state");

  switch (self->state)
  {
    /* ===== Инициализация ===== */

    case FPC_STATE_INIT_INDICATE:
      /* Отправляем команду индикации состояния сна */
      fpc_send_ctrl_cmd(self, CMD_INDICATE_S_STATE, 0x0010, 0,
                        NULL, 0, fpc_ctrl_cmd_cb);
      break;

    case FPC_STATE_INIT_GET_STATE:
      /* Запрашиваем статус устройства (версия, модель) */
      fpc_recv_ctrl(self, CMD_GET_STATE, 0, 0, 76,
                    fpc_init_get_state_cb);
      break;

    case FPC_STATE_INIT_SEND_SESSION:
      /* Генерируем случайный ID сессии и отправляем устройству */
      RAND_bytes(self->session_id, sizeof(self->session_id));
      fpc_log_hex(self, "Session ID", self->session_id,
                  sizeof(self->session_id));
      fpc_send_ctrl_cmd(self, CMD_INIT, 0x0001, 0,
                        self->session_id, sizeof(self->session_id),
                        fpc_ctrl_cmd_cb);
      break;

    case FPC_STATE_INIT_RECV_SESSION:
      /* Ожидаем подтверждения от устройства (Bulk read) */
      fpc_recv_bulk(self, 64, USB_TIMEOUT_MS, fpc_init_session_cb);
      break;

    case FPC_STATE_INIT_SET_TLS_KEY:
      /* Устанавливаем ключи для TLS */
      fpc_dbg(self, "Setting TLS key");
      fpc_send_ctrl_cmd(self, CMD_SET_TLS_KEY, 0, 0,
                        TLS_KEY_DATA, sizeof(TLS_KEY_DATA),
                        fpc_ctrl_cmd_cb);
      break;

    /* ===== TLS Handshake ===== */

    case FPC_STATE_TLS_INIT_CMD:
      /* Инициализируем OpenSSL структуры локально */
      if (!fpc_tls_init(self, &error))
      {
        fpc_complete_with_error(self, error);
        return;
      }
      /* Запускаем TLS на устройстве */
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

        /* Пытаемся выполнить рукопожатие */
        ret = SSL_do_handshake(self->ssl);
        ssl_err = SSL_get_error(self->ssl, ret);

        fpc_dbg(self, "SSL_do_handshake: ret=%d err=%d", ret, ssl_err);

        if (ret == 1)
        {
          /* Успех! */
          self->tls_ready = TRUE;
          fpc_dbg(self, "TLS handshake complete! Cipher: %s",
                  SSL_get_cipher(self->ssl));

          /* Если мы в процессе открытия устройства - завершаем открытие */
          if (self->current_op == FPC_OP_OPEN)
          {
            self->current_op = FPC_OP_NONE;
            fpc_set_state(self, FPC_STATE_NONE);
            fpi_device_open_complete(FP_DEVICE(self), NULL);
          }
          else
        {
            /* Иначе начинаем захват */
            fpc_set_state(self, FPC_STATE_CAPTURE_ARM);
            fpc_ssm_run_state(self);
          }
          return;
        }

        /* OpenSSL хочет записать данные (отправить на устройство) */
        if (ssl_err == SSL_ERROR_WANT_WRITE ||
          BIO_ctrl_pending(self->wbio) > 0)
        {
          fpc_set_state(self, FPC_STATE_TLS_SEND_DATA);
          fpc_ssm_run_state(self);
          return;
        }

        /* OpenSSL хочет прочитать данные (ждет от устройства) */
        if (ssl_err == SSL_ERROR_WANT_READ)
        {
          fpc_set_state(self, FPC_STATE_TLS_RECV_DATA);
          fpc_ssm_run_state(self);
          return;
        }

        /* Неустранимая ошибка */
        g_set_error(&error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "SSL handshake failed: ssl_err=%d", ssl_err);
        ERR_print_errors_fp(stderr);
        fpc_complete_with_error(self, error);
      }
      break;

    case FPC_STATE_TLS_SEND_DATA:
      {
        /* Достаем данные из wbio для отправки */
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
        /* Отправляем данные частями (chunks) из-за ограничений устройства */
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

    /* ===== Захват изображения ===== */

    case FPC_STATE_CAPTURE_ARM:
      /* Переводим сенсор в режим ожидания пальца */
      fpc_dbg(self, "Arming sensor");
      fpc_send_ctrl_cmd(self, CMD_ARM, 0x0001, 0,
                        self->session_id, sizeof(self->session_id),
                        fpc_ctrl_cmd_cb);
      break;

    case FPC_STATE_CAPTURE_WAIT_FINGER:
      /* Ждем события по Bulk EP */
      fpc_recv_bulk(self, 64, FINGER_TIMEOUT_MS, fpc_wait_finger_cb);
      break;

    case FPC_STATE_CAPTURE_GET_IMAGE:
      /* Даем команду передать изображение */
      fpc_dbg(self, "Getting image");
      self->image_buffer_len = 0;
      self->image_packet_count = 0;
      fpc_send_ctrl_cmd(self, CMD_GET_IMG, 0, 0, NULL, 0,
                        fpc_ctrl_cmd_cb);
      break;

    case FPC_STATE_CAPTURE_RECV_IMAGE:
      /* Читаем пакеты изображения */
      fpc_recv_bulk(self, USB_BULK_BUF_SIZE, IMAGE_TIMEOUT_MS,
                    fpc_recv_image_cb);
      break;

    case FPC_STATE_CAPTURE_CLEAR_IMAGE:
      /* Очищаем память сенсора после чтения */
      fpc_send_ctrl_cmd(self, CMD_CLR_IMG, 0, 0, NULL, 0,
                        fpc_ctrl_cmd_cb);
      break;

    case FPC_STATE_CAPTURE_PROCESS:
      /* Обрабатываем полученные данные */
      fpc_process_captured_image(self);
      break;

    case FPC_STATE_NONE:
      break;
  }
}

/* ============== Обработка изображения ============== */

/* Запуск захвата изображения (API) */
static void
fpc_dev_capture(FpDevice *device)
{
  FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

  fpc_dbg(self, "Starting capture");

  self->current_op = FPC_OP_CAPTURE;

  /* Если TLS уже поднят, пропускаем инициализацию */
  if (self->tls_ready)
  {
    fpc_set_state(self, FPC_STATE_CAPTURE_ARM);
    fpc_ssm_run_state(self);
  }
  else
{
    /* Иначе поднимаем сессию с нуля */
    fpc_set_state(self, FPC_STATE_INIT_INDICATE);
    fpc_ssm_run_state(self);
  }
}

/* Обработка принятого изображения: поворот, распознавание, сохранение */
static void
fpc_process_captured_image(FpiDeviceFpcA921 *self)
{
  FpDevice *device = FP_DEVICE(self);
  const gsize expected_size = IMAGE_HEADER_SIZE +
    (gsize)IMAGE_RAW_WIDTH * IMAGE_RAW_HEIGHT;
  GError *error = NULL;

  fpc_dbg(self, "Processing image: %zu bytes", self->image_buffer_len);

  /* Проверка размера */
  if (self->image_buffer_len < expected_size)
  {
    g_set_error(&error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                "Incomplete image: %zu < %zu",
                self->image_buffer_len, expected_size);
    fpc_complete_with_error(self, error);
    return;
  }

  /* Выделяем память под развернутое изображение */
  guint8 *rotated = g_malloc(IMAGE_WIDTH * IMAGE_HEIGHT);
  const guint8 *raw_data = self->image_buffer + IMAGE_HEADER_SIZE;
  fpc_rotate_90_ccw(raw_data, rotated, IMAGE_RAW_WIDTH, IMAGE_RAW_HEIGHT);

  /* Логика в зависимости от текущей операции */
  switch (self->current_op)
  {
    /* Простой захват (для теста или UI) */
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

    /* Запись отпечатка (Enroll) */
    case FPC_OP_ENROLL:
      {
        /* Извлекаем особенности (SIFT/Features) */
        FpiCustomFeatures *features = fpi_custom_extract_features(
          rotated, IMAGE_WIDTH, IMAGE_HEIGHT
        );

        gsize feature_count = features ? fpi_custom_features_get_count(features) : 0;
        fpc_dbg(self, "Extracted %zu features", feature_count);

        if (feature_count < FPI_CUSTOM_MIN_FEATURES)
        {
          fpi_custom_features_free(features);
          g_free(rotated);

          /* Плохое качество - просим повторить */
          fpc_warn(self, "Not enough features, retrying");
          fpi_device_enroll_progress(device, self->enroll_stage, NULL,
                                     g_error_new(FP_DEVICE_ERROR,
                                                 FP_DEVICE_ERROR_DATA_NOT_FOUND,
                                                 "Poor image quality, please try again"));

          fpc_set_state(self, FPC_STATE_CAPTURE_ARM);
          fpc_ssm_run_state(self);
          return;
        }

        /* Добавляем образец в массив */
        g_ptr_array_add(self->enroll_samples, features);
        self->enroll_stage++;

        fpc_dbg(self, "Enroll stage %d/%d complete",
                self->enroll_stage, ENROLL_STAGES);

        if (self->enroll_stage >= ENROLL_STAGES)
        {
          /* Выбираем лучший образец с макс. числом особенностей */
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

          /* Сериализуем и сохраняем */
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
          /* Переход к следующему этапу */
          fpi_device_enroll_progress(device, self->enroll_stage,
                                     NULL, NULL);
          fpc_set_state(self, FPC_STATE_CAPTURE_ARM);
          fpc_ssm_run_state(self);
        }
      }
      break;

    /* Верификация (Verify) */
    case FPC_OP_VERIFY:
      {
        FpPrint *enrolled = NULL;
        GVariant *enrolled_data = NULL;
        FpiMatchResult result = FPI_MATCH_FAIL;

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

        /* Получаем сохраненный шаблон */
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

        /* Десериализация и сравнение */
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

    /* Идентификация (Identify) */
    case FPC_OP_IDENTIFY:
      {
        GPtrArray *prints = NULL;
        FpPrint *match = NULL;
        gint best_score = 0;

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

        /* Получаем базу для поиска */
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

        /* Перебор всех сохраненных отпечатков */
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

        /* Проверка на лучший результат */
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

/* ============== Операции устройства (API libfprint) ============== */

/* Открытие устройства */
static void
fpc_dev_open(FpDevice *device)
{
  FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);
  GError *error = NULL;
  GUsbDevice *usb_dev;

  fpc_dbg(self, "Opening device");

  usb_dev = fpi_device_get_usb_device(device);

  /* Захватываем интерфейс USB */
  if (!g_usb_device_claim_interface(usb_dev, 0, 0, &error))
  {
    fpi_device_open_complete(device, error);
    return;
  }

  /* Выделяем память */
  self->image_buffer_alloc = MAX_TLS_BUF;
  self->image_buffer = g_malloc(self->image_buffer_alloc);
  self->image_buffer_len = 0;

  self->enroll_samples = g_ptr_array_new_with_free_func(
    (GDestroyNotify)fpi_custom_features_free
  );

  /* Пытаемся сбросить устройство */
  if (!g_usb_device_reset(usb_dev, &error))
  {
    fpc_warn(self, "USB reset failed: %s", error->message);
    g_error_free(error);
  }

  /* Запускаем инициализацию и TLS handshake */
  self->current_op = FPC_OP_OPEN;
  fpc_set_state(self, FPC_STATE_INIT_INDICATE);
  fpc_ssm_run_state(self);
}

/* Закрытие устройства */
static void
fpc_dev_close(FpDevice *device)
{
  FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);
  GError *error = NULL;
  GUsbDevice *usb_dev;

  fpc_dbg(self, "Closing device");

  /* Чистим TLS */
  fpc_tls_cleanup(self);

  /* Освобождаем буферы */
  g_clear_pointer(&self->image_buffer, g_free);
  self->image_buffer_alloc = 0;
  self->image_buffer_len = 0;

  /* Чистим массив enroll */
  if (self->enroll_samples)
  {
    g_ptr_array_free(self->enroll_samples, TRUE);
    self->enroll_samples = NULL;
  }

  /* Отпускаем интерфейс USB */
  usb_dev = fpi_device_get_usb_device(device);
  g_usb_device_release_interface(usb_dev, 0, 0, &error);

  fpi_device_close_complete(device, error);
}

/* Начало записи отпечатка */
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
    fpc_dbg(self, "Enroll template from fprintd: username: '%s', finger: %d",
            username ? username : "(NULL)", finger);
  }
  else
{
    fpc_warn(self, "No enroll template from fprintd!");
  }

  /* Сброс состояния записи */
  g_ptr_array_set_size(self->enroll_samples, 0);
  self->enroll_stage = 0;

  self->current_op = FPC_OP_ENROLL;

  /* Проверяем TLS */
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

/* Верификация */
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

/* Идентификация */
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

/* Отмена текущей операции */
static void
fpc_dev_cancel(FpDevice *device)
{
  FpiDeviceFpcA921 *self = FPI_DEVICE_FPC_A921(device);

  fpc_dbg(self, "Cancelling operation");

  /* Если уже не отменено и есть активное состояние */
  if (!self->cancelling && self->state != FPC_STATE_NONE)
  {
    self->cancelling = TRUE;
    /* 
* Важно: отправляем команду ABORT на устройство, чтобы вывести его 
* из режима ожидания пальца. Используем колбэк, чтобы дождаться подтверждения.
*/
    fpc_send_ctrl_cmd(self, CMD_ABORT, 0x0001, 0, NULL, 0, fpc_abort_cmd_cb);
  }
  else
{
    fpc_dbg(self, "No active operation to cancel");
  }
}

/* ============== GObject Implementation ============== */

/* Инициализация объекта */
static void
fpi_device_fpc_a921_init(FpiDeviceFpcA921 *self)
{
  self->state = FPC_STATE_NONE;
  self->current_op = FPC_OP_NONE;
  self->cancelling = FALSE;
  memset(self->session_id, 0, sizeof(self->session_id));
  self->ssl_ctx = NULL;
  self->ssl = NULL;
  self->rbio = NULL;
  self->wbio = NULL;
  self->tls_ready = FALSE;
  self->handshake_iterations = 0;
  self->tls_send_buf = NULL;
  self->tls_send_len = 0;
  self->tls_send_offset = 0;
  self->image_buffer = NULL;
  self->image_buffer_len = 0;
  self->image_buffer_alloc = 0;
  self->image_packet_count = 0;
  memset(self->version, 0, sizeof(self->version));
  memset(self->model, 0, sizeof(self->model));
  self->enroll_samples = NULL;
  self->enroll_stage = 0;
}

/* Финализация объекта (очистка перед удалением) */
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

/* Таблица совместимых USB устройств */
static const FpIdEntry fpc_id_table[] = {
  { .vid = FPC_VID, .pid = FPC_PID },
  { .vid = 0, .pid = 0 },
};

/* Инициализация класса */
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

  /* Поддерживаемые функции */
  dev_class->features = FP_DEVICE_FEATURE_CAPTURE |
    FP_DEVICE_FEATURE_IDENTIFY |
    FP_DEVICE_FEATURE_VERIFY;

  /* Привязка реализаций к виртуальным методам */
  dev_class->open = fpc_dev_open;
  dev_class->close = fpc_dev_close;
  dev_class->enroll = fpc_dev_enroll;
  dev_class->verify = fpc_dev_verify;
  dev_class->identify = fpc_dev_identify;
  dev_class->capture = fpc_dev_capture;
  dev_class->cancel = fpc_dev_cancel;
}
