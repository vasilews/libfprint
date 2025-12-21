# libfprint с поддержкой FPC A921

Форк [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) с добавлением драйвера для сканера отпечатков пальцев **FPC A921** (USB VID:PID `10A5:A921`).

---

## Проверка устройства

Убедитесь, что ваш сканер подключён и определяется системой:

```bash
lsusb | grep -i 10a5:a921
```

Если устройство найдено, вы увидите строку с `10a5:a921`. Если вывод пустой — устройство не подключено или не распознаётся.

---

## Установка

### Ubuntu 22.04

#### Шаг 1: Установка зависимостей

```bash
sudo apt-get update
sudo apt-get install \
    python3 \
    ninja-build \
    meson \
    git \
    build-essential \
    pkg-config \
    cmake \
    libglib2.0-dev \
    libgusb-dev \
    libcairo2-dev \
    libgirepository1.0-dev \
    libssl-dev \
    libgudev-1.0-dev \
    libopencv-dev \
    gtk-doc-tools \
    fprintd \
    libpam-fprintd
```

#### Шаг 2: Проверка текущего состояния

После установки fprintd в системе должна быть установлена стандартная libfprint:

```bash
ldconfig -p | grep libfprint
```

Ожидаемый вывод:
```
libfprint-2.so.2 (libc6,x86-64) => /lib/x86_64-linux-gnu/libfprint-2.so.2
```

#### Шаг 3: Клонирование и сборка

```bash
git clone https://github.com/vasilews/libfprint.git
cd libfprint

meson setup build --prefix=/usr/local --libdir=/usr/local/lib/x86_64-linux-gnu
meson compile -C build
sudo meson install -C build
```

**Пояснение параметров сборки:**
- `--prefix=/usr/local` — устанавливает библиотеку в `/usr/local`, не затрагивая системные файлы
- `--libdir=/usr/local/lib/x86_64-linux-gnu` — указывает правильный путь для библиотек на 64-битной системе

> ⚠️ **Не используйте** `--prefix=/usr` — это перезапишет системную библиотеку, и при обновлении системы возникнут конфликты.

#### Шаг 4: Настройка приоритета библиотеки (Пропустите создание 00-local.conf, если приоритет настроен `grep "/usr/local/lib/x86_64-linux-gnu" /etc/ld.so.conf.d/*`)

Чтобы система использовала собранную библиотеку вместо системной:

```bash
echo "/usr/local/lib/x86_64-linux-gnu" | sudo tee /etc/ld.so.conf.d/00-local.conf
sudo ldconfig
```

#### Шаг 5: Проверка установки

Убедитесь, что собранная библиотека имеет приоритет:

```bash
ldconfig -p | grep libfprint
```

Ожидаемый вывод (ваша версия должна быть **первой**):
```
libfprint-2.so.2 (libc6,x86-64) => /usr/local/lib/x86_64-linux-gnu/libfprint-2.so.2
libfprint-2.so.2 (libc6,x86-64) => /lib/x86_64-linux-gnu/libfprint-2.so.2
libfprint-2.so (libc6,x86-64) => /usr/local/lib/x86_64-linux-gnu/libfprint-2.so
```

Проверьте, что fprintd использует правильную библиотеку:

```bash
sudo ldd /usr/libexec/fprintd | grep libfprint
```

Ожидаемый вывод:
```
libfprint-2.so.2 => /usr/local/lib/x86_64-linux-gnu/libfprint-2.so.2
```

#### Шаг 6: Перезапуск сервиса и регистрация отпечатка

```bash
sudo systemctl restart fprintd.service
fprintd-enroll $USER
```

---

### Arch Linux

#### Шаг 1: Установка зависимостей

```bash
sudo pacman -Syu \
    base-devel \
    meson \
    ninja \
    cmake \
    git \
    libgusb \
    openssl \
    gtk-doc \
    pixman \
    nss \
    gobject-introspection \
    glib2-devel \
    opencv \
    hdf5 \
    vtk \
    fprintd
```

#### Шаг 2: Сборка и установка

```bash
git clone https://github.com/vasilews/libfprint.git
cd libfprint

meson setup build --prefix=/usr/local
meson compile -C build
sudo meson install -C build
```

#### Шаг 3: Настройка и проверка
```bash
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/00-local.conf
sudo ldconfig
sudo systemctl restart fprintd.service
fprintd-enroll $USER
```

---

## Использование

```bash
# Регистрация отпечатка
fprintd-enroll $USER

# Проверка отпечатка
fprintd-verify $USER

# Список зарегистрированных отпечатков
fprintd-list $USER

# Удаление отпечатков
fprintd-delete $USER
```

---

## Откат изменений

Если нужно вернуть систему к исходному состоянию:

```bash
# Удалите собранную библиотеку
cd libfprint/build
sudo ninja uninstall

# Удалите конфигурацию приоритета 
sudo rm /etc/ld.so.conf.d/00-local.conf # Arch Linux
sudo ldconfig

# Переустановите системную версию
sudo apt install --reinstall libfprint-2-2  # Ubuntu/Debian
# или
sudo pacman -S libfprint                     # Arch Linux

# Перезапустите сервис
sudo systemctl restart fprintd.service
```

---

## Решение проблем

### Ошибка "pam_fprintd.so: cannot open shared object file"

```bash
sudo apt install --reinstall libpam-fprintd
```

### Проверка логов

```bash
sudo journalctl -u fprintd.service -f
```

---

## Лицензия

LGPL-2.1 — см. файл [COPYING](COPYING)

## Оригинальный проект

- Репозиторий: https://gitlab.freedesktop.org/libfprint/libfprint
- Документация: https://fprint.freedesktop.org/
