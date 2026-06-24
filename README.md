<!-- Язык / Language: [Русский](#t3chatm) · [English](#t3chatm-en) -->

<a name="t3chatm"></a>
# T3ChatM

**Telegram, который работает в РФ — без VPN и без настройки.**

Форк Telegram со встроенным транспортом **Type3 (mtProxy3)**: трафик идёт внутри
обычного HTTPS, поэтому DPI/ТСПУ видит веб-трафик, а не Telegram. Прокси уже
зашит в сборку — скачал и открыл.

## Скачать

| Платформа | Ссылка |
|---|---|
| Desktop (Windows / macOS / Linux) | https://github.com/ankuper/tdesktop/releases/latest |
| Android (APK) | https://github.com/ankuper/telegram-android/releases/latest |
| iOS | https://github.com/ankuper/telegram-ios/releases |

Установи и открой. Настраивать ничего не нужно — прокси встроен.

## Свой прокси (независимость / резерв)

Если дефолтный прокси недоступен — подними свой
[teleproxy](https://github.com/ankuper/teleproxy) (~5 мин, Docker) и укажи его в
**Настройки → Подключение → Прокси**.

## Как это работает

MTProto заворачивается в HTTP-stream поверх TLS (протокол **Type3**) — для DPI
неотличимо от обычного HTTPS. Описание протокола и библиотека:
[teleproto3](https://github.com/ankuper/teleproto3).

---

<a name="t3chatm-en"></a>
# T3ChatM (English)

**Telegram that works under censorship — no VPN, no setup.**

A Telegram fork with the built-in **Type3 (mtProxy3)** transport: traffic is
tunneled inside ordinary HTTPS, so DPI sees web traffic, not Telegram. The proxy
is baked into the build — just download and open.

## Download

| Platform | Link |
|---|---|
| Desktop (Windows / macOS / Linux) | https://github.com/ankuper/tdesktop/releases/latest |
| Android (APK) | https://github.com/ankuper/telegram-android/releases/latest |
| iOS | https://github.com/ankuper/telegram-ios/releases |

Install and open. No configuration needed — the proxy is built in.

## Run your own proxy (independence / fallback)

Run your own [teleproxy](https://github.com/ankuper/teleproxy) (~5 min, Docker)
and set it in **Settings → Connection → Proxy**.

## How it works

MTProto is wrapped in an HTTP-stream over TLS (the **Type3** protocol) — to DPI
it's indistinguishable from regular HTTPS. Protocol spec and library:
[teleproto3](https://github.com/ankuper/teleproto3).

---

## Поддержать инфраструктуру · Support

Проект держится на одном прокси. Поддержать сервера (TON):

`UQAYS0k0PEky8BUE1Rij90v8-CmOWsuhAzdLTHOzYC-qZ0pV`

The project runs on a single proxy. Support the servers (TON) — address above.

---

> Независимый форк, не аффилирован с Telegram Messenger.
> Independent fork, not affiliated with Telegram Messenger.
