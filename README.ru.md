# ssh-tun

[English documentation](README.md)

**Версия 1.0.3**

`ssh-tun` — автономный сетевой прокси для Linux и Windows, который передаёт HTTP, HTTPS CONNECT, SOCKS5 и TUN-трафик через SSH. Поддерживаются промежуточные SSH-узлы, правила маршрутизации, отображение подсетей, автоматическое переподключение, установка нативной службы и создание шаблона конфигурации для текущей ОС.

Репозиторий: <https://github.com/zukhovich/ssh-tun>

## Возможности

- HTTP- и HTTPS CONNECT-прокси через SSH.
- SOCKS5 CONNECT для IPv4, IPv6 и доменных имён.
- TUN-режим IPv4 с пересылкой TCP и DNS.
- Прямая передача, SSH-прокси или блокировка по правилам YAML.
- Цепочки промежуточных SSH-узлов.
- Подтверждение ключа SSH-сервера при первом подключении в стиле OpenSSH и строгая проверка его изменений.
- Английский и русский интерфейс командной строки.
- Строгая конфигурация приложения в YAML.
- Настройка системного прокси GNOME с восстановлением состояния.
- Установка нативных служб systemd, OpenRC и Windows Service.
- Создание шаблона конфигурации для текущей ОС.
- Мониторинг SSH-канала и автоматическое переподключение.
- Статические Linux- и автономные Windows-бинарники для `amd64` и `arm64`.

## Установка

Установка версии 1.0.3 из GitHub Releases:

```sh
curl -fsSL https://raw.githubusercontent.com/zukhovich/ssh-tun/main/scripts/install.sh | sh
```

Установка в выбранный каталог:

```sh
curl -fsSL https://raw.githubusercontent.com/zukhovich/ssh-tun/main/scripts/install.sh |
  sh -s -- --version 1.0.3 --install-dir "$HOME/bin"
```

## Сборка

Требуется Go 1.25.5 или новее.

```sh
git clone https://github.com/zukhovich/ssh-tun.git
cd ssh-tun
make test vet build
file build/ssh-tun
```

Основной результат — `build/ssh-tun`, статически скомпонованный и очищенный Linux-бинарник. Релизная упаковка также создаёт автономные бинарники Linux и Windows для `amd64` и `arm64`.

Релизные архивы и контрольные суммы:

```sh
make package-release
```

## Быстрый запуск

Подключайтесь напрямую: при первом запуске проверьте показанный отпечаток ключа сервера и ответьте `yes`. Принятый ключ автоматически сохранится в `~/.ssh/known_hosts`:

```sh
ssh-tun user@example.com --http 127.0.0.1:8080 --socks5 127.0.0.1:1080
```

Использование конкретного закрытого ключа через `-i`/`--identity-file`:

```sh
ssh-tun user@example.com --identity-file ~/.ssh/id_ed25519
```

Если файл ключа не указан, `ssh-tun` использует ключи из `ssh-agent`, а затем пробует стандартные незашифрованные файлы в `~/.ssh`. Для защищённого парольной фразой файла ключа доступен интерактивный запрос; для неинтерактивного запуска добавьте ключ в `ssh-agent`. Доступные ключи, пароль и keyboard-interactive предлагаются серверу за одно SSH-рукопожатие.

Настройка системного прокси рабочего стола по умолчанию выключена и не обязательна. Для интеграции с GNOME используйте `--sys-proxy`. Если `gsettings` отсутствует, ssh-tun выводит предупреждение и продолжает работу локальных прокси.

Использование прокси:

```sh
curl -x http://127.0.0.1:8080 https://example.org
curl --proxy socks5h://127.0.0.1:1080 https://example.org
```

## Конфигурация

Создание шаблона для текущей операционной системы (пути `~/.ssh` в Linux и `%USERPROFILE%`/`%PROGRAMDATA%` в Windows):

```sh
ssh-tun --write-config ./ssh-tun.yaml
```

Готовые примеры для Linux также находятся в [`configs/linux/config.yaml`](configs/linux/config.yaml) и [`configs/linux/rules.yaml`](configs/linux/rules.yaml).

Запуск:

```sh
ssh-tun --config ./ssh-tun.yaml
```

Приоритет настроек: встроенные значения, YAML, явно указанные параметры CLI. Неизвестные поля YAML считаются ошибкой. Не рекомендуется хранить пароли в YAML; используйте SSH-ключи или защищённое хранилище секретов.

## Правила маршрутизации

```yaml
mode: rule
rules:
  - DOMAIN-SUFFIX,example.org,DIRECT
  - DOMAIN,blocked.example.org,REJECT
  - IP-CIDR,10.0.0.0/8,PROXY
  - MATCH,,PROXY
```

Режимы: `rule`, `direct`, `global`. Действия: `PROXY`, `DIRECT`, `REJECT`. Используется первое совпавшее правило.

## TUN-режим

```sh
sudo ssh-tun user@example.com --tun-route 10.20.0.0/16
sudo ssh-tun user@example.com --tun-global
```

В Linux для TUN нужны права root и `iproute2`, в Windows — консоль с повышенными правами администратора. Версия 1.0.3 пересылает IPv4 TCP и DNS; произвольная пересылка UDP не реализована.

## Язык

```sh
ssh-tun --lang en --help
ssh-tun --lang ru --help
```

Поле `language` в YAML принимает `en` или `ru`. Без файла конфигурации и параметра `--lang` по умолчанию используется английский язык независимо от локали системы.

## Автоматическое переподключение

Мониторинг SSH-канала и автоматическое переподключение без перезапуска локальных HTTP/SOCKS listener-ов:

```sh
ssh-tun user@example.com --auto-reconnect \
  --keepalive-interval 15s --reconnect-interval 5s
```

В YAML используются параметры `ssh.auto_reconnect`, `ssh.keepalive_interval` и `ssh.reconnect_interval`.

## systemd, OpenRC и службы Windows

Сначала создайте постоянную конфигурацию:

```sh
sudo mkdir -p /etc/ssh-tun
sudo ssh-tun --write-config /etc/ssh-tun/config.yaml
sudo chmod 600 /etc/ssh-tun/config.yaml
```

Установка и удаление нативной службы с автоматическим выбором для текущей ОС:

```sh
ssh-tun --config /path/to/config.yaml --install-service auto
ssh-tun --config /path/to/config.yaml --remove-service auto
```

В Linux `auto` выбирает systemd или OpenRC. В Windows служба создаётся и удаляется через `sc.exe`; консоль необходимо запустить от имени администратора. В Linux нужны права root. Служба должна использовать неинтерактивную SSH-аутентификацию. `--sys-proxy` предназначен для пользовательской сессии GNOME и обычно должен быть отключён в службе.

## Безопасность

- Никогда не публикуйте закрытые ключи, пароли, токены, созданный `known_hosts` и реальные производственные конфигурации.
- Проверка ключа SSH-сервера включена по умолчанию.
- `--insecure-host-key` отключает проверку и небезопасен.
- `--pass` раскрывает пароль через аргументы процесса; рекомендуется SSH-ключ.
- Без необходимости не открывайте прокси на внешнем сетевом интерфейсе.
- Штатное завершение восстанавливает маршруты и параметры прокси. `SIGKILL` не позволяет выполнить очистку.

## Лицензия

`ssh-tun` распространяется на условиях [лицензии MIT](LICENSE).
