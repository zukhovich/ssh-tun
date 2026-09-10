# ssh-tun

[English documentation](README.md)

**Версия 1.0.2**

`ssh-tun` — сетевой прокси для Linux, который передаёт HTTP, HTTPS CONNECT, SOCKS5 и TUN-трафик через SSH. Поддерживаются промежуточные SSH-узлы, правила маршрутизации, отображение подсетей, настройка прокси GNOME и установка службы systemd/OpenRC.

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
- Установка служб systemd и OpenRC.
- Статические бинарные файлы Linux для `amd64` и `arm64`.

## Установка

Установка версии 1.0.2 из GitHub Releases:

```sh
curl -fsSL https://raw.githubusercontent.com/zukhovich/ssh-tun/main/scripts/install.sh | sh
```

Установка в выбранный каталог:

```sh
curl -fsSL https://raw.githubusercontent.com/zukhovich/ssh-tun/main/scripts/install.sh |
  sh -s -- --version 1.0.2 --install-dir "$HOME/bin"
```

## Сборка

Требуется Go 1.25.5 или новее.

```sh
git clone https://github.com/zukhovich/ssh-tun.git
cd ssh-tun
make test vet build
file build/ssh-tun
```

Результат `build/ssh-tun` собирается с `CGO_ENABLED=0` как статически скомпонованный исполняемый файл Linux.

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

Создание полного шаблона:

```sh
ssh-tun --write-config ./ssh-tun.yaml
```

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

Нужны права root и `iproute2`. Версия 1.0.2 пересылает IPv4 TCP и DNS; произвольная пересылка UDP не реализована.

## Язык

```sh
ssh-tun --lang en --help
ssh-tun --lang ru --help
```

Поле `language` в YAML принимает `en` или `ru`. Без файла конфигурации и параметра `--lang` по умолчанию используется английский язык независимо от локали системы.

## systemd и OpenRC

Сначала создайте постоянную конфигурацию:

```sh
sudo mkdir -p /etc/ssh-tun
sudo ssh-tun --write-config /etc/ssh-tun/config.yaml
sudo chmod 600 /etc/ssh-tun/config.yaml
```

Установка и удаление службы:

```sh
sudo ssh-tun --config /etc/ssh-tun/config.yaml --install-service auto
sudo ssh-tun --config /etc/ssh-tun/config.yaml --remove-service auto
```

Вместо `auto` можно явно указать `systemd` или `openrc`. Служба должна использовать неинтерактивную SSH-аутентификацию. `--sys-proxy` предназначен для пользовательской сессии GNOME и обычно должен быть отключён в службе root.

## Безопасность

- Проверка ключа SSH-сервера включена по умолчанию.
- `--insecure-host-key` отключает проверку и небезопасен.
- `--pass` раскрывает пароль через аргументы процесса; рекомендуется SSH-ключ.
- Без необходимости не открывайте прокси на внешнем сетевом интерфейсе.
- Штатное завершение восстанавливает маршруты и параметры прокси. `SIGKILL` не позволяет выполнить очистку.

## Лицензия

`ssh-tun` распространяется на условиях [лицензии MIT](LICENSE).
