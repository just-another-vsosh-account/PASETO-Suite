# PASETO Suite

Набор инструментов для работы с PASETO токенами - PASETO Suite.

## Установка
```bash
git clone https://github.com/asd_dever/paseto-suite.git
```
### Установка CLI
```bash
pip install -e .
```
или
```bash
python setup.py install
```

## Использование

После установки вы можете использовать команду `pasuite` в терминале:

```bash
pasuite [опции] [команды]
```

## Запуск

### Запуск всего набора
```bash
docker compose up -d
```

### Запуск CLI
```bash
python -m cliwrap.py
```
или
```bash
docker build -t pasuite . -f cli.Dockerfile
docker run -it pasuite
```

### Запуск сайта
```bash
docker build -t pasuite . -f web.Dockerfile
docker run -d -p 8080:8080 pasuite
```

## Зависимости

- argon2-cffi
- cryptography
- pynacl

## Лицензия

Apache Software License 2.0
