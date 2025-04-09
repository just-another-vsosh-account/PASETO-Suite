import json
import os
import argparse
import re
from lib import *
import getpass

def info(args):
    if not args.paseto:
        while True:
            args.paseto = input("Введите токен: ")
            paseto_pattern = r'^v[1-4]\.(local|public)\.[A-Za-z0-9\-_]+(\.[A-Za-z0-9\-_]+)?$'
            if re.match(paseto_pattern, args.paseto):
                break
            else:
                print("Неправильный формат токена. Попробуйте снова.")
    if not args.key and args.paseto.split('.')[1] == "public":
        print("Для публичного токена требуется указать файл ключа при помощи -kf")
        return
    elif not args.key:
        args.key = getpass.getpass("Введите ключ: ").strip() 
    if not args.nokey:
        args.nokey = input("Выводить ключ?(N, y)") == "N"
    
    try:
        token = PasetoToken.from_paseto(args.key, args.paseto)
        print(f"Информация о токене:")
        print(f"Token: {args.paseto}")
        print(f"Версия: {token.version}")
        print(f"Тип: {token.purpose}")
        
        payload = token.payload
        if isinstance(payload, bytes):
            try:
                payload = payload.decode('utf-8')
                if payload.startswith('{') or payload.startswith('['):
                    payload = json.loads(payload)
            except:
                payload = payload.hex()  
                
        footer = token.footer
        if isinstance(footer, bytes):
            try:
                footer = footer.decode('utf-8')
                if footer.startswith('{') or footer.startswith('['):
                    footer = json.loads(footer)
            except:
                footer = footer.hex()
                
        print(f"Тело: {json.dumps(payload, indent=4, ensure_ascii=False)}")
        print(f"Доп информация: {json.dumps(footer, indent=4, ensure_ascii=False)}")
        if not args.nokey:
            print(f"Ключ: {args.key}")
    except Exception as e:
        print(f"Ошибка: {str(e)}")

def sign(args):
    if not args.data:
        print(f"Пожалуйста, используйте -d для указания файла с телом токена")
        return

    try:
        # Version validation
        if not args.version:
            while True:
                args.version = input('Введите версию (1-4): ').strip()
                if args.version in ['1', '2', '3', '4']:
                    break
                print("Неверная версия. Используйте 1-4")

        # Purpose validation
        if not args.purpose:
            while True:
                args.purpose = input('Введите версию(l - local, p - public): ').strip()
                if args.purpose in ['l', 'p']:
                    break
                print("Неверное назначение. Используйте 'l' для local или 'p' для public")
            args.purpose = 'public' if args.purpose == 'p' else 'local'

        try:
            with open(args.data) as f:
                data = json.load(f)
        except json.JSONDecodeError:
            print("Ошибка: Неверный формат JSON файла")
            return
        except FileNotFoundError:
            print(f"Ошибка: Файл данных не найден - {args.data}")
            return
        
        if args.version == '3' and args.purpose == 'public' and len(data) <= 96:
            print("Ограничение на размер тела токена для версии 3 и публичного ключа - не менее 96 байт")
            return

        # Key handling
        key = None
        if args.keyfile:
            key = args.keyfile.read().strip().encode()
        elif args.key:
            key = args.key.encode()
        elif args.purpose == "public":
            print("Для публичного токена требуется указать файл ключа при помощи -kf")
            return
        else:
            key_input = getpass.getpass("Введите ключ: ").strip()
            if key_input:
                key = key_input.encode()
            else:
                key = None  

        footer = None
        if args.footer:
            try:
                with open(args.footer) as f:
                    footer = json.load(f)
            except json.JSONDecodeError:
                print("Ошибка: Неверный формат JSON файла футера")
                return
            except FileNotFoundError:
                print(f"Ошибка: Файл футера не найден - {args.footer}")
                return

        try:
            token = PasetoToken(
                key=key,
                version=args.version,
                purpose=args.purpose,
                payload=data,
                footer=footer
            )
            
            result = token.sign() if args.purpose == "public" else token.encrypt()
            result = result.decode()
            if result == -1:
                print("Ошибка: Неверная длина ключа")
                return
                
            print(f"Сгенерированный токен: {result}")
            
            if args.output:
                with open(args.output.name, 'w') as f:
                    f.write(result)
                print(f"Токен сохранен в файл: {args.output.name}")
                
        except ValueError as e:
            print(f"Ошибка при создании токена: {str(e)}")
        except Exception as e:
            print(f"Неожиданная ошибка: {str(e)}")
            
    except Exception as e:
        print(f"Неожиданная ошибка: {str(e)}")

def check(args):
    if not args.paseto:
        while True:
            args.paseto = input("Введите токен: ")
            paseto_pattern = r'^v[1-4]\.(local|public)\.[A-Za-z0-9\-_]+(\.[A-Za-z0-9\-_]+)?$'
            if re.match(paseto_pattern, args.paseto):
                break
    key = None
    if args.keyfile:
        key = args.keyfile.read().strip().encode()
    elif args.key:
        key = args.key.encode()  
    elif args.purpose == "public":
        print("Для публичного токена требуется указать файл ключа при помощи -kf")
        return
    else:
        key_input = getpass.getpass("Введите ключ: ").strip()
        if key_input:
            key = key_input.encode()
        else:
            key = None
    try:
        token = PasetoToken.from_paseto(key, args.paseto)
        print(f"Проверка подписи: {token.verify()}")
    except Exception as e:
        print(f"Ошибка проверки подписи: {str(e)}")

def wrap(args):
    if not args.version:
        while args.version not in ['1', '2', '3', '4', 'v1', 'v2', 'v3', 'v4']:
            args.version = input('Введите версию: ')
    if not args.purpose:
        while i not in ['l', 'p']:
            i = input('Введите версию(l - local, p - public): ')
        args.purpose = ['local', 'public'][i == 'l']
    if args.purpose == 'public' and not args.keyfile:
        print("Для публичного токена требуется указать файл ключа при помощи -kf")
        return
    if not args.key:
        args.key = getpass.getpass("Введите ключ: ").strip().encode()
    print(f"Wrapped key: {PASERKHandler.wrap(args.version, args.purpose, args.key)}")

def unwrap(args):
    if not args.version:
        while args.version not in ['1', '2', '3', '4', 'v1', 'v2', 'v3', 'v4']:
            args.version = input('Введите версию: ')
    if not args.purpose:
        while i not in ['l', 'p']:
            i = input('Введите версию(l - local, p - public): ')
        args.purpose = ['local', 'public'][i == 'l']
    if not args.keyfile:
        print("Для расшифровки требуется указать файл ключа при помощи -kf")
        return

def dialog(args):
    while args.mode not in ['0', '1', '2', '3', '4', '5']:
        print("Выберете действие:") 
        print("1. Подпись")
        print("2. Проверка подписи")
        print('3. Вывести информацию о токене')
        print("4. Оборачивание ключа")
        print("5. Разворачивание ключа")
        print("0. Выход")
        args.mode = input("Выберите действие: ")
    if args.mode == '0':
        return
    args.mode = ['sign', 'check','info', 'wrap', 'unwrap'][int(args.mode)-1]
    if args.mode == 'info':
        info(args)
    elif args.mode == 'sign':
        sign(args)
    elif args.mode == "check":
        check(args)
    elif args.mode == "wrap":
        wrap(args)
    elif args.mode == "unwrap":
        unwrap(args)

def main():
    parser = argparse.ArgumentParser(description="A simple example of argparse.")
    parser.add_argument_group("PASETO data")
    parser.add_argument("-P", "--paseto", help="PASETO token")
    parser.add_argument("-v", "--version", help="Version of PASETO")
    parser.add_argument("-p", "--purpose", help="Purpose of PASETO")
    parser.add_argument("-k", "--key", help="Path to the key file", type=str)
    parser.add_argument("-kf", "--keyfile", help="Path to the key file", type=argparse.FileType('r'))
    parser.add_argument("-d", "--data", help="Path to the JSON file")
    parser.add_argument("-f", "--footer", help="Path to the footer file")
    parser.add_argument("--nokey", help='No print key in info')
    parser.add_argument('mode', nargs='?', default=None, help="Mode of operation", choices=['encrypt', 'sign', 'decrypt', 'check', 'info', 'wrap', 'unwrap'])
    parser.add_argument_group("System options")
    parser.add_argument('-o','--output', type=argparse.FileType('r'), help='Output file path')
    parser.add_argument('-V', action="store_true", help='Version of PASETO Suite')
    
    args = parser.parse_args()
    if args.V:
        print("PASETO Version: 1.0") 
        exit(0)
    if not args.mode:
        dialog(args)
        exit(0)
    print(f"Using mode: {args.mode}")
    if args.paseto:
        paseto_pattern = r'^v[1-4]\.(local|public)\.[A-Za-z0-9\-_]+(\.[A-Za-z0-9\-_]+)?$'
        if not re.match(paseto_pattern, args.paseto):
            print("Error: Invalid PASETO token format")
            exit(1)
    if args.mode == "sign" or args.mode == "encrypt":
        sign(args)
    elif args.mode == "check" or args.mode == "decrypt":
        check(args)
    elif args.mode == "info":
        info(args)
    elif args.mode == "wrap":
        wrap(args)
    elif args.mode == "unwrap":
        unwrap(args)
    else:
        print("Error: Invalid mode")
        parser.print_help()
        exit(1)

if __name__ == "__main__":
    main()
