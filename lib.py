# -*- coding: utf-8 -*-

#import pyseto
import paseto
from typing import Union
import json
import os
import re
from cryptography.hazmat.primitives import serialization
import base64
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa

def normalize_key(key: bytes, size: int = 32) -> bytes:
    """Нормализует ключ до нужного размера"""
    if len(key) < size:
        return key.ljust(size, b'\0')
    return key[:size]

class PasetoToken():
    def __init__(self, key: Union[bytes, str, paseto.KeyInterface], version: str, purpose: str = "local", payload: dict = None, footer: dict = None, token: str = None, nonce: str = None):
        """
        Инициализация PASETO-токена.
        :param key: Ключ для подписи/шифрования.
        :param version: Версия протокола (v1, v2, v3, v4).
        :param purpose: Назначение (local или public).
        :param payload: Полезная нагрузка.
        :param footer: Дополнительные данные (опционально).
        :param token: Существующий PASETO токен.
        :param nonce: Предопределенный nonce для шифрования (для тестирования).
        """
        version_str = str(version)
        if version_str.startswith('v'):
            version_str = version_str[1:]
        self.version_num = int(version_str)
        if self.version_num not in [1, 2, 3, 4]:
            raise ValueError("Неподдерживаемая версия PASETO")
        self.version = f"v{self.version_num}"
        self.purpose = purpose.lower()
        if self.purpose not in ["local", "public"]:
            raise ValueError("Purpose должен быть 'local' или 'public'")
        if (isinstance(key, str) or isinstance(key, bytes)) and len(key) == 0:
            if purpose == 'local':    
                key = token.random(32) 
            elif purpose == 'public':
                if self.version in ['v3', 'v4']:
                    private_key = ed25519.Ed25519PrivateKey.generate()
                    key = private_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                else:
                    private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=2048
                    )
                    key = private_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )
        self.paseto = token
        self.nonce = nonce
        
        try:
            if isinstance(key, (str, bytes)):
                if purpose == "local":
                    if isinstance(key, str):
                        key = key.encode()
                    key = normalize_key(key)
                    self.key = key
                elif purpose == "public":
                    if isinstance(key, str):
                        if os.path.isfile(key):
                            with open(key, 'rb') as key_file:
                                key_data = key_file.read()
                        else:
                            key_data = key.encode()
                    else:
                        key_data = key
                    
                    self.key = key_data
            else:
                self.key = key
        except Exception as e:
            raise ValueError(f"Неправильный ключ: {str(e)}")
            
        self.payload = {} if payload is None else payload
        self.footer = {} if footer is None else footer

    @classmethod
    def from_paseto(cls, key: Union[bytes, str, paseto.KeyInterface], token: str):
        """
        Упрощенная инициализация PASETO-токена.
        :param key: Ключ для подписи/шифрования.
        :param token: PASETO токен.
        """
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        paseto_pattern = r'^v[1-4]\.(local|public)\.[A-Za-z0-9\-_]+(\.[A-Za-z0-9\-_]+)?$'
        if not re.match(paseto_pattern, token):
            raise ValueError("Invalid PASETO token format")
        parts = token.split('.')

        version = parts[0]
        purpose = parts[1]
        
        version_num = int(version[1:]) if version.startswith('v') else int(version)
        
        try:
            if isinstance(key, (str, bytes)):
                if purpose == "local":
                    if isinstance(key, str):
                        key = key.encode()
                    key = normalize_key(key)
                elif purpose == "public":
                    if isinstance(key, str):
                        if os.path.isfile(key):
                            with open(key, 'rb') as key_file:
                                key = key_file.read()
                        else:
                            key = key.encode()
        except Exception as e:
            raise ValueError(f"Неправильный ключ: {str(e)}")

        decoded = paseto.decode(key, token)
        footer = parts[3] if len(parts) > 3 else None
        
        instance = cls(
            key=key,
            version=version,
            purpose=purpose,
            payload=decoded,
            footer=footer,
            token=token
        )
        
        return instance

    def encrypt(self, payload: dict = None, footer: dict = None) -> bytes:
        """
        Шифрует данные и возвращает PASETO-токен.
        Используется только для local purpose (симметричное шифрование).
        :param payload: Данные для шифрования (если не указаны, используются из __init__).
        :param footer: Дополнительные данные (если не указаны, используются из __init__).
        :return: PASETO-токен.
        """
        if self.purpose != "local":
            return self.sign(payload or self.payload, footer or self.footer)
            
        payload = payload or self.payload
        footer = footer or self.footer
        
        try:
            token = paseto.encode(
                self.key, 
                payload, 
                version=self.version, 
                purpose=self.purpose, 
                footer=footer, 
                nonce=self.nonce  # Используем nonce, если он был указан
            )
            return token.encode('utf-8')  # Преобразуем строку в байты
        except ValueError as e:
            raise ValueError(f"Ошибка шифрования: {str(e)}")

    def decrypt(self) -> dict:
        """
        Расшифровывает PASETO-токен.
        Используется только для local purpose (симметричное шифрование).
        :return: Расшифрованные данные.
        """
        if self.purpose != "local":
            return self.verify() 
        if not self.paseto:
            raise ValueError("Невозможно декодировать созданный вручную PASETO")
        try:
            decoded = paseto.decode(self.key, self.paseto)
            return decoded['payload']
        except Exception as e:
            raise ValueError(f"Ошибка расшифровки: {str(e)}")

    def sign(self, payload: dict = None, footer: dict = None) -> bytes:
        """
        Подписывает данные и возвращает PASETO-токен.
        Используется только для public purpose (асимметричная подпись).
        :param payload: Данные для подписи (если не указаны, используются из __init__).
        :param footer: Дополнительные данные (если не указаны, используются из __init__).
        :return: PASETO-токен.
        """
        if self.purpose != "public":
            return self.encrypt(payload or self.payload, footer or self.footer)
            
        payload = payload or self.payload
        footer = footer or self.footer
        
        try:
            return paseto.encode(self.key, payload, version=self.version, purpose=self.purpose, footer=footer)
        except ValueError as e:
            raise ValueError(f"Ошибка подписи: {str(e)}")

    def verify(self) -> dict:
        """
        Проверяет подпись PASETO-токена.
        Используется только для public purpose (асимметричная подпись).
        :return: Проверенные данные.
        """
        if self.purpose != "public":
            return self.decrypt()
        if not self.paseto:
            raise ValueError("Невозможно подписать созданный вручную PASETO")
        try:
            decoded = paseto.decode(self.key, self.paseto)
            return decoded['payload']
        except Exception as e:
            # Попытаемся использовать специальную функцию для проверки подписи напрямую
            version_num = int(self.version[1:]) if self.version.startswith('v') else int(self.version)
            parts = self.paseto.split('.')
            payload = parts[2]
            footer = parts[3] if len(parts) > 3 else None
            
            verify_func = None
            if version_num == 1:
                verify_func = paseto.verify_v1_public
            elif version_num == 2:
                verify_func = paseto.verify_v2_public
            elif version_num == 3:
                verify_func = paseto.verify_v3_public
            elif version_num == 4:
                verify_func = paseto.verify_v4_public
                
            if verify_func:
                try:
                    return verify_func(self.key, self.paseto, footer)
                except Exception as e2:
                    raise ValueError(f"Ошибка проверки подписи: {str(e2)}")
            else:
                raise ValueError(f"Ошибка проверки подписи: {str(e)}")

    def info(self, token: str) -> dict:
        """
        Возвращает информацию о PASETO-токене.
        :param token: PASETO-токен.
        :return: Информация о PASETO-токене.
        """
        return paseto.decode(token, allow_failed_verification=True)

class PASERKHandler:
    @staticmethod
    def wrap(version: Union[str, int], purpose: str, key: bytes) -> str:
        version = f"v{version}" if not str(version).startswith('v') else version
        return paseto.KeyInterface(version, purpose, key).wrap()
    
    @staticmethod
    def unwrap(version: Union[str, int], purpose: str, wrapped_key: str) -> bytes:
        version = f"v{version}" if not str(version).startswith('v') else version
        return paseto.KeyInterface(version, purpose).unwrap(wrapped_key)
