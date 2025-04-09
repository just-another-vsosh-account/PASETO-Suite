import base64
import os
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, ec, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import BLAKE2b, Hash, SHA512, SHA384
from cryptography.hazmat.primitives.hmac import HMAC
from typing import Any, Union, Optional, Dict
import nacl.public
import nacl.utils
import nacl.secret
import nacl.exceptions
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import nacl.bindings
import struct
import argon2
from cryptography.hazmat.backends import default_backend
from hashlib import blake2b
from base64 import urlsafe_b64encode, urlsafe_b64decode
import hmac
from cryptography.exceptions import InvalidTag

__all__ = [
    'PASERK',
    'base64url_encode',
    'base64url_decode',
    'create_lid',
    'create_pid',
    'create_sid',
    'local_pw_wrap',
    'local_pw_unwrap',
    'secret_pw_wrap',
    'secret_pw_unwrap',
    'local_wrap',
    'local_unwrap',
    'secret_wrap',
    'secret_unwrap',
    'seal',
    'seal_open'
]

def base64url_encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    pad = b'=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)

def local_pw_wrap(version, key, password, options=None):
    """Оборачивает локальный ключ с паролем.
    
    Args:
        version (str): Версия PASERK ('1', '2', '3' или '4')
        key (bytes): Локальный ключ
        password (bytes): Пароль
        options (dict): Опции для Argon2
        
    Returns:
        str: PASERK строка
    """
    if version not in ['1', '2', '3', '4']:
        raise ValueError(f"Неподдерживаемая версия PASERK: {version}")
    
    # Генерируем соль
    salt = os.urandom(32 if version in ['1', '3'] else 16)
    
    # Получаем ключи
    encryption_key, authentication_key = _pbkw_derive_key(
        version=version,
        password=password,
        salt=salt,
        options=options
    )
    
    # Генерируем nonce
    nonce = os.urandom(16 if version in ['1', '3'] else 12)
    
    # Шифруем ключ
    if version in ['1', '3']:
        # Используем AES-256-CTR
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CTR(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(key) + encryptor.finalize()
        
        # Вычисляем HMAC-SHA384
        hmac = HMAC(authentication_key, SHA384(), backend=default_backend())
        hmac.update(ciphertext)
        tag = hmac.finalize()
        
    else:
        # Используем XChaCha20
        cipher = ChaCha20Poly1305(encryption_key)
        ciphertext_and_tag = cipher.encrypt(nonce, key, None)
        ciphertext = ciphertext_and_tag[:-16]  # Последние 16 байт - это тег
        tag = ciphertext_and_tag[-16:]  # Получаем тег из последних 16 байт
    
    # Формируем PASERK строку
    header = f"k{version}.local-pw"
    encoded_salt = urlsafe_b64encode(salt).decode('utf-8').rstrip('=')
    encoded_nonce = urlsafe_b64encode(nonce).decode('utf-8').rstrip('=')
    encoded_ciphertext = urlsafe_b64encode(ciphertext).decode('utf-8').rstrip('=')
    encoded_tag = urlsafe_b64encode(tag).decode('utf-8').rstrip('=')
    
    return f"{header}.{encoded_salt}.{encoded_nonce}.{encoded_ciphertext}.{encoded_tag}"

def secret_pw_wrap(version, key, password, options=None):
    """Оборачивает секретный ключ с паролем.
    
    Args:
        version (str): Версия PASERK ('1', '2', '3' или '4')
        key (bytes): Секретный ключ
        password (bytes): Пароль
        options (dict): Опции для Argon2
        
    Returns:
        str: PASERK строка
    """
    if version not in ['1', '2', '3', '4']:
        raise ValueError(f"Неподдерживаемая версия PASERK: {version}")
    
    # Генерируем соль
    salt = os.urandom(32 if version in ['1', '3'] else 16)
    
    # Получаем ключи
    encryption_key, authentication_key = _pbkw_derive_key(
        version=version,
        password=password,
        salt=salt,
        options=options
    )
    
    # Генерируем nonce
    nonce = os.urandom(16 if version in ['1', '3'] else 12)
    
    # Шифруем ключ
    if version in ['1', '3']:
        # Используем AES-256-CTR
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CTR(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(key) + encryptor.finalize()
        
        # Вычисляем HMAC-SHA384
        hmac = HMAC(authentication_key, SHA384(), backend=default_backend())
        hmac.update(ciphertext)
        tag = hmac.finalize()
        
    else:
        # Используем XChaCha20
        cipher = ChaCha20Poly1305(encryption_key)
        ciphertext_and_tag = cipher.encrypt(nonce, key, None)
        ciphertext = ciphertext_and_tag[:-16]  # Последние 16 байт - это тег
        tag = ciphertext_and_tag[-16:]  # Получаем тег из последних 16 байт
    
    # Формируем PASERK строку
    header = f"s{version}.secret-pw"
    encoded_salt = urlsafe_b64encode(salt).decode('utf-8').rstrip('=')
    encoded_nonce = urlsafe_b64encode(nonce).decode('utf-8').rstrip('=')
    encoded_ciphertext = urlsafe_b64encode(ciphertext).decode('utf-8').rstrip('=')
    encoded_tag = urlsafe_b64encode(tag).decode('utf-8').rstrip('=')
    
    return f"{header}.{encoded_salt}.{encoded_nonce}.{encoded_ciphertext}.{encoded_tag}"

class PASERK:
    @staticmethod
    def from_paserk(paserk_string):
        parts = paserk_string.split('.')
        if len(parts) < 3:
            raise ValueError("Неверный формат PASERK")
        
        version = parts[0][1:]
        paserk_type = parts[1]
        data = '.'.join(parts[2:])
        
        if paserk_type == 'local':
            return PASERK.decode_local(version, data)
        elif paserk_type == 'public':
            return PASERK.decode_public(version, data)
        elif paserk_type == 'secret':
            return PASERK.decode_secret(version, data)
        else:
            raise ValueError(f"Неподдерживаемый тип PASERK: {paserk_type}")

    @staticmethod
    def decode_local(version, data):
        key_bytes = base64url_decode(data)
        return {
            'version': version,
            'type': 'local',
            'key': key_bytes
        }

    @staticmethod
    def decode_public(version, data):
        key_bytes = base64url_decode(data)

        if version == '1':
            try:
                public_key = serialization.load_der_public_key(key_bytes)
                if not isinstance(public_key, rsa.RSAPublicKey):
                    raise ValueError("Ключ не является RSA публичным ключом")
                return {
                    'version': version,
                    'type': 'public',
                    'key': public_key
                }
            except Exception as e:
                raise ValueError(f"Ошибка при декодировании RSA публичного ключа: {e}")
        elif version in ['2', '4']:
            try:
                if len(key_bytes) != 32:
                    raise ValueError("Неверная длина Ed25519 публичного ключа")
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
                return {
                    'version': version,
                    'type': 'public',
                    'key': public_key
                }
            except Exception as e:
                raise ValueError(f"Ошибка при декодировании Ed25519 публичного ключа: {e}")
        elif version == '3':
            try:
                public_key = serialization.load_der_public_key(key_bytes)
                if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP384R1):
                    raise ValueError("Ключ не является P-384 публичным ключом")
                return {
                    'version': version,
                    'type': 'public',
                    'key': public_key
                }
            except Exception as e:
                raise ValueError(f"Ошибка при декодировании P-384 публичного ключа: {e}")
        else:
            raise ValueError(f"Неподдерживаемая версия PASERK: {version}")

    @staticmethod
    def decode_secret(version, data):
        key_bytes = base64url_decode(data)

        if version == '1':
            try:
                private_key = serialization.load_der_private_key(key_bytes, password=None)
                if not isinstance(private_key, rsa.RSAPrivateKey):
                    raise ValueError("Ключ не является RSA приватным ключом")
                return {
                    'version': version,
                    'type': 'secret',
                    'key': private_key
                }
            except Exception as e:
                raise ValueError(f"Ошибка при декодировании RSA приватного ключа: {e}")
        elif version in ['2', '4']:
            try:
                if len(key_bytes) != 64:
                    raise ValueError("Неверная длина Ed25519 приватного ключа")

                secret_key = key_bytes[:32]
                public_key = key_bytes[32:]

                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key)

                return {
                    'version': version,
                    'type': 'secret',
                    'key': private_key,
                    'public_key': ed25519.Ed25519PublicKey.from_public_bytes(public_key)
                }
            except Exception as e:
                raise ValueError(f"Ошибка при декодировании Ed25519 приватного ключа: {e}")
        elif version == '3':
            try:
                private_key = serialization.load_der_private_key(key_bytes, password=None)
                if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP384R1):
                    raise ValueError("Ключ не является P-384 приватным ключом")
                return {
                    'version': version,
                    'type': 'secret',
                    'key': private_key
                }
            except Exception as e:
                raise ValueError(f"Ошибка при декодировании P-384 приватного ключа: {e}")
        else:
            raise NotImplementedError(f"Version {version} not implemented")

    @staticmethod
    def create_local(version, key):
        if not isinstance(key, bytes):
            raise TypeError("Ключ должен быть в формате bytes")
        
        expected_lengths = {
            '1': 32,
            '2': 32,
            '3': 32,
            '4': 32
        }
        
        if version not in expected_lengths:
            raise ValueError(f"Неподдерживаемая версия PASERK: {version}")
        
        if len(key) != expected_lengths[version]:
            raise ValueError(f"Неверная длина ключа для версии {version}: ожидается {expected_lengths[version]} байт")
        
        return f"k{version}.local.{base64url_encode(key)}"

    @staticmethod
    def create_public(version: str, public_key: Any) -> str:
        if version not in ['1', '2', '3', '4']:
            raise ValueError(f"Unsupported version: {version}")
        
        if isinstance(public_key, bytes):
            if len(public_key) != 32:
                raise ValueError("Public key must be 32 bytes")
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            pass
        elif isinstance(public_key, ec.EllipticCurvePublicKey) and version == '3':
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return f"k{version}.public.{base64url_encode(public_key_bytes)}"
        else:
            raise TypeError("Public key must be Ed25519PublicKey, EC public key, or bytes")
        
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return f"k{version}.public.{base64url_encode(public_key_bytes)}"

    @staticmethod
    def create_secret(version: str, private_key: Any) -> str:
        if version not in ['1', '2', '3', '4']:
            raise ValueError(f"Unsupported version: {version}")
        
        if isinstance(private_key, str):
            private_key = private_key.encode('utf-8')
        
        if version == '1':
            if isinstance(private_key, (str, bytes)) and b'BEGIN RSA PRIVATE KEY' in private_key:
                private_key = serialization.load_pem_private_key(private_key, password=None)
                private_key_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                return f"k{version}.secret.{base64url_encode(private_key_bytes)}"
        
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            if version in ['2', '4']:
                private_key_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_key = private_key.public_key()
                public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                key_bytes = private_key_bytes + public_key_bytes
                return f"k{version}.secret.{base64url_encode(key_bytes)}"
        elif isinstance(private_key, bytes):
            if b'BEGIN RSA PRIVATE KEY' in private_key or b'BEGIN PRIVATE KEY' in private_key:
                private_key = serialization.load_pem_private_key(private_key, password=None)
                if version == '1' and isinstance(private_key, rsa.RSAPrivateKey):
                    private_key_bytes = private_key.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    return f"k{version}.secret.{base64url_encode(private_key_bytes)}"
                elif version in ['2', '4'] and isinstance(private_key, ed25519.Ed25519PrivateKey):
                    private_key_bytes = private_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    public_key = private_key.public_key()
                    public_key_bytes = public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                    key_bytes = private_key_bytes + public_key_bytes
                    return f"k{version}.secret.{base64url_encode(key_bytes)}"
                elif version == '3' and isinstance(private_key, ec.EllipticCurvePrivateKey):
                    private_key_bytes = private_key.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    return f"k{version}.secret.{base64url_encode(private_key_bytes)}"
            elif len(private_key) == 32:
                if version in ['2', '4']:
                    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
                    public_key = private_key.public_key()
                    public_key_bytes = public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                    key_bytes = private_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    ) + public_key_bytes
                    return f"k{version}.secret.{base64url_encode(key_bytes)}"
            elif len(private_key) == 64:
                if version in ['2', '4']:
                    private_key_bytes = private_key[:32]
                    public_key_bytes = private_key[32:]
                    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
                    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
                    key_bytes = private_key_bytes + public_key_bytes
                    return f"k{version}.secret.{base64url_encode(key_bytes)}"
        
        raise ValueError("Неподдерживаемый формат приватного ключа")

    @staticmethod
    def from_key(key: bytes, version: str) -> str:
        """Create a PASERK from a key.

        Args:
            key (bytes): The key to create a PASERK from. For RSA keys, this should be a PEM-encoded private key.
                        For Ed25519, this should be either a 32-byte seed or 64-byte full key.
                        For P-384, this should be either a 48-byte seed or a PEM/DER-encoded private key.
            version (str): The version of PASERK to create ('1', '2', '3', or '4').

        Returns:
            str: The PASERK string.

        Raises:
            ValueError: If the version is not supported or the key format is invalid.
        """
        if version not in ['1', '2', '3', '4']:
            raise ValueError(f"Unsupported version: {version}")

        if version in ['1', '2']:  # RSA and Ed25519
            if version == '1':  # RSA
                try:
                    key_obj = serialization.load_pem_private_key(key, password=None)
                    if not isinstance(key_obj, rsa.RSAPrivateKey):
                        raise ValueError("Invalid RSA key format")
                    key_pem = key.decode('utf-8')
                    # Remove header, footer and newlines
                    key_data = key_pem.replace('-----BEGIN RSA PRIVATE KEY-----\n', '')
                    key_data = key_data.replace('\n-----END RSA PRIVATE KEY-----', '')
                    key_data = key_data.replace('\n', '')
                    return f"k1.secret.{key_data}"
                except Exception as e:
                    raise ValueError(f"Invalid RSA key format: {str(e)}")
            else:  # Ed25519
                if len(key) == 32:  # Seed
                    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key)
                    key_bytes = private_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    public_key = private_key.public_key()
                    public_bytes = public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                    full_key = key_bytes + public_bytes
                elif len(key) == 64:  # Full key
                    full_key = key
                    # Verify that the public key part is valid
                    try:
                        ed25519.Ed25519PublicKey.from_public_bytes(key[32:])
                    except Exception:
                        raise ValueError("Invalid Ed25519 key: Invalid public key portion")
                else:
                    raise ValueError(f"Invalid Ed25519 key length: {len(key)} bytes")
                return f"k2.secret.{base64url_encode(full_key)}"
        else:  # P-384
            try:
                if len(key) == 48:  # Seed
                    private_key = ec.derive_private_key(
                        int.from_bytes(key, byteorder='big'),
                        ec.SECP384R1()
                    )
                else:  # PEM or DER
                    try:
                        private_key = serialization.load_pem_private_key(key, password=None)
                    except ValueError:
                        private_key = serialization.load_der_private_key(key, password=None)
                    
                    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP384R1):
                        raise ValueError("Invalid P-384 key")

                # Get the private key in the correct format
                key_bytes = private_key.private_numbers().private_value.to_bytes(48, byteorder='big')
                public_key = private_key.public_key()
                public_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
                full_key = key_bytes + public_bytes

                return f"k{version}.secret.{base64url_encode(full_key)}"
            except Exception as e:
                raise ValueError(f"Invalid P-384 key: {str(e)}")

    @staticmethod
    def from_key_password(key: bytes, password: Union[str, bytes], version: str, options: Optional[Dict] = None) -> str:
        """Создает PASERK из ключа, защищенный паролем."""
        if version not in ['1', '2', '3', '4']:
            raise ValueError(f"Неподдерживаемая версия: {version}")

        if isinstance(password, str):
            password = password.encode('utf-8')

        # Генерируем случайную соль
        salt = os.urandom(16)

        # Для версий 2 и 4 используем Argon2id
        if version in ['2', '4']:
            # Параметры по умолчанию
            memlimit = options.get('memlimit', 65536)  # 64MB
            opslimit = options.get('opslimit', 2)
            parallelism = options.get('parallelism', 1)

            # Генерируем pre-key с помощью Argon2id
            pre_key = argon2.hash_password_raw(
                password=password,
                salt=salt,
                time_cost=opslimit,
                memory_cost=memlimit,
                parallelism=parallelism,
                hash_len=32,
                type=argon2.Type.ID
            )

            # Генерируем ключи для шифрования и аутентификации
            enc_key = BLAKE2b(digest_size=32).update(pre_key + b'\x01').finalize()[:32]
            auth_key = BLAKE2b(digest_size=32).update(pre_key + b'\x02').finalize()[:32]

            # Генерируем случайный nonce
            nonce = os.urandom(12)  # 12 байт для ChaCha20Poly1305

            # Шифруем ключ
            cipher = ChaCha20Poly1305(enc_key)
            encrypted = cipher.encrypt(nonce, key, None)

            # Вычисляем HMAC для аутентификации
            h = HMAC(auth_key, digestmod='sha384')
            h.update(encrypted)
            tag = h.digest()

            # Формируем данные для кодирования
            data = struct.pack('>Q', memlimit) + struct.pack('>Q', opslimit) + struct.pack('>Q', parallelism) + \
                   salt + nonce + encrypted + tag

        # Для версий 1 и 3 используем PBKDF2
        else:
            # Параметры по умолчанию
            iterations = options.get('iterations', 100000)

            # Генерируем pre-key с помощью PBKDF2
            pre_key = PBKDF2HMAC(
                algorithm=SHA384(),
                length=32,
                salt=salt,
                iterations=iterations,
            ).derive(password)

            # Генерируем ключи для шифрования и аутентификации
            enc_key = BLAKE2b(digest_size=32).update(pre_key + b'\x01').finalize()[:32]
            auth_key = BLAKE2b(digest_size=32).update(pre_key + b'\x02').finalize()[:32]

            # Генерируем случайный nonce
            nonce = os.urandom(16)  # 16 байт для AES-CTR

            # Шифруем ключ с помощью AES-CTR
            cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(key) + encryptor.finalize()

            # Вычисляем HMAC для аутентификации
            h = HMAC(auth_key, digestmod='sha384')
            h.update(encrypted)
            tag = h.digest()

            # Формируем данные для кодирования
            data = salt + struct.pack('>I', iterations) + nonce + encrypted + tag

        # Кодируем данные в base64 или base64url в зависимости от версии
        if version in ['1', '3']:
            encoded = base64.b64encode(data).decode()
        else:
            encoded = base64.urlsafe_b64encode(data).decode().rstrip('=')

        return f"k{version}.secret-pw.{encoded}"

    @staticmethod
    def to_key(paserk_string):
        """Извлекает ключ из PASERK."""
        decoded = PASERK.from_paserk(paserk_string)
        if decoded['type'] == 'secret':
            if decoded['version'] == '1':
                return decoded['key'].private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            elif decoded['version'] in ['2', '4']:
                # Для Ed25519 возвращаем полный ключ (приватный + публичный)
                private_key = decoded['key']
                public_key = decoded['public_key']
                private_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                return private_bytes + public_bytes
            elif decoded['version'] == '3':
                return decoded['key'].private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
        raise ValueError("Неподдерживаемый тип PASERK")

    @staticmethod
    def to_key_password(paserk_string, password):
        """Извлекает ключ из PASERK, защищенного паролем."""
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        parts = paserk_string.split('.')
        if len(parts) < 3:
            raise ValueError("Неверный формат PASERK")
        
        version = parts[0][1:]
        if parts[1] != 'secret-pw':
            raise ValueError("PASERK не является защищенным паролем секретным ключом")
        
        data = base64url_decode(parts[2])
        salt = data[:16]
        
        if version in ['2', '4']:
            # Для версий 2 и 4 используем Argon2id
            memlimit = int.from_bytes(data[16:24], byteorder='big')
            opslimit = int.from_bytes(data[24:28], byteorder='big')
            parallelism = int.from_bytes(data[28:32], byteorder='big')
            nonce = data[32:56]  # 24 байта для XChaCha20
            encrypted = data[56:-32]  # -32 для тега
            received_tag = data[-32:]
            
            # Получаем pre-key с помощью Argon2id
            pre_key = argon2.hash_password_raw(
                password=password,
                salt=salt,
                time_cost=opslimit,
                memory_cost=memlimit // 1024,
                parallelism=parallelism,
                hash_len=32,
                type=argon2.Type.ID
            )
            
            # Получаем ключи шифрования и аутентификации
            h = Hash(BLAKE2b(32))
            h.update(b'\xFF')
            h.update(pre_key)
            encryption_key = h.finalize()
            
            h = Hash(BLAKE2b(32))
            h.update(b'\xFE')
            h.update(pre_key)
            auth_key = h.finalize()
            
            # Проверяем тег аутентификации
            header = f"k{version}.secret-pw."
            auth_data = header.encode() + salt + \
                       memlimit.to_bytes(8, byteorder='big') + \
                       opslimit.to_bytes(4, byteorder='big') + \
                       parallelism.to_bytes(4, byteorder='big') + \
                       nonce + encrypted
            
            h = Hash(BLAKE2b(32))
            h.update(auth_data)
            h.update(auth_key)
            calculated_tag = h.finalize()
            
            if not hmac.compare_digest(calculated_tag, received_tag):
                raise ValueError("Неверный пароль или поврежденные данные")
            
            # Расшифровываем
            cipher = ChaCha20Poly1305(encryption_key)
            try:
                return cipher.decrypt(nonce, encrypted, b"")
            except Exception:
                raise ValueError("Ошибка расшифрования")
            
        else:
            # Для версий 1 и 3 используем PBKDF2
            iterations = int.from_bytes(data[16:20], byteorder='big')
            nonce = data[20:36]  # 16 байт для AES-CTR
            encrypted = data[36:-48]  # -48 для HMAC-SHA384
            received_tag = data[-48:]
            
            # Получаем pre-key с помощью PBKDF2-SHA384
            kdf = PBKDF2HMAC(
                algorithm=SHA384(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            pre_key = kdf.derive(password)
            
            # Получаем ключи шифрования и аутентификации
            h = Hash(SHA384())
            h.update(b'\xFF')
            h.update(pre_key)
            encryption_key = h.finalize()[:32]
            
            h = Hash(SHA384())
            h.update(b'\xFE')
            h.update(pre_key)
            auth_key = h.finalize()
            
            # Проверяем HMAC
            header = f"k{version}.secret-pw."
            auth_data = header.encode() + salt + \
                       iterations.to_bytes(4, byteorder='big') + \
                       nonce + encrypted
            
            h = HMAC(auth_key, SHA384())
            h.update(auth_data)
            calculated_tag = h.digest()
            
            if not hmac.compare_digest(calculated_tag, received_tag):
                raise ValueError("Неверный пароль или поврежденные данные")
            
            # Расшифровываем
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.CTR(nonce),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            try:
                return decryptor.update(encrypted) + decryptor.finalize()
            except Exception:
                raise ValueError("Ошибка расшифрования")

    @staticmethod
    def from_key_wrap(key: bytes, wrapping_key: bytes, version: str) -> str:
        """Создает PASERK из ключа, обернутого другим ключом."""
        if version not in ['1', '2', '3', '4']:
            raise ValueError(f"Неподдерживаемая версия: {version}")

        # Генерируем случайный nonce
        nonce = os.urandom(32)

        # Для версий 2 и 4 используем ChaCha20Poly1305
        if version in ['2', '4']:
            # Генерируем ключи для шифрования и аутентификации
            enc_key = BLAKE2b(digest_size=32).update(wrapping_key + b'\x01').finalize()[:32]
            auth_key = BLAKE2b(digest_size=32).update(wrapping_key + b'\x02').finalize()[:32]

            # Шифруем ключ
            cipher = ChaCha20Poly1305(enc_key)
            encrypted = cipher.encrypt(nonce[:12], key, None)  # Используем первые 12 байт nonce

            # Вычисляем HMAC для аутентификации
            h = HMAC(auth_key, digestmod='sha384')
            h.update(encrypted)
            tag = h.digest()

            # Формируем данные для кодирования
            data = nonce + encrypted + tag

        # Для версий 1 и 3 используем AES-256-CTR
        else:
            # Генерируем ключи для шифрования и аутентификации
            enc_key = BLAKE2b(digest_size=32).update(wrapping_key + b'\x01').finalize()[:32]
            auth_key = BLAKE2b(digest_size=32).update(wrapping_key + b'\x02').finalize()[:32]

            # Шифруем ключ с помощью AES-CTR
            cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce[:16]))  # Используем первые 16 байт nonce
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(key) + encryptor.finalize()

            # Вычисляем HMAC для аутентификации
            h = HMAC(auth_key, digestmod='sha384')
            h.update(encrypted)
            tag = h.digest()

            # Формируем данные для кодирования
            data = nonce + encrypted + tag

        # Кодируем данные в base64 или base64url в зависимости от версии
        if version in ['1', '3']:
            encoded = base64.b64encode(data).decode()
        else:
            encoded = base64.urlsafe_b64encode(data).decode().rstrip('=')

        return f"k{version}.secret-wrap.pie.{encoded}"

    @staticmethod
    def to_key_wrap(paserk_string, wrapping_key):
        if isinstance(wrapping_key, str):
            wrapping_key = wrapping_key.encode('utf-8')
        
        decoded = PASERK.from_paserk(paserk_string)
        if decoded['type'] != 'secret-wrap':
            raise ValueError("PASERK не является обернутым секретным ключом")
        
        version = decoded['version']
        data = base64url_decode(decoded['data'])
        
        if version == '4':
            nonce = data[:12]
            ciphertext = data[12:]
            cipher = ChaCha20Poly1305(wrapping_key)
        else:
            nonce = data[:12]
            ciphertext = data[12:]
            kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"PASERK",
            )
            key_hash = kdf.derive(wrapping_key)
            cipher = ChaCha20Poly1305(key_hash)
        
        return cipher.decrypt(nonce, ciphertext, b"")

    @staticmethod
    def create_local(version, key):
        if not isinstance(key, bytes):
            raise TypeError("Ключ должен быть в формате bytes")
        
        expected_lengths = {
            '1': 32,
            '2': 32,
            '3': 32,
            '4': 32
        }
        
        if version not in expected_lengths:
            raise ValueError(f"Неподдерживаемая версия PASERK: {version}")
        
        if len(key) != expected_lengths[version]:
            raise ValueError(f"Неверная длина ключа для версии {version}: ожидается {expected_lengths[version]} байт")
        
        return f"k{version}.local.{base64url_encode(key)}"

def create_lid(version: str, key: str | bytes) -> str:
    """Создает Local Key ID."""
    if isinstance(key, str):
        key = bytes.fromhex(key)
    header = f"k{version}.lid."
    paserk = f"k{version}.local.{base64url_encode(key)}"
    h = blake2b(digest_size=33)
    h.update(header.encode())
    h.update(paserk.encode())
    return f"{header}{urlsafe_b64encode(h.digest()).decode().rstrip('=')}"

def create_pid(version: str, key: str | bytes) -> str:
    """Создает Public Key ID."""
    if isinstance(key, str):
        key = bytes.fromhex(key)
    header = f"k{version}.pid."
    paserk = f"k{version}.public.{base64url_encode(key)}"
    h = blake2b(digest_size=33)
    h.update(header.encode())
    h.update(paserk.encode())
    return f"{header}{urlsafe_b64encode(h.digest()).decode().rstrip('=')}"

def create_sid(version: str, key: str | bytes) -> str:
    """Создает Secret Key ID."""
    if isinstance(key, str):
        key = bytes.fromhex(key)
    header = f"k{version}.sid."
    paserk = f"k{version}.secret.{base64url_encode(key)}"
    h = blake2b(digest_size=33)
    h.update(header.encode())
    h.update(paserk.encode())
    return f"{header}{urlsafe_b64encode(h.digest()).decode().rstrip('=')}"

def _pbkw_derive_key(version, password, salt, iterations=100000, options=None):
    """Выводит ключ из пароля в соответствии со спецификацией PBKD.
    
    Args:
        version (str): Версия PASERK ('1', '2', '3' или '4')
        password (bytes): Пароль
        salt (bytes): Соль
        iterations (int): Количество итераций для PBKDF2
        options (dict): Опции для Argon2
        
    Returns:
        tuple: (encryption_key, authentication_key)
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    if version in ['1', '3']:
        # Для версий 1 и 3 используем PBKDF2-SHA384
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA384(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        pre_key = kdf.derive(password)
        
        # Получаем ключ шифрования из SHA-384(0xFF || k)
        h = Hash(SHA384())
        h.update(b'\xFF')
        h.update(pre_key)
        encryption_key = h.finalize()[:32]
        
        # Получаем ключ аутентификации из SHA-384(0xFE || k)
        h = Hash(SHA384())
        h.update(b'\xFE')
        h.update(pre_key)
        authentication_key = h.finalize()
        
    else:  # версии 2 и 4
        if options is None:
            options = {}
        
        memlimit = options.get('memlimit', 67108864)  # 64MB
        opslimit = options.get('opslimit', 2)
        parallelism = options.get('parallelism', 1)
        
        # Используем Argon2id
        pre_key = argon2.hash_password_raw(
            password=password,
            salt=salt,
            time_cost=opslimit,
            memory_cost=memlimit // 1024,
            parallelism=parallelism,
            hash_len=32,
            type=argon2.Type.ID
        )
        
        # Получаем ключ шифрования из BLAKE2b(0xFF || k)
        h = blake2b(digest_size=32)
        h.update(b'\xFF')
        h.update(pre_key)
        encryption_key = h.digest()
        
        # Получаем ключ аутентификации из BLAKE2b(0xFE || k)
        h = blake2b(digest_size=32)
        h.update(b'\xFE')
        h.update(pre_key)
        authentication_key = h.digest()
    
    return encryption_key, authentication_key

def wrap_key_with_password(version, key, password, options=None):
    if options is None:
        options = {}
    
    salt = os.urandom(16)
    
    if version == '4':
        memlimit = options.get('memlimit', 67108864)
        opslimit = options.get('opslimit', 2)
        iterations = opslimit
        
        header = struct.pack('>QQQQ', memlimit, 0, 0, opslimit)
    else:
        iterations = options.get('iterations', 100000)
        header = struct.pack('>Q', iterations)
    
    derived_key = _pbkw_derive_key(version, password, salt, iterations, options)
    
    nonce = os.urandom(24)
    box = nacl.secret.SecretBox(derived_key)
    encrypted = box.encrypt(key, nonce)
    
    components = [salt, header, encrypted]
    payload = b''.join(components)
    
    encoded = base64.urlsafe_b64encode(payload).rstrip(b'=').decode()
    return f"k{version}.local-pw.{encoded}"

def local_pw_unwrap(version, paserk, password):
    if not paserk.startswith(f"k{version}.local-pw."):
        raise ValueError("Неверный формат PASERK")

    parts = paserk.split('.')
    if len(parts) != 6:
        raise ValueError("Неверный формат PASERK")

    salt = urlsafe_b64decode(parts[2] + '=' * (-len(parts[2]) % 4))
    nonce = urlsafe_b64decode(parts[3] + '=' * (-len(parts[3]) % 4))
    ciphertext = urlsafe_b64decode(parts[4] + '=' * (-len(parts[4]) % 4))
    tag = urlsafe_b64decode(parts[5] + '=' * (-len(parts[5]) % 4))

    encryption_key, authentication_key = _pbkw_derive_key(
        version=version,
        password=password,
        salt=salt
    )

    if version in ['1', '3']:
        hmac_obj = HMAC(authentication_key, hashes.SHA384(), backend=default_backend())
        hmac_obj.update(ciphertext)
        expected_tag = hmac_obj.finalize()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Неверный пароль или поврежденные данные")

        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CTR(nonce),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        key = decryptor.update(ciphertext) + decryptor.finalize()

    else:
        cipher = ChaCha20Poly1305(encryption_key)
        try:
            key = cipher.decrypt(nonce, ciphertext + tag, b"")
        except InvalidTag:
            raise ValueError("Неверный пароль или поврежденные данные")

    return key

def secret_pw_unwrap(version, paserk, password):
    if not paserk.startswith(f"s{version}.secret-pw."):
        raise ValueError("Неверный формат PASERK")

    parts = paserk.split('.')
    if len(parts) != 6:
        raise ValueError("Неверный формат PASERK")

    salt = urlsafe_b64decode(parts[2] + '=' * (-len(parts[2]) % 4))
    nonce = urlsafe_b64decode(parts[3] + '=' * (-len(parts[3]) % 4))
    ciphertext = urlsafe_b64decode(parts[4] + '=' * (-len(parts[4]) % 4))
    tag = urlsafe_b64decode(parts[5] + '=' * (-len(parts[5]) % 4))

    encryption_key, authentication_key = _pbkw_derive_key(
        version=version,
        password=password,
        salt=salt
    )

    if version in ['1', '3']:
        hmac_obj = HMAC(authentication_key, hashes.SHA384(), backend=default_backend())
        hmac_obj.update(ciphertext)
        expected_tag = hmac_obj.finalize()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Неверный пароль или поврежденные данные")

        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CTR(nonce),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        key = decryptor.update(ciphertext) + decryptor.finalize()

    else:
        cipher = ChaCha20Poly1305(encryption_key)
        try:
            key = cipher.decrypt(nonce, ciphertext + tag, b"")
        except InvalidTag:
            raise ValueError("Неверный пароль или поврежденные данные")

    return key

def convert_ed25519_to_curve25519_public_key(ed25519_public_key: bytes) -> bytes:
    if len(ed25519_public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    
    ed25519_key = ed25519.Ed25519PublicKey.from_public_bytes(ed25519_public_key)
    
    raw_bytes = ed25519_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    curve25519_bytes = bytearray(raw_bytes)
    curve25519_bytes[31] &= 0x7F
    
    try:
        x25519_key = x25519.X25519PublicKey.from_public_bytes(bytes(curve25519_bytes))
        return x25519_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    except Exception:
        raise ValueError("Invalid Ed25519 public key")

def convert_ed25519_to_curve25519_private_key(ed25519_private_key: bytes) -> bytes:
    if len(ed25519_private_key) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")
    
    h = Hash(BLAKE2b(64))
    h.update(ed25519_private_key)
    hashed = h.finalize()
    
    curve25519_bytes = bytearray(hashed[:32])
    curve25519_bytes[0] &= 248
    curve25519_bytes[31] &= 127
    curve25519_bytes[31] |= 64
    
    try:
        x25519_key = x25519.X25519PrivateKey.from_private_bytes(bytes(curve25519_bytes))
        return x25519_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    except Exception:
        raise ValueError("Invalid Ed25519 private key")

def convert_public_key_to_x25519(ed25519_public_key: bytes) -> x25519.X25519PublicKey:
    if len(ed25519_public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    
    try:
        x25519_bytes = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(ed25519_public_key)
        return x25519.X25519PublicKey.from_public_bytes(x25519_bytes)
    except Exception:
        raise ValueError("Invalid Ed25519 public key")

def convert_private_key_to_x25519(ed25519_private_key: bytes) -> x25519.X25519PrivateKey:
    if len(ed25519_private_key) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")

    ed25519_key = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_private_key)
    
    private_bytes = ed25519_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    h = Hash(SHA512())
    h.update(private_bytes)
    hashed_key = h.finalize()
    
    x25519_bytes = bytearray(hashed_key[:32])
    x25519_bytes[0] &= 0xF8
    x25519_bytes[31] &= 0x7F
    x25519_bytes[31] |= 0x40
    
    return x25519.X25519PrivateKey.from_private_bytes(bytes(x25519_bytes))

def seal(version: str, key: bytes, public_key: Any) -> str:
    if version != '4':
        raise ValueError("Only version 4 is supported")
        
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
        
    if not isinstance(public_key, (ed25519.Ed25519PublicKey, bytes)):
        raise TypeError("Public key must be Ed25519PublicKey or bytes")
    
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        public_key_bytes = public_key
        
    if len(public_key_bytes) != 32:
        raise ValueError("Public key must be 32 bytes")
    
    x25519_public = convert_public_key_to_x25519(public_key_bytes)
    
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()
    
    shared_secret = ephemeral_private.exchange(x25519_public)
    
    h = Hash(BLAKE2b(64))
    h.update(shared_secret)
    encryption_key = h.finalize()[:32]
    
    nonce = os.urandom(12)
    
    cipher = ChaCha20Poly1305(encryption_key)
    ciphertext = cipher.encrypt(nonce, key, None)
    
    result = b""
    result += ephemeral_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    result += nonce
    result += ciphertext
    
    return f"k{version}.seal.{base64url_encode(result)}"

def seal_open(version: str, sealed: str, private_key: Any) -> bytes:
    if version != '4':
        raise ValueError("Only version 4 is supported")
    
    if not sealed.startswith(f"k{version}.seal."):
        raise ValueError("Invalid sealed format")
    
    sealed_data = base64url_decode(sealed[len(f"k{version}.seal."):])
    if len(sealed_data) < 44:
        raise ValueError("Invalid sealed data length")
    
    ephemeral_public_bytes = sealed_data[:32]
    nonce = sealed_data[32:44]
    ciphertext = sealed_data[44:]
    
    if len(ciphertext) < 16:
        raise ValueError("Invalid ciphertext length")
    
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        private_key_bytes = private_key
    
    if len(private_key_bytes) != 32:
        raise ValueError("Private key must be 32 bytes")
    
    x25519_private = convert_private_key_to_x25519(private_key_bytes)
    
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
    
    shared_secret = x25519_private.exchange(ephemeral_public)
    
    h = Hash(BLAKE2b(64))
    h.update(shared_secret)
    encryption_key = h.finalize()[:32]
    
    cipher = ChaCha20Poly1305(encryption_key)
    try:
        decrypted = cipher.decrypt(nonce, ciphertext, b"")
        return decrypted
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def local_wrap(version, key, wrapping_key, wrapping_id='pie'):
    if version not in ['1', '2', '3', '4']:
        raise ValueError(f"Неподдерживаемая версия PASERK: {version}")
    
    if not isinstance(key, bytes) or not isinstance(wrapping_key, bytes):
        raise TypeError("Ключи должны быть в формате bytes")
    
    if len(wrapping_key) != 32:
        raise ValueError("Ключ оборачивания должен быть 32 байта")
    
    salt = os.urandom(16)
    
    h = Hash(BLAKE2b(64))
    h.update(wrapping_key)
    h.update(salt)
    h.update(wrapping_id.encode('utf-8'))
    derived_key = h.finalize()[:32]
    
    nonce = os.urandom(24)
    box = nacl.secret.SecretBox(derived_key)
    encrypted = box.encrypt(key, nonce)
    
    components = [salt, encrypted]
    payload = b''.join(components)
    
    encoded = base64.urlsafe_b64encode(payload).rstrip(b'=').decode()
    return f"k{version}.local-wrap.{encoded}"

def local_unwrap(version, paserk, wrapping_key):
    if not paserk.startswith(f"k{version}.local-wrap."):
        raise ValueError(f"Неверный формат PASERK для версии {version}")
    
    encoded = paserk.split('.')[-1]
    payload = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    
    salt = payload[:16]
    encrypted = payload[16:]
    
    h = Hash(BLAKE2b(64))
    h.update(wrapping_key)
    h.update(salt)
    h.update(b"pie")
    derived_key = h.finalize()[:32]
    
    box = nacl.secret.SecretBox(derived_key)
    try:
        return box.decrypt(encrypted)
    except nacl.exceptions.CryptoError:
        raise ValueError("Неверный ключ оборачивания или поврежденные данные")

def secret_wrap(version, key, wrapping_key, wrapping_id='pie'):
    if version not in ['1', '2', '3', '4']:
        raise ValueError(f"Неподдерживаемая версия PASERK: {version}")
    
    if not isinstance(key, bytes) or not isinstance(wrapping_key, bytes):
        raise TypeError("Ключи должны быть в формате bytes")
    
    if len(wrapping_key) != 32:
        raise ValueError("Ключ оборачивания должен быть 32 байта")
    
    salt = os.urandom(16)
    
    h = Hash(BLAKE2b(64))
    h.update(wrapping_key)
    h.update(salt)
    h.update(wrapping_id.encode('utf-8'))
    derived_key = h.finalize()[:32]
    
    nonce = os.urandom(24)
    box = nacl.secret.SecretBox(derived_key)
    encrypted = box.encrypt(key, nonce)
    
    components = [salt, encrypted]
    payload = b''.join(components)
    
    encoded = base64.urlsafe_b64encode(payload).rstrip(b'=').decode()
    return f"k{version}.secret-wrap.{encoded}"

def secret_unwrap(version, paserk, wrapping_key):
    if not paserk.startswith(f"k{version}.secret-wrap."):
        raise ValueError(f"Неверный формат PASERK для версии {version}")
    
    encoded = paserk.split('.')[-1]
    payload = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    
    salt = payload[:16]
    encrypted = payload[16:]
    
    h = Hash(BLAKE2b(64))
    h.update(wrapping_key)
    h.update(salt)
    h.update(b"pie")
    derived_key = h.finalize()[:32]
    
    box = nacl.secret.SecretBox(derived_key)
    try:
        return box.decrypt(encrypted)
    except nacl.exceptions.CryptoError:
        raise ValueError("Неверный ключ оборачивания или поврежденные данные")

def unwrap_key_with_password(version, paserk, password):
    if not paserk.startswith(f"k{version}.local-pw."):
        raise ValueError(f"Неверный формат PASERK для версии {version}")
    
    encoded = paserk.split('.')[-1]
    payload = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    
    salt = payload[:16]
    if version == '4':
        header = payload[16:48]
        encrypted = payload[48:]
        memlimit, _, _, opslimit = struct.unpack('>QQQQ', header)
        iterations = opslimit
        options = {'memlimit': memlimit, 'opslimit': opslimit}
    else:
        header = payload[16:24]
        encrypted = payload[24:]
        iterations, = struct.unpack('>Q', header)
        options = {'iterations': iterations}
    
    derived_key = _pbkw_derive_key(version, password, salt, iterations, options)
    
    box = nacl.secret.SecretBox(derived_key)
    try:
        return box.decrypt(encrypted)
    except nacl.exceptions.CryptoError:
        raise ValueError("Неверный пароль или поврежденные данные")

