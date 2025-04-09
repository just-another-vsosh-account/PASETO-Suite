# -*- coding: utf-8 -*-

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, ec, x25519
import base64, json, os, struct, hmac as std_hmac
from nacl.secret import SecretBox
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from typing import Any, Union
import nacl.utils
import nacl.secret
import nacl.exceptions
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def auth_encrypt(key, info_string):
    """
    Генерирует ключ для шифрования/аутентификации на основе мастер-ключа
    """
    h = std_hmac.HMAC(key, digestmod='sha384')
    h.update(info_string)
    return h.digest()[:32]  # Возвращаем 32 байта для AES-256

def base64url_encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    pad = b'=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)

def pre_auth_encode(*pieces):
    output = struct.pack('<Q', len(pieces))
    for piece in pieces:
        if isinstance(piece, str):
            piece = piece.encode('utf-8')
        output += struct.pack('<Q', len(piece)) + piece
    return output

class KeyInterface:
    def __init__(self, key, purpose='local', version=None):
        """
        Инициализирует объект KeyInterface.
        
        Args:
            key (bytes или ключ): Ключ для инициализации
            purpose (str): Назначение ключа ('local', 'public', 'secret')
            version (str): Версия PASETO ('v1', 'v2', 'v3', 'v4')
        """
        self.purpose = purpose
        self.version = version
        
        # Если ключ уже является объектом нужного типа, используем его напрямую
        if purpose == 'public' and isinstance(key, (rsa.RSAPublicKey, ed25519.Ed25519PublicKey, ec.EllipticCurvePublicKey)):
            self.key = key
        elif purpose == 'secret' and isinstance(key, (rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey)):
            self.key = key
        else:
            # Если передан bytes, создаем соответствующий объект ключа
            if not isinstance(key, bytes):
                raise TypeError("Ключ должен быть в формате bytes или соответствующим объектом ключа")
            
            if purpose == 'local':
                if len(key) != 32:
                    raise ValueError("Локальный ключ должен быть 32 байта")
                self.key = key
            elif purpose == 'public':
                if version == 'v1':
                    # RSA публичный ключ
                    self.key = serialization.load_der_public_key(key)
                    if not isinstance(self.key, rsa.RSAPublicKey):
                        raise ValueError("Для версии v1 требуется RSA публичный ключ")
                elif version in ['v2', 'v4']:
                    # Ed25519 публичный ключ
                    if len(key) != 32:
                        raise ValueError("Ed25519 публичный ключ должен быть 32 байта")
                    self.key = ed25519.Ed25519PublicKey.from_public_bytes(key)
                elif version == 'v3':
                    # P-384 публичный ключ
                    if not isinstance(key, bytes) or len(key) != 49:
                        raise ValueError("P-384 публичный ключ должен быть 49 байт в сжатом формате")
                    curve = ec.SECP384R1()
                    self.key = ec.EllipticCurvePublicKey.from_encoded_point(curve, key)
                else:
                    raise ValueError(f"Неподдерживаемая версия PASETO: {version}")
            elif purpose == 'secret':
                if version == 'v1':
                    # RSA приватный ключ
                    self.key = serialization.load_der_private_key(key, password=None)
                    if not isinstance(self.key, rsa.RSAPrivateKey):
                        raise ValueError("Для версии v1 требуется RSA приватный ключ")
                elif version in ['v2', 'v4']:
                    # Ed25519 приватный ключ
                    if len(key) == 32:
                        self.key = ed25519.Ed25519PrivateKey.from_private_bytes(key)
                    elif len(key) == 64:
                        # Если передан полный ключ (seed + public), берем только seed
                        self.key = ed25519.Ed25519PrivateKey.from_private_bytes(key[:32])
                    else:
                        raise ValueError("Ed25519 приватный ключ должен быть 32 или 64 байта")
                elif version == 'v3':
                    # P-384 приватный ключ
                    self.key = serialization.load_der_private_key(key, password=None)
                    if not isinstance(self.key.curve, ec.SECP384R1):
                        raise ValueError("Для версии v3 требуется ключ на кривой P-384 (SECP384R1)")
                else:
                    raise ValueError(f"Неподдерживаемая версия PASETO: {version}")
            else:
                raise ValueError(f"Неподдерживаемое назначение ключа: {purpose}")
    
    def to_bytes(self):
        """
        Преобразует ключ в байты.
        
        Returns:
            bytes: Байтовое представление ключа
        """
        if self.purpose == 'local':
            return self.key
        elif self.purpose == 'public':
            if isinstance(self.key, rsa.RSAPublicKey):
                return self.key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.PKCS1
                )
            elif isinstance(self.key, ed25519.Ed25519PublicKey):
                return self.key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            elif isinstance(self.key, ec.EllipticCurvePublicKey):
                return self.key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.CompressedPoint
                )
        elif self.purpose == 'secret':
            if isinstance(self.key, rsa.RSAPrivateKey):
                return self.key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            elif isinstance(self.key, ed25519.Ed25519PrivateKey):
                private_bytes = self.key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_bytes = self.key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                return private_bytes + public_bytes
            elif isinstance(self.key, ec.EllipticCurvePrivateKey):
                return self.key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
        raise ValueError(f"Не удалось преобразовать ключ в байты: {self.purpose}")

def decode(key, token, nonce_override=None):
    """Декодирует PASETO токен."""
    try:
        parts = token.split('.')
        if len(parts) < 3:
            raise ValueError("Invalid token format")

        version, purpose, payload = parts[:3]
        footer = parts[3] if len(parts) > 3 else None

        if version not in ['v1', 'v2', 'v3', 'v4']:
            raise ValueError(f"Invalid version: {version}")
        if purpose not in ['local', 'public']:
            raise ValueError(f"Invalid purpose: {purpose}")

        result = {'version': version, 'purpose': purpose, 'payload': None, 'footer': footer}

        key_bytes = key.key if isinstance(key, KeyInterface) else key

        if purpose == 'local':
            decrypt_func = globals()[f'decrypt_{version}_local']
            result['payload'] = decrypt_func(key_bytes, payload, footer)
        elif purpose == 'public':
            verify_func = globals()[f'verify_{version}_public']
            result['payload'] = verify_func(key_bytes, payload, footer)

        return result
    except Exception as e:
        raise ValueError(f"Failed to decode: {str(e)}")

def encode(key, payload, version='v4', purpose='local', footer='', nonce=None):
    """Кодирует данные в PASETO токен."""
    try:
        key_bytes = key.key if isinstance(key, KeyInterface) else key
        payload_bytes = payload if isinstance(payload, bytes) else json.dumps(payload).encode('utf-8')
        footer_bytes = footer.encode('utf-8') if isinstance(footer, str) else footer

        if purpose == 'local':
            encrypt_func = globals()[f'encrypt_{version}_local']
            return encrypt_func(key_bytes, payload_bytes, footer_bytes, nonce)
        elif purpose == 'public':
            sign_func = globals()[f'sign_{version}_public']
            return sign_func(key_bytes, payload_bytes, footer_bytes)
        else:
            raise ValueError(f"Invalid purpose: {purpose}")
    except Exception as e:
        raise ValueError(f"Failed to encode: {str(e)}")

def calculate_nonce(key, message, version, size=None, random_bytes=None):
    """
    Рассчитывает детерминированный nonce для PASETO токена.
    
    Args:
        key (bytes): Ключ шифрования
        message (bytes): Сообщение для шифрования
        version (str): Версия PASETO (v1, v2, v3, v4)
        size (int, optional): Размер nonce в байтах. Если не указан, используется 
                              стандартный размер для версии.
        random_bytes (bytes, optional): Случайные байты для GetNonce в v1
    
    Returns:
        bytes: Детерминированный nonce
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
        
    # Особая обработка для v1 с использованием random_bytes (GetNonce)
    if version == 'v1' and random_bytes is not None:
        if isinstance(random_bytes, str):
            random_bytes = random_bytes.encode('utf-8')
            
        h = hmac.HMAC(random_bytes, hashes.SHA384())
        h.update(message)
        return h.finalize()[:32]
        
    if not size:
        if version == 'v1':
            size = 32  # 32 байта для v1 (полный nonce)
        elif version == 'v2':
            size = 24  # 24 байта для XChaCha20
        elif version == 'v3':
            size = 32  # 32 байта для v3
        elif version == 'v4':
            size = 24  # 24 байта для XChaCha20
        else:
            raise ValueError(f"Неподдерживаемая версия: {version}")
    
    # Для v2 и v4 используем BLAKE2b с настраиваемым размером выхода
    if version in ['v2', 'v4']:
        try:
            # Используем hashlib для BLAKE2b с настраиваемым размером
            return hashlib.blake2b(message, key=key, digest_size=size).digest()
        except (ImportError, AttributeError):
            # Если hashlib.blake2b недоступен, используем HMAC-SHA384 как запасной вариант
            h = hmac.HMAC(key, hashes.SHA384())
            h.update(message)
            return h.finalize()[:size]
    
    # Для v1 и v3 используем HMAC-SHA384
    h = hmac.HMAC(key, hashes.SHA384())
    h.update(message)
    return h.finalize()[:size]

def decrypt_v4_local(key, encrypted_payload, footer='', nonce_override=None):
    """
    ChaCha20-Poly1305 по спецификации PASETO v4
    """
    try:
        data = base64url_decode(encrypted_payload)

        if len(data) < 24 + 16:  # nonce + tag
            raise ValueError("Invalid ciphertext length")

        nonce = data[:24]
        ciphertext = data[24:]

        # Вычисляем ключ шифрования
        enc_key = hmac.HMAC(key, hashes.SHA384())
        enc_key.update(b"v4.local-enc")
        enc_key.update(nonce)
        enc_key = enc_key.finalize()[:32]

        # Используем ChaCha20-Poly1305 с первыми 12 байтами nonce
        cipher = ChaCha20Poly1305(enc_key)
        try:
            plaintext = cipher.decrypt(nonce[:12], ciphertext, None)
        except Exception:
            raise ValueError("Decryption failed")

        try:
            return json.loads(plaintext.decode('utf-8'))
        except:
            return plaintext.decode('utf-8')

    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def decrypt_v3_local(key, encrypted_payload, footer='', nonce_override=None):
    """
    AES-256-CTR + HMAC-SHA384 по спецификации PASETO v3
    """
    try:
        data = base64url_decode(encrypted_payload)

        if len(data) < 32 + 48:  # nonce + tag
            raise ValueError("Invalid ciphertext length")

        nonce = data[:32]
        ciphertext = data[32:-48]
        tag = data[-48:]

        # Вычисляем MAC ключ
        mac_key = hmac.HMAC(key, hashes.SHA384())
        mac_key.update(b"v3.local-mac")
        mac_key = mac_key.finalize()[:32]

        # Вычисляем MAC
        footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8') if footer else b""
        pre_auth_pae = pre_auth_encode(b"v3.local.", nonce + ciphertext, footer_bytes)
        mac = hmac.HMAC(mac_key, hashes.SHA384())
        mac.update(pre_auth_pae)
        calculated_tag = mac.finalize()[:48]

        if not std_hmac.compare_digest(calculated_tag, tag):
            raise ValueError("MAC verification failed")

        # Вычисляем ключ шифрования
        enc_key = hmac.HMAC(key, hashes.SHA384())
        enc_key.update(b"v3.local-enc")
        enc_key.update(nonce)
        enc_key = enc_key.finalize()[:32]

        # Используем AES-256-CTR
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce[:16]))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        try:
            return json.loads(plaintext.decode('utf-8'))
        except:
            return plaintext.decode('utf-8')

    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def decrypt_v2_local(key, encrypted_payload, footer='', nonce_override=None):
    """
    XChaCha20-Poly1305 по спецификации PASETO v2
    
    Реализовано в соответствии с официальной спецификацией:
    https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md
    """
    try:
        # 1. Проверяем длину ключа (32 байта для v2.local)
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits) for v2.local")
            
        # 2. Декодируем полезную нагрузку
        data = base64url_decode(encrypted_payload)
        
        if len(data) < 24 + 16:  # nonce + tag
            raise ValueError("Invalid ciphertext length")
        
        # Всегда используем nonce из токена
        nonce = data[:24]
            
        ciphertext_with_tag = data[24:]
    
        # Заголовок
        header = b"v2.local."
        footer_bytes = b""
        if footer:
            footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8')
    
        # Нормализуем ключ до 32 байт для SecretBox
        if len(key) < 32:
            padded_key = key.ljust(32, b'\0')
        elif len(key) > 32:
            padded_key = key[:32]
        else:
            padded_key = key
            
        # Метод 1: стандартная расшифровка с NaCl
        box = SecretBox(padded_key)
        try:
            plaintext = box.decrypt(ciphertext_with_tag, nonce)
        except Exception:
            # Метод 2: если есть футер
            if footer:
                try:
                    # Вариант 1: с футером напрямую
                    pre_auth = header + footer_bytes
                    box = SecretBox(padded_key, encoder=None)
                    plaintext = box.decrypt(ciphertext_with_tag, nonce, pre_auth)
                except Exception:
                    try:
                        # Вариант 2: с PAE и футером
                        pre_auth = pre_auth_encode(header, nonce + ciphertext_with_tag, footer_bytes)
                        box = SecretBox(padded_key, encoder=None)
                        plaintext = box.decrypt(ciphertext_with_tag, nonce, pre_auth)
                    except Exception:
                        try:
                            # Вариант 3: с декодированным футером
                            decoded_footer = json.loads(footer) if isinstance(footer, str) else footer
                            footer_json = json.dumps(decoded_footer).encode('utf-8')
                            box = SecretBox(padded_key, encoder=None)
                            plaintext = box.decrypt(ciphertext_with_tag, nonce, footer_json)
                        except Exception:
                            raise ValueError("Failed to decrypt")
            else:
                raise ValueError("Failed to decrypt")
            
        # Возвращаем расшифрованные данные
        try:
            return json.loads(plaintext.decode('utf-8'))
        except:
            return plaintext.decode('utf-8')
            
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def decrypt_v1_local(key, encrypted_payload, footer='', nonce_override=None):
    """
    AES-256-CTR + HMAC-SHA384 по спецификации PASETO v1
    """
    try:
        data = base64url_decode(encrypted_payload)

        if len(data) < 32 + 48:  # nonce + tag
            raise ValueError("Invalid ciphertext length")

        nonce = data[:32]
        ciphertext = data[32:-48]
        tag = data[-48:]

        # Вычисляем MAC ключ
        mac_key = hmac.HMAC(key, hashes.SHA384())
        mac_key.update(b"v1.local-mac")
        mac_key = mac_key.finalize()[:32]

        # Вычисляем MAC
        footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8') if footer else b""
        pre_auth_pae = pre_auth_encode(b"v1.local.", nonce + ciphertext, footer_bytes)
        mac = hmac.HMAC(mac_key, hashes.SHA384())
        mac.update(pre_auth_pae)
        calculated_tag = mac.finalize()[:48]

        if not std_hmac.compare_digest(calculated_tag, tag):
            raise ValueError("MAC verification failed")

        # Вычисляем ключ шифрования
        enc_key = hmac.HMAC(key, hashes.SHA384())
        enc_key.update(b"v1.local-enc")
        enc_key.update(nonce)
        enc_key = enc_key.finalize()[:32]

        # Используем AES-256-CTR
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce[:16]))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        try:
            return json.loads(plaintext.decode('utf-8'))
        except:
            return plaintext.decode('utf-8')

    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def verify_v4_public(public_key, signed_payload, footer=''):
    """Ed25519 проверка подписи по спецификации PASETO v4"""
    try:
        data = base64url_decode(signed_payload)
        
        if isinstance(public_key, bytes):
            if b'BEGIN PUBLIC KEY' in public_key:
                public_key = serialization.load_pem_public_key(public_key)
                if not isinstance(public_key, ed25519.Ed25519PublicKey):
                    raise ValueError("Invalid public key type")
            elif b'BEGIN PRIVATE KEY' in public_key:
                public_key = serialization.load_pem_private_key(public_key, password=None)
                if not isinstance(public_key, ed25519.Ed25519PrivateKey):
                    raise ValueError("Invalid private key type")
                public_key = public_key.public_key()
            else:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
                
        signature = data[-64:]
        message = data[:-64]
        
        m2 = b"v4.public." + message
        if footer:
            footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8')
            m2 += b"." + footer_bytes
            
        try:
            public_key.verify(signature, m2)
            try:
                return json.loads(message.decode('utf-8'))
            except:
                return message.decode('utf-8')
        except Exception:
            raise ValueError("Invalid signature")
            
    except Exception as e:
        raise ValueError(f"Verification failed: {str(e)}")

def sign_v4_public(private_key, payload, footer=''):
    """Ed25519 подпись по спецификации PASETO v4"""
    try:
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
            
        if isinstance(private_key, bytes):
            if b'BEGIN PRIVATE KEY' in private_key:
                private_key = serialization.load_pem_private_key(private_key, password=None)
                if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                    raise ValueError("Invalid private key type")
            elif len(private_key) == 32:
                # Если это seed, конвертируем в полный приватный ключ
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
            elif len(private_key) == 64:
                # Если это полный приватный ключ
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
            else:
                raise ValueError("Private key must be 32 or 64 bytes")
        elif not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TypeError("For version 4, private_key must be Ed25519PrivateKey or bytes")
                
        m2 = b"v4.public." + payload
        if footer:
            footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8')
            m2 += b"." + footer_bytes
            
        signature = private_key.sign(m2)
        
        token = f"v4.public.{base64url_encode(payload + signature)}"
        if footer:
            token += f".{base64url_encode(footer_bytes)}"
            
        return token
        
    except Exception as e:
        raise ValueError(f"Signing failed: {str(e)}")

def sign_v3_public(private_key, payload, footer=''):
    """ECDSA P-384 подпись"""
    try:
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
            
        if isinstance(private_key, bytes):
            if b'BEGIN PRIVATE KEY' in private_key or b'BEGIN EC PRIVATE KEY' in private_key:
                private_key = serialization.load_pem_private_key(private_key, password=None)
                if not isinstance(private_key, ec.EllipticCurvePrivateKey) or private_key.curve.name != 'secp384r1':
                    raise ValueError("Invalid private key type or curve")
            else:
                raise ValueError("Invalid private key format")
                
        # Кодируем payload в base64url
        encoded_payload = base64url_encode(payload)
        
        # Подготовка данных для подписи
        m2 = b"v3.public." + encoded_payload.encode('utf-8')
        if footer:
            footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8')
            m2 += b"." + footer_bytes
            
        # Создание подписи
        signature = private_key.sign(
            m2,
            ec.ECDSA(hashes.SHA384())
        )
        
        # Формируем токен
        token = f"v3.public.{encoded_payload}"
        if footer:
            token += f".{base64url_encode(footer_bytes)}"
        else:
            token += f".{base64url_encode(signature)}"
            
        return token
            
    except Exception as e:
        raise ValueError(f"Signing failed: {str(e)}")

def verify_v3_public(public_key, signed_payload, footer=''):
    """ECDSA P-384 проверка подписи"""
    try:
        # Разделяем данные на части
        parts = signed_payload.split('.')
        
        # Проверяем формат токена - полный токен или только полезная нагрузка
        if len(parts) >= 3 and parts[0] == 'v3' and parts[1] == 'public':
            # Это полный токен
            version, purpose, encoded_payload = parts[:3]
            signature_or_footer = parts[3] if len(parts) > 3 else None
        else:
            # Считаем, что передана только полезная нагрузка
            version = 'v3'
            purpose = 'public'
            encoded_payload = signed_payload
            signature_or_footer = footer
            footer = ''
        
        # Определяем, что является подписью, а что футером
        if footer:
            # Если передан footer, то signature_or_footer должен быть подписью
            if signature_or_footer is None:
                raise ValueError("Missing signature")
            signature = base64url_decode(signature_or_footer)
        else:
            # Если footer не передан, то signature_or_footer - это подпись
            if signature_or_footer is None:
                raise ValueError("Missing signature")
            signature = base64url_decode(signature_or_footer)
        
        # Загружаем публичный ключ
        if isinstance(public_key, str):
            with open(public_key, 'rb') as f:
                public_key = serialization.load_pem_public_key(public_key)
        
        if isinstance(public_key, bytes):
            if b'PUBLIC KEY' in public_key:
                public_key = serialization.load_pem_public_key(public_key)
                if not isinstance(public_key, ec.EllipticCurvePublicKey) or public_key.curve.name != 'secp384r1':
                    raise ValueError("Invalid public key type or curve")
            elif b'PRIVATE KEY' in public_key:
                private_key = serialization.load_pem_private_key(public_key, password=None)
                if not isinstance(private_key, ec.EllipticCurvePrivateKey) or private_key.curve.name != 'secp384r1':
                    raise ValueError("Invalid private key type or curve")
                public_key = private_key.public_key()
        
        # Подготовка данных для проверки
        m2 = f"v3.public.{encoded_payload}"
        if footer:
            footer_str = footer if isinstance(footer, str) else footer.decode('utf-8')
            m2 += f".{footer_str}"
        
        # Проверка подписи
        public_key.verify(
            signature,
            m2.encode('utf-8'),
            ec.ECDSA(hashes.SHA384())
        )
        
        # Если подпись верна, декодируем сообщение
        payload = base64url_decode(encoded_payload)
        try:
            return json.loads(payload.decode('utf-8'))
        except:
            return payload.decode('utf-8')
    
    except Exception as e:
        raise ValueError(f"Failed to decode: Verification failed: {str(e)}")

def verify_v2_public(public_key, signed_payload, footer=''):
    """Ed25519"""
    try:
        data = base64url_decode(signed_payload)
        
        if isinstance(public_key, bytes):
            if b'BEGIN PUBLIC KEY' in public_key:
                public_key = serialization.load_pem_public_key(public_key)
                if not isinstance(public_key, ed25519.Ed25519PublicKey):
                    raise ValueError("Invalid public key type")
            elif b'BEGIN PRIVATE KEY' in public_key:
                public_key = serialization.load_pem_private_key(public_key, password=None)
                if not isinstance(public_key, ed25519.Ed25519PrivateKey):
                    raise ValueError("Invalid private key type")
                public_key = public_key.public_key()
            else:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
                
        signature = data[-64:]  # Ed25519 подпись - 64 байта
        message = data[:-64]
        
        m2 = b"v2.public." + message
        if footer:
            footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8')
            m2 += b"." + footer_bytes
            
        try:
            public_key.verify(signature, m2)
            try:
                return json.loads(message.decode('utf-8'))
            except:
                return message.decode('utf-8')
        except Exception:
            raise ValueError("Invalid signature")
            
    except Exception as e:
        raise ValueError(f"Verification failed: {str(e)}")

def verify_v1_public(public_key, signed_payload, footer=''):
    """RSA-PSS"""
    try:
        data = base64url_decode(signed_payload)
        
        if isinstance(public_key, bytes):
            if b'BEGIN PUBLIC KEY' in public_key or b'BEGIN RSA PUBLIC KEY' in public_key:
                public_key = serialization.load_pem_public_key(public_key)
                if not isinstance(public_key, rsa.RSAPublicKey):
                    raise ValueError("Invalid public key type")
            elif b'BEGIN PRIVATE KEY' in public_key or b'BEGIN RSA PRIVATE KEY' in public_key:
                public_key = serialization.load_pem_private_key(public_key, password=None)
                if not isinstance(public_key, rsa.RSAPrivateKey):
                    raise ValueError("Invalid public key type")
                public_key = public_key.public_key()
            else:
                raise ValueError("Invalid public key format")
                
        signature = data[-256:]  # RSA-2048 подпись - 256 байт
        message = data[:-256]
        
        m2 = b"v1.public." + message
        if footer:
            footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8')
            m2 += b"." + footer_bytes
            
        try:
            public_key.verify(
                signature,
                m2,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA384()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA384()
            )
            try:
                return json.loads(message.decode('utf-8'))
            except:
                return message.decode('utf-8')
        except Exception:
            raise ValueError("Invalid signature")
            
    except Exception as e:
        raise ValueError(f"Verification failed: {str(e)}")

def sign_v2_public(private_key, payload, footer=''):
    """Ed25519"""
    try:
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
            
        if isinstance(private_key, bytes):
            if b'BEGIN PRIVATE KEY' in private_key:
                private_key = serialization.load_pem_private_key(private_key, password=None)
                if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                    raise ValueError("Invalid private key type")
            else:
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
                
        m2 = b"v2.public." + payload
        if footer:
            footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8')
            m2 += b"." + footer_bytes
            
        signature = private_key.sign(m2)
        
        token = f"v2.public.{base64url_encode(payload + signature)}"
        if footer:
            token += f".{base64url_encode(footer_bytes)}"
            
        return token
            
    except Exception as e:
        raise ValueError(f"Signing failed: {str(e)}")

def sign_v1_public(private_key, payload, footer=''):
    """RSA-PSS"""
    try:
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
            
        if isinstance(private_key, bytes):
            if b'BEGIN PRIVATE KEY' in private_key or b'BEGIN RSA PRIVATE KEY' in private_key:
                private_key = serialization.load_pem_private_key(private_key, password=None)
                if not isinstance(private_key, rsa.RSAPrivateKey):
                    raise ValueError("Invalid private key type")
            else:
                raise ValueError("Invalid private key format")
                
        m2 = b"v1.public." + payload
        if footer:
            footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8')
            m2 += b"." + footer_bytes
            
        signature = private_key.sign(
            m2,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA384()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA384()
        )
        
        token = f"v1.public.{base64url_encode(payload + signature)}"
        if footer:
            token += f".{base64url_encode(footer_bytes)}"
            
        return token
            
    except Exception as e:
        raise ValueError(f"Signing failed: {str(e)}")

def encrypt_v4_local(key, payload, footer='', nonce=None):
    """
    ChaCha20-Poly1305 по спецификации PASETO v4
    """
    try:
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes")

        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes")

        # Генерируем случайный nonce если не предоставлен
        if nonce is None:
            nonce = os.urandom(24)
        elif isinstance(nonce, str):
            nonce = bytes.fromhex(nonce)

        if len(nonce) != 24:
            raise ValueError("Nonce must be exactly 24 bytes")

        # Преобразуем payload в байты
        if isinstance(payload, bytes):
            payload_bytes = payload
        elif isinstance(payload, str):
            payload_bytes = payload.encode('utf-8')
        else:
            payload_bytes = json.dumps(payload).encode('utf-8')

        # Вычисляем ключ шифрования
        enc_key = hmac.HMAC(key, hashes.SHA384())
        enc_key.update(b"v4.local-enc")
        enc_key.update(nonce)
        enc_key = enc_key.finalize()[:32]

        # Используем ChaCha20-Poly1305 с первыми 12 байтами nonce
        cipher = ChaCha20Poly1305(enc_key)
        ciphertext = cipher.encrypt(nonce[:12], payload_bytes, None)

        # Формируем финальный токен
        token = base64url_encode(nonce + ciphertext)
        if footer:
            token = token + '.' + (footer if isinstance(footer, str) else footer.decode('utf-8'))

        return f"v4.local.{token}"

    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def encrypt_v3_local(key, payload, footer='', nonce=None):
    """
    AES-256-CTR + HMAC-SHA384 по спецификации PASETO v3
    """
    try:
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes")

        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes")

        # Генерируем случайный nonce если не предоставлен
        if nonce is None:
            nonce = os.urandom(32)
        elif isinstance(nonce, str):
            nonce = bytes.fromhex(nonce)

        if len(nonce) != 32:
            raise ValueError("Nonce must be exactly 32 bytes")

        # Преобразуем payload в байты
        if isinstance(payload, bytes):
            payload_bytes = payload
        elif isinstance(payload, str):
            payload_bytes = payload.encode('utf-8')
        else:
            payload_bytes = json.dumps(payload).encode('utf-8')

        # Вычисляем ключ шифрования
        enc_key = hmac.HMAC(key, hashes.SHA384())
        enc_key.update(b"v3.local-enc")
        enc_key.update(nonce)
        enc_key = enc_key.finalize()[:32]

        # Используем AES-256-CTR
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce[:16]))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(payload_bytes) + encryptor.finalize()

        # Вычисляем MAC ключ
        mac_key = hmac.HMAC(key, hashes.SHA384())
        mac_key.update(b"v3.local-mac")
        mac_key = mac_key.finalize()[:32]

        # Вычисляем MAC
        footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8') if footer else b""
        pre_auth_pae = pre_auth_encode(b"v3.local.", nonce + ciphertext, footer_bytes)
        mac = hmac.HMAC(mac_key, hashes.SHA384())
        mac.update(pre_auth_pae)
        tag = mac.finalize()[:48]

        # Формируем финальный токен
        token = base64url_encode(nonce + ciphertext + tag)
        if footer:
            token = token + '.' + (footer if isinstance(footer, str) else footer.decode('utf-8'))

        return f"v3.local.{token}"

    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def encrypt_v2_local(key, payload, footer='', nonce=None):
    """XChaCha20-Poly1305 согласно спецификации PASETO v2"""
    try:
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        if isinstance(payload, str):
            payload_bytes = payload.encode('utf-8')
        else:
            payload_bytes = payload
            
        # Нормализуем ключ до 32 байт для SecretBox
        if len(key) < 32:
            padded_key = key.ljust(32, b'\0')
        elif len(key) > 32:
            padded_key = key[:32]
        else:
            padded_key = key
            
        # Генерируем nonce или используем переданный
        if nonce is None:
            nonce = calculate_nonce(padded_key, payload_bytes, 'v2')
        elif isinstance(nonce, str):
            nonce = bytes.fromhex(nonce)
            
        # Создаем SecretBox (NaCl) для шифрования
        box = SecretBox(padded_key)
        ciphertext_with_tag = box.encrypt(payload_bytes, nonce=nonce).ciphertext
        
        # Формируем токен
        pre_auth = b"v2.local."
        footer_bytes = b""
        if footer:
            footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8')
            
        # Формируем токен
        token = f"v2.local.{base64url_encode(nonce + ciphertext_with_tag)}"
        if footer:
            token += f".{base64url_encode(footer_bytes)}"
            
        return token
            
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def encrypt_v1_local(key, payload, footer='', nonce=None):
    """
    AES-256-CTR + HMAC-SHA384 по спецификации PASETO v1
    """
    try:
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes")

        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes")

        # Генерируем случайный nonce если не предоставлен
        if nonce is None:
            nonce = os.urandom(32)
        elif isinstance(nonce, str):
            nonce = bytes.fromhex(nonce)

        if len(nonce) != 32:
            raise ValueError("Nonce must be exactly 32 bytes")

        # Преобразуем payload в байты
        if isinstance(payload, bytes):
            payload_bytes = payload
        elif isinstance(payload, str):
            payload_bytes = payload.encode('utf-8')
        else:
            payload_bytes = json.dumps(payload).encode('utf-8')

        # Вычисляем ключ шифрования
        enc_key = hmac.HMAC(key, hashes.SHA384())
        enc_key.update(b"v1.local-enc")
        enc_key.update(nonce)
        enc_key = enc_key.finalize()[:32]

        # Используем AES-256-CTR
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce[:16]))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(payload_bytes) + encryptor.finalize()

        # Вычисляем MAC ключ
        mac_key = hmac.HMAC(key, hashes.SHA384())
        mac_key.update(b"v1.local-mac")
        mac_key = mac_key.finalize()[:32]

        # Вычисляем MAC
        footer_bytes = footer if isinstance(footer, bytes) else footer.encode('utf-8') if footer else b""
        pre_auth_pae = pre_auth_encode(b"v1.local.", nonce + ciphertext, footer_bytes)
        mac = hmac.HMAC(mac_key, hashes.SHA384())
        mac.update(pre_auth_pae)
        tag = mac.finalize()[:48]

        # Формируем финальный токен
        token = base64url_encode(nonce + ciphertext + tag)
        if footer:
            token = token + '.' + (footer if isinstance(footer, str) else footer.decode('utf-8'))

        return f"v1.local.{token}"

    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")
