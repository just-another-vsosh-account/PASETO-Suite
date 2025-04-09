import pytest
from lib import PasetoToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

@pytest.fixture
def setup_tokens():
    # Генерация RSA ключей для v1
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    local_key = b'asd'
    local_payload = {'data': 'local_payload'}
    public_payload = {'data': 'public_payload'}
    
    tokens = {
        'local': {
            'v1': PasetoToken(key=local_key, version='v1', purpose='local', payload=local_payload),
        },
        'public': {
            'v1': PasetoToken(key=private_pem, version='v1', purpose='public', payload=public_payload),
        }
    }
    return tokens

def test_local_encrypt(setup_tokens):
    for version in setup_tokens['local']:
        token = setup_tokens['local'][version].encrypt()
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        assert token.startswith(f'{version}.local.')

def test_public_sign(setup_tokens):
    for version in setup_tokens['public']:
        token = setup_tokens['public'][version].sign()
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        assert token.startswith(f'{version}.public.')

def test_local_decrypt(setup_tokens):
    for version in setup_tokens['local']:
        token = setup_tokens['local'][version].encrypt()
        local_token = PasetoToken.from_paseto(setup_tokens['local'][version].key, token)
        decrypted_payload = local_token.decrypt()
        assert decrypted_payload == setup_tokens['local'][version].payload

def test_public_verify(setup_tokens):
    for version in setup_tokens['public']:
        token = setup_tokens['public'][version].sign()
        public_token = PasetoToken.from_paseto(setup_tokens['public'][version].key, token)
        verified_payload = public_token.verify()
        assert verified_payload == setup_tokens['public'][version].payload

def test_invalid_token_format():
    with pytest.raises(ValueError):
        PasetoToken.from_paseto(b'secret_key_32_bytes_long', 'invalid.token.format')


