import pytest
from lib import PasetoToken
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

@pytest.fixture
def setup_tokens():
    # Генерация Ed25519 ключей для v2
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    local_key = b'asd'
    local_payload = {'data': 'local_payload'}
    public_payload = {'data': 'public_payload'}
    
    tokens = {
        'local': {
            'v2': PasetoToken(key=local_key, version='v2', purpose='local', payload=local_payload),
        },
        'public': {
            'v2': PasetoToken(key=private_key, version='v2', purpose='public', payload=public_payload),
        },
        'verify': {
            'v2': public_bytes
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
        public_token = PasetoToken.from_paseto(setup_tokens['verify'][version], token)
        verified_payload = public_token.verify()
        assert verified_payload == setup_tokens['public'][version].payload

def test_invalid_token_format():
    with pytest.raises(ValueError):
        PasetoToken.from_paseto(b'secret_key_32_bytes_long', 'invalid.token.format')


