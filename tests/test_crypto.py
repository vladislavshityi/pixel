#Тесты для app/services/crypto.py.
#Каждый тест устроен одинаково: подготовить данные -> вызвать функцию -> сравнить (assert).

import string
import uuid

from app.services import crypto

# Тестовая пара, выданная `mihomo generate reality-keypair.
MIHOMO_PRIVATE_KEY = "aIluTeYBcoEDV6x8BANtQ6rZ1RdvN3t3_m_1luPDV1A"
MIHOMO_PUBLIC_KEY = "Kv8aeMsLMEN4-DFJ74bWAP3AiA4nlR_cjxYi9qZaun4"

# Алфавит url-safe base64: обычный base64, но вместо "+" и "/" используются "-" и "_".
URLSAFE_B64_ALPHABET = set(string.ascii_letters + string.digits + "-_")
HEX_ALPHABET = set("0123456789abcdef")

#Ключи Reality
def test_public_key_matches_mihomo():
    assert crypto.public_key_generator(MIHOMO_PRIVATE_KEY) == MIHOMO_PUBLIC_KEY

def test_private_key_has_mihomo_format():
    key = crypto.private_key_generator()
    assert len(key) == 43
    assert "=" not in key
    assert set(key) <= URLSAFE_B64_ALPHABET

def test_public_key_has_mihomo_format():
    key = crypto.public_key_generator(crypto.private_key_generator())
    assert len(key) == 43
    assert "=" not in key
    assert set(key) <= URLSAFE_B64_ALPHABET


def test_public_key_is_deterministic():
    private = crypto.private_key_generator()
    assert crypto.public_key_generator(private) == crypto.public_key_generator(private)


def test_private_keys_are_unique():
    assert crypto.private_key_generator() != crypto.private_key_generator()

#short-id, secret, UUID
def test_short_id_is_16_hex_chars():
    short_id = crypto.short_id_generator()
    assert len(short_id) == 16
    assert set(short_id) <= HEX_ALPHABET


def test_secret_api_key_is_64_hex_chars():
    secret = crypto.secret_api_key_generator()
    assert len(secret) == 64
    assert set(secret) <= HEX_ALPHABET


def test_user_uuid_is_valid_uuid4():
    value = crypto.user_uuid_generator()
    # uuid.UUID() упадёт, если строка не UUID; version проверяет, что это именно v4.
    assert uuid.UUID(value).version == 4
    assert str(uuid.UUID(value)) == value
