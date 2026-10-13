"""Deep tests for the cryptography-dependent pieces.

Golden vectors were generated with cryptography 41.0.7 and pin the on-disk
format, so an upgrade of ``cryptography`` can never silently make existing
encrypted data undecryptable.
"""
import base64
import time

import pytest
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

import fernet_fields as fields
from fernet_fields import hkdf
from . import models

DERIVED_KEYS = [
    ('secret', b'eWHXcUXxud6rRb_yANSEsNsfZ0YFs2P6OTSzfFeL55E='),
    ('key1', b'P7lQELXAge5sAkWyi4IfqEbdG5j7fCPozg4TW0E7ff4='),
    ('', b'SuI5KyU9Uqrrst623hJb98pxlQDRvFaFDCeOBtbqpNU='),
    (u'\xfcn\xefcode-κey', b'XswDC2eJM_FX9AL7IMUouWMr-eUcFCEzljWL1PR-n4U='),
    (b'bytes-key', b'kMRPHamNoLnJfwfpROu7JGSKpTwXYXIXGkk8P4gC6vI='),
]

# Token produced from derive_fernet_key('secret') with fixed time and IV.
GOLDEN_TOKEN = (
    b'gAAAAABlU_EAAQEBAQEBAQEBAQEBAQEBAQ6KwMLI4s788w3kwFIPF-YjBg0mLRi0yTwgLO0o'
    b'Slw5SYUfnDbjZogs2uqQca0JNg=='
)


class TestHKDF(object):
    @pytest.mark.parametrize('inp,expected', DERIVED_KEYS)
    def test_known_answer(self, inp, expected):
        assert hkdf.derive_fernet_key(inp) == expected

    def test_deterministic(self):
        assert hkdf.derive_fernet_key('x') == hkdf.derive_fernet_key('x')

    def test_different_inputs_differ(self):
        assert hkdf.derive_fernet_key('a') != hkdf.derive_fernet_key('b')

    def test_valid_fernet_key_shape(self):
        key = hkdf.derive_fernet_key('anything')
        assert len(base64.urlsafe_b64decode(key)) == 32
        Fernet(key)  # must be accepted

    def test_str_and_bytes_equivalent(self):
        assert hkdf.derive_fernet_key('abc') == hkdf.derive_fernet_key(b'abc')


class TestFernetCompat(object):
    def test_decrypt_golden_token(self):
        f = Fernet(hkdf.derive_fernet_key('secret'))
        assert f.decrypt(GOLDEN_TOKEN) == b'hello world'

    def test_field_decrypts_golden_token(self, settings):
        settings.SECRET_KEY = 'secret'
        field = fields.EncryptedTextField()
        assert field.fernet.decrypt(GOLDEN_TOKEN) == b'hello world'

    def test_roundtrip_various_payloads(self):
        f = Fernet(Fernet.generate_key())
        for payload in [b'', b'a', b'\x00\xff' * 1000, b'x' * 100000]:
            assert f.decrypt(f.encrypt(payload)) == payload

    def test_encrypt_is_nondeterministic(self):
        f = Fernet(Fernet.generate_key())
        assert f.encrypt(b'a') != f.encrypt(b'a')

    def test_tampered_token_rejected(self):
        f = Fernet(hkdf.derive_fernet_key('secret'))
        bad = bytearray(base64.urlsafe_b64decode(GOLDEN_TOKEN))
        bad[-1] ^= 1
        with pytest.raises(InvalidToken):
            f.decrypt(base64.urlsafe_b64encode(bytes(bad)))

    def test_wrong_key_rejected(self):
        f = Fernet(hkdf.derive_fernet_key('other'))
        with pytest.raises(InvalidToken):
            f.decrypt(GOLDEN_TOKEN)

    def test_ttl_expiry(self):
        f = Fernet(hkdf.derive_fernet_key('secret'))
        # golden token timestamp is 2023; far older than any ttl
        with pytest.raises(InvalidToken):
            f.decrypt(GOLDEN_TOKEN, ttl=60)
        assert f.decrypt(f.encrypt(b'fresh'), ttl=60) == b'fresh'

    def test_multifernet_rotation(self):
        old, new = Fernet(Fernet.generate_key()), Fernet(Fernet.generate_key())
        token = old.encrypt(b'data')
        multi = MultiFernet([new, old])
        assert multi.decrypt(token) == b'data'
        rotated = multi.rotate(token)
        assert new.decrypt(rotated) == b'data'

    def test_garbage_token(self):
        with pytest.raises(InvalidToken):
            Fernet(Fernet.generate_key()).decrypt(b'not-a-token')


class TestFieldKeys(object):
    def test_single_key_uses_fernet(self, settings):
        settings.FERNET_KEYS = ['k']
        assert isinstance(fields.EncryptedTextField().fernet, Fernet)

    def test_multiple_keys_use_multifernet(self, settings):
        settings.FERNET_KEYS = ['k1', 'k2']
        assert isinstance(fields.EncryptedTextField().fernet, MultiFernet)

    def test_rotation_encrypts_with_first_key(self, settings):
        settings.FERNET_KEYS = ['new', 'old']
        f = fields.EncryptedTextField()
        token = f.fernet.encrypt(b'v')
        assert Fernet(f.fernet_keys[0]).decrypt(token) == b'v'
        with pytest.raises(InvalidToken):
            Fernet(f.fernet_keys[1]).decrypt(token)

    def test_no_hkdf_raw_keys(self, settings):
        settings.FERNET_USE_HKDF = False
        key = Fernet.generate_key()
        settings.FERNET_KEYS = [key]
        f = fields.EncryptedTextField()
        assert f.fernet_keys == [key]


@pytest.mark.django_db
class TestDBRoundtrip(object):
    def test_raw_column_is_golden_compatible_ciphertext(self, settings):
        """Stored bytes are a Fernet token decryptable by the derived key."""
        from django.db import connection
        obj = models.EncryptedText.objects.create(value='hello world')
        with connection.cursor() as c:
            c.execute('SELECT value FROM %s' % models.EncryptedText._meta.db_table)
            raw = bytes(c.fetchone()[0])
        key = hkdf.derive_fernet_key(settings.SECRET_KEY)
        assert Fernet(key).decrypt(raw) == b'hello world'
        assert models.EncryptedText.objects.get(pk=obj.pk).value == 'hello world'

    def test_legacy_ciphertext_readable_through_orm(self, settings):
        from django.db import connection
        settings.SECRET_KEY = 'secret'
        # re-create field cache with the key under test
        models.EncryptedText._meta.get_field('value').__dict__.pop('fernet', None)
        models.EncryptedText._meta.get_field('value').__dict__.pop('fernet_keys', None)
        models.EncryptedText._meta.get_field('value').__dict__.pop('keys', None)
        obj = models.EncryptedText.objects.create(value='placeholder')
        with connection.cursor() as c:
            c.execute(
                'UPDATE %s SET value = %%s WHERE id = %%s'
                % models.EncryptedText._meta.db_table,
                [GOLDEN_TOKEN, obj.pk])
        assert models.EncryptedText.objects.get(pk=obj.pk).value == 'hello world'

    def test_unicode_roundtrip(self):
        text = u'h\xe9llo 世界 \U0001f512'
        obj = models.EncryptedText.objects.create(value=text)
        assert models.EncryptedText.objects.get(pk=obj.pk).value == text

