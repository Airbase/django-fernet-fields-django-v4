INSTALLED_APPS = [
    'fernet_fields.test',
]

SECRET_KEY = 'secret'

SILENCED_SYSTEM_CHECKS = ['1_7.W001']

# Existing tests use naive datetimes; USE_TZ=True is covered in test_crypto.py
USE_TZ = False
