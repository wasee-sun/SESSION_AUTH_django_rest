from django.conf import settings
from django.core.cache import cache
from .encryption import generate_hash_key, encrypt_data, decrypt_data


def get_cache_data(prefix, token):
    """Decrypt and return the cache data from Redis"""
    hashed_key = generate_hash_key(token)
    encrypted_data = cache.get(f"{prefix}:{hashed_key}")

    if not encrypted_data:
        return {"error": "Invalid Token"}

    return {
        "hashed_key": hashed_key,
        "decrypted_data": decrypt_data(encrypted_data),
    }


def set_cache_data(
    prefix,
    raw_cache_data,
    object_type,
    main_cache_ttl,
    throttle_id=None,
    cooldown_cache_ttl=None,
):
    """Encrypt and store the cache data in Redis"""

    encrypt_obj = encrypt_data(raw_cache_data, object_type)

    cache.set(
        f"{prefix}:{encrypt_obj["hashed_key"]}",
        encrypt_obj["encrypted_data"],
        timeout=main_cache_ttl,
    )

    if throttle_id:
        user_lock_key = generate_hash_key(throttle_id)
        cache.set(
            f"{prefix}-cooldown:{user_lock_key}",
            True,
            timeout=cooldown_cache_ttl,
        )

    return str(encrypt_obj["token"])
