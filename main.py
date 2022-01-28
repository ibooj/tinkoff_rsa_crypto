from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15


def concat_values(data: dict) -> str:
    """
    Формирует канкотинированную строку из переданных данных.
    :param data: параметры.
    :return: канонизированную строку.
    """
    return ''.join([str(data[key]) for key in sorted(data.keys())])


def calc_digest(data: bytes) -> bytes:
    """
    Вычисляет хеш-значение от переданных данных.
    :param data: сырые данные.
    :return: вычисленное хеш-значение.
    """
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(data)
    return hasher.finalize()


def calc_signature(key: bytes, digest: bytes) -> bytes:
    """
    Формирует подпись для переданных данных.
    :param key: ключ для формирования подписи.
    :param digest: сырые данные.
    :return: сформированную подпись.
    """
    private_key = serialization.load_pem_private_key(key, password=None)
    return private_key.sign(digest, PKCS1v15(), hashes.SHA256())
