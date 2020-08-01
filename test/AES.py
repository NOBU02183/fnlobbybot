# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
key_size = 32
iv = '1234567890123456'.encode('utf-8')

def create_key(p_key):
    """
    キーデータ(bytes)を作成する。
    長さが32でない場合は、0埋め、もしくはtrimする。
    :param p_key:
    :return:
    """
    key_size_fill = p_key.zfill(key_size)
    key = key_size_fill[:key_size].encode('utf-8')
    return key


def encrypt(data, p_key):
    """
    暗号化
    :param data: 暗号化対象データ
    :param p_key: 暗号キー
    :return:
    """
    key = create_key(p_key)
    obj = AES.new(key, AES.MODE_CFB, iv)

    ret_bytes = obj.encrypt(data)
    
    return ret_bytes


def decrypt(data, p_key):
    """
    復号化
    :param data:復号化データ
    :param p_key:暗号キー
    :return:
    """
    key = create_key(p_key)
    obj = AES.new(key, AES.MODE_CFB, iv)
    return obj.decrypt(data)
