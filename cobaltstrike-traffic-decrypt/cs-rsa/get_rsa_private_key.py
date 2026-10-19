# -*- coding: utf-8 -*-
from Crypto.PublicKey import RSA
def generate_rsa_keypair(p, q, e=65537):
    """
    生成RSA密钥对。

    :param p: 大素数p
    :param q: 大素数q
    :param e: 公钥指数，默认为65537
    :return: RSA私钥
    """
    # 计算模数N
    N = p * q
    # 计算欧拉函数phi(N)
    phi = (p - 1) * (q - 1)
    # 计算私钥d
    d = pow(e, -1, phi)
    # 构造RSA私钥
    pri_key = RSA.construct((N, e, d))
    return pri_key

def save_private_key_to_file(private_key, filename="id_rsa"):
    """
    将私钥保存到文件中。

    :param private_key: RSA私钥对象
    :param filename: 保存的文件名，默认为"id_rsa"
    """
    with open(filename, "wb") as f:
        f.write(private_key.export_key("PEM"))

# 示例：生成RSA密钥对并保存私钥
if __name__ == "__main__":
    # 输入大素数p和q
    p = 7605291443685150594150190909345113655196508809219162555499789316232908573154196070425269090153291952292016936024761413150455793038505322748933150548026527
    q = 7605291443685150594150190909345113655196508809219162555499789316232908573154196070425269090153291952292016936024761413150455793038505322748933150548026221

    private_key = generate_rsa_keypair(p, q)
    print(f"private key: ", RSA.import_key(private_key))
    save_private_key_to_file(private_key)
    print(f"saved private key ：id_rsa")