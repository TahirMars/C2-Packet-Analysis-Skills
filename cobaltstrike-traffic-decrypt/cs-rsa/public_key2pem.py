from Crypto.PublicKey import RSA
import binascii

# 将你的16进制字符串放在这里
hex_key = "30819f300d06092a864886f70d010101050003818d00308189028181008e8b16bf2a9182d1bf8f349ee14645aec658010212b7521ba28951208131614432740c834d19483d56695764c25e39aefe14b9242b1fd9b7c79ffd96571cbf01cdd0e42563536e00f62175b978e96c772a2d0f05f1615d98d6ea189e4938f816a935bf16653fed8e5c1ea5ddb1309505a2d68a1426ac50268d6beaf51d1b817b0203010001" 
# 将十六进制字符串转换为字节
key_bytes = binascii.unhexlify(hex_key)
# 导入RSA公钥
rsa_key = RSA.import_key(key_bytes)
# 提取模数(n)和指数(e)
n = rsa_key.n
e = rsa_key.e
# 打印模数和指数
print(f"Modulus (n): {n}")
print(f"Exponent (e): {e}")

# 将RSA公钥导出为PEM格式
pem_key = rsa_key.publickey().export_key(format='PEM')
# 打印PEM格式公钥
print(pem_key.decode('utf-8'))
   