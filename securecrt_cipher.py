#!/usr/bin/env python3
import os, struct
from Crypto.Hash import SHA256, SHA512
from Crypto.Cipher import AES, Blowfish
from Crypto.Protocol import KDF

# bcrypt哈希函数实现
# 用于生成基于密码和盐的哈希值，采用特定的Blowfish算法变体
def bcrypt_hash(password: bytes, salt: bytes) -> bytes:
    password = SHA512.new(password).digest()
    salt = SHA512.new(salt).digest()

    # 使用指定的Blowfish变体进行哈希计算
    digest = KDF._bcrypt_hash(password, 6, salt, b'OxychromaticBlowfishSwatDynamite', False)
    # 调整字节顺序，将每个4字节块反转
    digest = b''.join(digest[i:i + 4][::-1] for i in range(0, len(digest), 4))

    return digest

# bcrypt PBKDF2密钥派生函数
# 通过多次迭代的bcrypt哈希生成指定长度的密钥
def bcrypt_pbkdf2(password: bytes, salt: bytes, key_length: int, rounds: int) -> bytes:
    BCRYPT_BLOCKS = 8
    BCRYPT_HASHSIZE = BCRYPT_BLOCKS * 4

    # 计算输出长度，确保是BCRYPT_HASHSIZE的整数倍
    out_len = (key_length + BCRYPT_HASHSIZE - 1) // BCRYPT_HASHSIZE * BCRYPT_HASHSIZE
    # 使用PBKDF2算法，以bcrypt_hash作为伪随机函数
    out = KDF.PBKDF2(password, salt, out_len, rounds, prf = bcrypt_hash)

    # 计算步长并提取所需长度的密钥
    stride_n = (key_length + BCRYPT_HASHSIZE - 1) // BCRYPT_HASHSIZE
    return bytes(out[sum(a * b for a, b in zip(divmod(i, stride_n), (1, BCRYPT_HASHSIZE)))] for i in range(0, key_length))

class SecureCRTCrypto:
    """
    SecureCRT密码加密解密V1版本实现
    使用Blowfish算法进行加密解密，适用于早期版本的SecureCRT
    """
    def __init__(self) -> None:
        '''初始化SecureCRTCrypto对象'''
        # 初始化向量(IV)，全部为0字节
        self._iv = b'\x00' * Blowfish.block_size
        # 固定加密密钥1
        self._key1 = b'\x24\xA6\x3D\xDE\x5B\xD3\xB3\x82\x9C\x7E\x06\xF4\x08\x16\xAA\x07'
        # 固定加密密钥2
        self._key2 = b'\x5F\xB0\x45\xA2\x94\x17\xD9\x16\xC6\xC6\xA2\xFF\x06\x41\x82\xB7'

    def encrypt(self, plaintext: str) -> str:
        '''
        加密明文并返回对应的密文

        参数:
            plaintext (str): 要加密的ASCII字符串

        返回:
            str: 十六进制编码的密文字符串
        '''
        # 将明文转换为UTF-16LE编码的字节流
        plaintext_bytes = plaintext.encode('utf-16-le')
        # 添加空终止符
        plaintext_bytes += b'\x00\x00'

        # 计算需要的填充长度，确保数据长度为Blowfish块大小的整数倍
        padding_length = Blowfish.block_size - len(plaintext_bytes) % Blowfish.block_size
        # 添加随机填充
        plaintext_bytes_padded = plaintext_bytes + os.urandom(padding_length)

        # 使用两个不同密钥的Blowfish-CBC模式加密器
        cipher1 = Blowfish.new(self._key1, Blowfish.MODE_CBC, iv = self._iv)
        cipher2 = Blowfish.new(self._key2, Blowfish.MODE_CBC, iv = self._iv)
        # 加密过程：添加4字节随机前缀 -> 使用key2加密 -> 添加4字节随机后缀 -> 使用key1加密
        encrypted_data = cipher1.encrypt(os.urandom(4) + cipher2.encrypt(plaintext_bytes_padded) + os.urandom(4))
        # 返回十六进制编码的密文
        return encrypted_data.hex()

    def decrypt(self, ciphertext: str) -> str:
        '''
        解密密文并返回对应的明文

        参数:
            ciphertext (str): 要解密的十六进制字符串

        返回:
            str: 明文字符串
        '''
        # 创建两个Blowfish-CBC解密器
        cipher1 = Blowfish.new(self._key1, Blowfish.MODE_CBC, iv = self._iv)
        cipher2 = Blowfish.new(self._key2, Blowfish.MODE_CBC, iv = self._iv)

        # 将十六进制密文转换为字节流
        ciphertext_bytes = bytes.fromhex(ciphertext)
        # 检查密文长度是否有效
        if len(ciphertext_bytes) <= 8:
            raise ValueError('无效密文: 长度过短!')

        # 解密过程：先用key1解密 -> 去除前后4字节随机数据 -> 再用key2解密
        plaintext_bytes_padded = cipher2.decrypt(cipher1.decrypt(ciphertext_bytes)[4:-4])

        # 寻找UTF-16LE的空终止符（两个连续的0字节）
        null_terminator_index = -1
        for i in range(0, len(plaintext_bytes_padded), 2):
            if plaintext_bytes_padded[i] == 0 and plaintext_bytes_padded[i + 1] == 0:
                null_terminator_index = i
                break
        # 检查是否找到空终止符
        if null_terminator_index < 0:
            raise ValueError('无效密文: 未找到空终止符.')
        else:
            # 计算填充长度
            padding_len = len(plaintext_bytes_padded) - (null_terminator_index + 2)
            assert(padding_len >= 0)

            # 验证填充是否正确
            if padding_len != Blowfish.block_size - (null_terminator_index + 2) % Blowfish.block_size:
                raise ValueError('无效密文: 填充不正确.')

        # 提取实际明文字节（空终止符之前的部分）
        plaintext_bytes = plaintext_bytes_padded[0:null_terminator_index]

        try:
            # 将UTF-16LE字节流解码为字符串
            return plaintext_bytes.decode('utf-16-le')
        except UnicodeDecodeError:
            raise ValueError('无效密文: 不是UTF16-LE编码.')

class SecureCRTCryptoV2:
    """
    SecureCRTCrypto密码加密解密V2版本实现
    使用AES算法进行加密解密，支持配置密码保护，适用于新版本的SecureCRT
    """
    def __init__(self, config_passphrase: str = ''):
        '''
        初始化SecureCRTCryptoV2对象

        参数:
            config_passphrase (str): SecureCRT使用的配置密码，如果未设置则留空
        '''
        self._config_passphrase = config_passphrase.encode('utf-8')

    def encrypt(self, plaintext: str, **kwargs) -> str:
        '''
        加密明文并返回对应的密文

        参数:
            plaintext (str): 要加密的ASCII字符串
            **kwargs: 关键字参数，支持prefix（加密前缀，默认'03'）

        返回:
            str: 十六进制编码的密文字符串
        '''
        # 将明文转换为UTF-8字节流
        plaintext_bytes = plaintext.encode('utf-8')
        # 获取加密前缀，默认为'03'
        prefix = kwargs.get('prefix', '03')

        # 检查明文长度是否超过最大限制
        if len(plaintext_bytes) > 0xffffffff:
            raise OverflowError('无效明文: 长度过长!')

        # 根据前缀选择不同的加密方式
        if prefix == '02':
            # 使用SHA256哈希配置密码作为AES密钥
            cipher = AES.new(SHA256.new(self._config_passphrase).digest(), AES.MODE_CBC, iv = b'\x00' * AES.block_size)
        elif prefix == '03':
            # 生成16字节随机盐值
            salt = os.urandom(16)
            # 使用bcrypt_pbkdf2派生32字节密钥和16字节IV
            kdf_bytes = bcrypt_pbkdf2(self._config_passphrase, salt, 32 + AES.block_size, 16)
            # 创建AES-CBC加密器
            cipher = AES.new(kdf_bytes[:32], mode = AES.MODE_CBC, iv = kdf_bytes[32:])
        else:
            raise NotImplementedError(f'未知前缀: {prefix}')

        # 构建lvc结构: 4字节长度 + 明文 + 32字节SHA256校验和
        lvc_bytes = struct.pack('<I', len(plaintext_bytes)) + plaintext_bytes + SHA256.new(plaintext_bytes).digest()

        # 计算填充长度，确保总长度为AES块大小的整数倍
        padding_len = AES.block_size - len(lvc_bytes) % AES.block_size
        # 如果填充长度小于块大小的一半，则额外添加一个块的填充
        if padding_len < AES.block_size // 2:
            padding_len += AES.block_size

        # 加密lvc结构和随机填充
        ciphertext_bytes = cipher.encrypt(lvc_bytes + os.urandom(padding_len))
        # 对于prefix=03，在密文前添加盐值
        if prefix == '03':
            ciphertext_bytes = salt + ciphertext_bytes

        # 返回十六进制编码的密文
        return ciphertext_bytes.hex()

    def decrypt(self, ciphertext: str, **kwargs) -> str:
        '''
        解密密文并返回对应的明文

        参数:
            ciphertext (str): 要解密的十六进制字符串
            **kwargs: 关键字参数，支持prefix（加密前缀，默认'03'）

        返回:
            str: 明文字符串
        '''
        # 将十六进制密文转换为字节流
        ciphertext_bytes = bytes.fromhex(ciphertext)
        # 获取加密前缀，默认为'03'
        prefix = kwargs.get('prefix', '03')

        # 根据前缀选择不同的解密方式
        if prefix == '02':
            # 使用SHA256哈希配置密码作为AES密钥
            cipher = AES.new(SHA256.new(self._config_passphrase).digest(), AES.MODE_CBC, iv = b'\x00' * AES.block_size)
        elif prefix == '03':
            # 检查密文长度是否足够（至少包含16字节盐值）
            if len(ciphertext_bytes) < 16:
                raise ValueError('无效密文: 长度过短!')
            # 分离盐值和实际密文
            salt, ciphertext_bytes = ciphertext_bytes[:16], ciphertext_bytes[16:]
            # 使用bcrypt_pbkdf2派生32字节密钥和16字节IV
            kdf_bytes = bcrypt_pbkdf2(self._config_passphrase, salt, 32 + AES.block_size, 16)
            # 创建AES-CBC解密器
            cipher = AES.new(kdf_bytes[:32], mode = AES.MODE_CBC, iv = kdf_bytes[32:])
        else:
            raise NotImplementedError(f'未知前缀: {prefix}')

        # 解密获取带填充的lvc结构
        padded_bytes = cipher.decrypt(ciphertext_bytes)

        # 解析前4字节获取明文长度
        plaintext_len, = struct.unpack('<I', padded_bytes[0:4])
        # 检查密文是否包含足够的明文数据
        if len(padded_bytes) < 4 + plaintext_len:
            raise ValueError('无效密文: 明文长度不正确.')

        # 提取明文字节
        plaintext_bytes = padded_bytes[4:][:plaintext_len]
        # 检查密文是否包含完整的校验和
        if len(padded_bytes) < 4 + plaintext_len + SHA256.digest_size:
            raise ValueError('无效密文: 缺少SHA256校验和.')

        # 提取校验和和填充字节
        checksum_bytes = padded_bytes[4 + plaintext_len:][:SHA256.digest_size]
        padding_bytes = padded_bytes[4 + plaintext_len + SHA256.digest_size:]

        # 计算预期的填充长度
        expected_padding_len = AES.block_size - (4 + plaintext_len + SHA256.digest_size) % AES.block_size
        if expected_padding_len < AES.block_size // 2:
            expected_padding_len += AES.block_size

        # 验证填充长度是否正确
        if len(padding_bytes) != expected_padding_len:
            raise ValueError('无效密文: 填充不正确.')

        # 验证SHA256校验和
        if SHA256.new(plaintext_bytes).digest() != checksum_bytes:
            raise ValueError('无效密文: SHA256校验和不正确.')

        # 将明文字节解码为字符串
        return plaintext_bytes.decode('utf-8')

if __name__ == '__main__':
    import argparse

    # 创建命令行参数解析器
    parser = argparse.ArgumentParser()
    # 创建子解析器用于区分加密和解密操作
    subparsers = parser.add_subparsers(dest = 'OPERATION', required = True)

    # 创建加密操作子解析器
    enc_subparser = subparsers.add_parser('enc', help = '执行加密操作')
    # 创建解密操作子解析器
    dec_subparser = subparsers.add_parser('dec', help = '执行解密操作')

    # 为加密操作添加参数
    enc_subparser.add_argument(
        '-2', '--v2',
        action = 'store_true',
        help = '使用"Password V2"算法进行加密/解密'
    )
    enc_subparser.add_argument(
        '--prefix',
        action = 'store',
        type = str,
        choices = ['02', '03'],
        default = '03',
        help = '使用"Password V2"算法生成的加密密码前缀'
    )
    enc_subparser.add_argument(
        '-p', '--passphrase',
        action = 'store',
        type = str,
        help = 'SecureCRT使用的配置密码'
    )
    enc_subparser.add_argument(
        'PASSWORD',
        type = str,
        help = '要加密的明文密码'
    )

    # 为解密操作添加参数
    dec_subparser.add_argument(
        '-2', '--v2',
        action = 'store_true',
        help = '使用"Password V2"算法进行加密/解密'
    )
    dec_subparser.add_argument(
        '--prefix',
        action = 'store',
        type = str,
        choices = ['02', '03'],
        default = '03',
        help = '使用"Password V2"算法生成的加密密码前缀'
    )
    dec_subparser.add_argument(
        '-p', '--passphrase',
        action = 'store',
        type = str,
        help = 'SecureCRT使用的配置密码'
    )
    dec_subparser.add_argument(
        'PASSWORD',
        type = str,
        help = '要解密的加密密码'
    )

    # 解析命令行参数
    args = parser.parse_args()

    # 确定要执行的操作（加密或解密）
    if args.OPERATION == 'enc':
        operation = 'encrypt'
    elif args.OPERATION == 'dec':
        operation = 'decrypt'
    else:
        raise NotImplementedError(f'未知操作: {args.OPERATION}')

    # 根据是否使用V2算法创建相应的加密解密对象
    if args.v2:
        cipher = SecureCRTCryptoV2() if args.passphrase is None else SecureCRTCryptoV2(args.passphrase)
        # 执行加密或解密操作并打印结果
        print(getattr(cipher, operation)(args.PASSWORD, prefix = args.prefix))
    else:
        cipher = SecureCRTCrypto()
        # 执行加密或解密操作并打印结果
        print(getattr(cipher, operation)(args.PASSWORD))
