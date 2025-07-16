import os
import re
import csv
import sys
from securecrt_cipher import SecureCRTCrypto, SecureCRTCryptoV2


# ======================== 配置常量 ========================
CSV_HEADERS = ["目录层级", "文件名", "用户名", "明文密码", "密码版本"]
OUTPUT_CSV = 'securecrt_passwords.csv'


# ======================== 辅助函数 ========================
def extract_password_info(file_path):
    """从INI文件中提取密码信息和用户名

    Args:
        file_path (str): INI文件路径

    Returns:
        dict: 包含用户名、密码版本、前缀(如V2)和密文的字典，若未找到则返回None
    """
    # 正则表达式匹配V2和V1版本的密码模式以及用户名
    password_v2_pattern = re.compile(r'S:"Password V2"\s*=\s*(\w+):([0-9a-fA-F]+)')
    password_v1_pattern = re.compile(r'S:"Password"\s*=\s*u([0-9a-fA-F]+)')
    # 用户名正则表达式，限制只匹配当前行内容
    username_pattern = re.compile(r'S:"Username"\s*=\s*(.*?)\r?\n')  # 用户名匹配模式

    try:
        # 尝试使用UTF-16编码读取(SecureCRT默认编码)
        with open(file_path, 'r', encoding='utf-16') as f:
            content = f.read()
    except UnicodeDecodeError:
        # 解码失败时尝试UTF-8
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"读取文件失败 {file_path}: {e}")
            return None
    except Exception as e:
        print(f"读取文件失败 {file_path}: {e}")
        return None

    # 提取用户名
    username_match = username_pattern.search(content)
    username = username_match.group(1) if username_match else ""

    # 优先查找V2版本密码
    v2_match = password_v2_pattern.search(content)
    if v2_match:
        return {
            'version': 'V2',
            'prefix': v2_match.group(1),
            'ciphertext': v2_match.group(2),
            'username': username  # 添加用户名
        }

    # 查找V1版本密码
    v1_match = password_v1_pattern.search(content)
    if v1_match:
        return {
            'version': 'V1',
            'ciphertext': v1_match.group(1),
            'username': username  # 添加用户名
        }

    # 如果没有密码但有用户名，也返回用户名信息
    if username:
        return {
            'version': None,
            'ciphertext': None,
            'username': username
        }

    return None


def decrypt_password(password_info, config_passphrase):
    """使用相应版本的解密算法解密密码

    Args:
        password_info (dict): 包含密码版本和密文的字典
        config_passphrase (str): CRT配置密码

    Returns:
        str: 解密后的明文密码，若解密失败则返回错误信息
    """
    try:
        if password_info['version'] == 'V2':
            # V2版本解密，需要prefix参数和配置密码
            crypto = SecureCRTCryptoV2(config_passphrase)
            return crypto.decrypt(password_info['ciphertext'], prefix=password_info['prefix'])
        elif password_info['version'] == 'V1':
            # V1版本解密
            crypto = SecureCRTCrypto()
            return crypto.decrypt(password_info['ciphertext'])
    except Exception as e:
        return f"解密失败: {str(e)}"
    return None


# ======================== 主函数逻辑 ========================
def main():
    # 1. 获取配置密码
    print("请输入CRT配置密码（若无则直接回车）: ")
    config_passphrase = input().strip()
    print("密码输入完成，开始处理会话文件...\n")

    # 2. 配置Session目录路径 - 修改路径获取逻辑
    if getattr(sys, 'frozen', False):
        # 打包后的EXE模式
        SESSIONS_DIR = os.path.dirname(sys.executable)
    else:
        # 脚本模式
        SESSIONS_DIR = os.path.dirname(os.path.abspath(__file__))

    sessions_dir = os.path.join(SESSIONS_DIR, 'Sessions')
    print(f"使用Sessions目录: {sessions_dir}")

    # 3. 验证目录是否存在
    if not os.path.isdir(sessions_dir):
        print(f"错误: 目录 '{sessions_dir}' 不存在，请检查路径是否正确。")
        return

    # 4. 初始化CSV文件
    record_count = 0
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(CSV_HEADERS)

        # 5. 遍历会话目录处理文件
        for root, dirs, files in os.walk(sessions_dir):
            for file in files:
                if file.endswith('.ini'):
                    # 5.1 计算目录层级 (a-b-c格式)
                    relative_path = os.path.relpath(root, sessions_dir)
                    dir_level = 'root' if relative_path == '.' else relative_path.replace(os.sep, '-')

                    # 5.2 提取密码信息
                    file_path = os.path.join(root, file)
                    password_info = extract_password_info(file_path)

                    # 5.3 处理密码解密和写入
                    if password_info:
                        decrypted_password = decrypt_password(password_info, config_passphrase) if password_info['ciphertext'] else ""
                        writer.writerow([
                            dir_level,
                            file,
                            password_info['username'],
                            decrypted_password,
                            password_info['version'] or ""
                        ])
                        record_count += 1

    # 6. 输出处理结果
    print(f"处理完成！共提取 {record_count} 条记录，结果已保存到 {OUTPUT_CSV}")


if __name__ == '__main__':
    main()
