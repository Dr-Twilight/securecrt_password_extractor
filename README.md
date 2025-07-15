# SecureCRT密码提取工具
## 项目简介
SecureCRT密码提取工具是一个用于解密和提取SecureCRT会话文件中存储的密码的Python工具集，支持V1和V2版本的加密密码格式。

## 项目结构
```
SecureCRT-encrypt-password/
├── README.md                   # 项目说明文档
├── requirements.txt            # 依赖包列表
├── securecrt_cipher.py         # 核心加密解密算法实现
├── securecrt_password_extractor.py      # 批量密码提取脚本
├── securecrt_passwords.csv     # 提取结果输出文件
└── Sessions/                   # SecureCRT会话文件目录
    └── ...                     # 会话子目录和.ini文件
```
## 功能特点
- 支持SecureCRT V1和V2两种密码加密格式
- 批量扫描并提取Sessions目录下所有会话的密码信息
- 自动识别文件编码（UTF-16/UTF-8）
- 提取结果保存为CSV格式，包含目录层级、文件名、用户名、明文密码和密码版本
- 兼容处理无密码或无用户名的会话文件
## 安装说明
### 环境要求
- Python 3.6 及以上版本
- 依赖库：pycryptodome
### 安装步骤
1. 克隆或下载本项目到本地
2. 安装依赖包
```
pip install -r requirements.txt
```
## 使用方法

### 1. securecrt_password_extractor.py（批量密码提取工具） 功能说明
批量扫描Sessions目录下的所有会话文件，提取用户名和加密密码，并自动解密后生成CSV报告。
 使用步骤
1. 将SecureCRT的会话目录（通常包含多个.ini文件）复制到项目根目录下，文件夹名称为 Sessions
2. 运行提取脚本：
```
python securecrt_password_extractor.py
```
3. 根据提示输入CRT配置密码（若无则直接回车）
4. 提取完成后，结果将保存到 securecrt_passwords.csv 文件 CSV输出格式:
   
  | 目录层级 | 文件名 | 用户名 | 明文密码 | 密码版本 |
  |----------|--------|--------|----------|----------|
  | root     | server1.ini | admin | password123 | V2 |
  | db/mysql | dbserver.ini | root | dbpass456 | V1 |


### 2. securecrt_cipher.py（密码加解密工具）
## SecureCRT加密密码解密工具可 单独使用
## 来源于大佬项目:https://github.com/HyperSine/how-does-navicat-encrypt-password

## 1. 工作原理

[SecureCRT密码加密原理](doc/how-does-SecureCRT-encrypt-password.md)

注意：SecureCRT 9.4+版本的内容有待更新

## 2. 使用方法

请确保已安装Python3和`pycryptodome`模块。

可通过以下命令安装所需模块：

```console
$ pip3 install pycryptodome
```

---

使用方法：

```console
$ ./securecrt_cipher.py -h
usage: securecrt_cipher.py [-h] {enc,dec} ...

位置参数：
  {enc,dec}
    enc       执行加密操作
    dec       执行解密操作

可选参数：
  -h, --help  显示此帮助消息并退出
```

```console
$ ./securecrt_cipher.py enc -h
usage: securecrt_cipher.py enc [-h] [-2] [--prefix {02,03}] [-p PASSPHRASE]
                               PASSWORD

位置参数：
  PASSWORD              要加密的明文密码

可选参数：
  -h, --help            显示此帮助消息并退出
  -2, --v2              使用"Password V2"算法进行加密/解密
  --prefix {02,03}      使用"Password V2"算法生成的加密密码前缀
  -p PASSPHRASE, --passphrase PASSPHRASE
                        SecureCRT使用的配置密码
```

```console
$ ./securecrt_cipher.py dec -h
usage: securecrt_cipher.py dec [-h] [-2] [--prefix {02,03}] [-p PASSPHRASE]
                               PASSWORD

位置参数：
  PASSWORD              要解密的加密密码

可选参数：
  -h, --help            显示此帮助消息并退出
  -2, --v2              使用"Password V2"算法进行加密/解密
  --prefix {02,03}      使用"Password V2"算法生成的加密密码前缀
  -p PASSPHRASE, --passphrase PASSPHRASE
                        SecureCRT使用的配置密码
```

## 3. 解密示例

如果你有一个SecureCRT会话文件 example.com.ini ，内容如下：

```
S:"Username"=root
S:"Password"=
S:"Password V2"=03:7f59810d05b03f8e49b96e091dad49cb474c2e8435a5dbe53fc5d1e7aa228a8df8938cb01a7dd0c72cc361595ef5c2b675d8b2a64663776b95b065fec9b0fc36f168ffe3ae6fdedc3e1897389609536f
S:"Login Script V2"=
...
```

你可以使用以下命令解密密码：

```console
$ ./securecrt_cipher.py dec -2 --prefix 03 7f59810d05b03f8e49b96e091dad49cb474c2e8435a5dbe53fc5d1e7aa228a8df8938cb01a7dd0c72cc361595ef5c2b675d8b2a64663776b95b065fec9b0fc36f168ffe3ae6fdedc3e1897389609536f
Hypersine
```

如果会话文件是由 SecureCRT 7.3.3 之前版本生成的，敏感数据应该是：

```
...
S:"Username"=root
D:"[SSH2] Port"=00000016
S:"Password"=uc71bd1c86f3b804e42432f53247c50d9287f410c7e59166969acab69daa6eaadbe15c0c54c0e076e945a6d82f9e13df2
D:"Session Password Saved"=00000001
...
```

你可以使用以下命令解密密码：

```console
$ ./securecrt_cipher.py dec c71bd1c86f3b804e42432f53247c50d9287f410c7e59166969acab69daa6eaadbe15c0c54c0e076e945a6d82f9e13df2
DoubleLabyrinth
```
## 注意事项
- 确保Sessions目录包含正确的SecureCRT会话文件
- 对于受配置密码保护的会话文件，需要正确输入配置密码才能解密
- 程序会自动处理不同编码格式的会话文件（UTF-16/UTF-8）
- 对于没有密码的会话文件，也会记录用户名信息
## 许可证
本项目采用MIT许可证 - 详见LICENSE文件

## 免责声明
本工具仅用于合法授权的测试和管理目的，请遵守相关法律法规，不得用于未经授权的访问。
