import logging
import subprocess

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone

class ColoredFormatter(logging.Formatter):
    """
    一个自定义日志格式器，用于给不同级别的日志添加颜色。
    根据日志的严重性，分别以不同的颜色高亮显示日志消息。
    """
    # ANSI 颜色代码
    grey = "\x1b[38;21m"
    green = "\x1b[32;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: green + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.format)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
    
class GeneratePrivateKey():
    """
    这个类提供了生成自签名证书和私钥的方法。
    通过generate_cert_and_key方法，可以自动创建自签名的证书和对应的私钥文件。
    """

    @staticmethod
    def generate_cert_and_key(cert_path, key_path, valid_time = 10, public_exponent=65537, key_size=2048, name_oid = {
            "COUNTRY_NAME": u"US",
            "STATE_OR_PROVINCE_NAME": u"California",
            "LOCALITY_NAME": u"San Francisco",
            "ORGANIZATION_NAME": u"My Organization",
            "COMMON_NAME": u"mydomain.com"
        }):
        """
        自动生成密钥和自签名证书文件，并将它们保存到指定路径。

        参数:
        - cert_path (str): 证书文件的保存路径。
        - key_path (str): 私钥文件的保存路径。
        - valid_time (int): 证书的有效期（天），默认为10天。
        - public_exponent (int): RSA公钥指数，通常是65537。
        - key_size (int): RSA密钥的大小，推荐至少2048位。
        - name_oid (dict): 证书主题的各个字段，包括国家名、省/州名、地名、组织名和通用名。
        
        此函数不返回任何值，但会在指定路径生成证书和私钥文件，并记录相关日志信息。
        """
        logging.info('自动生成密钥与证书文件')
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Generate a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, name_oid["COUNTRY_NAME"]),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, name_oid["STATE_OR_PROVINCE_NAME"]),
            x509.NameAttribute(NameOID.LOCALITY_NAME, name_oid["LOCALITY_NAME"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, name_oid["ORGANIZATION_NAME"]),
            x509.NameAttribute(NameOID.COMMON_NAME, name_oid["COMMON_NAME"]),
        ])
        
        start_date  = datetime.now(timezone.utc) - timedelta(days=1)
        end_date  = datetime.now(timezone.utc) + timedelta(days=valid_time)
        
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            start_date
        ).not_valid_after(
            end_date 
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
            # Sign our certificate with our private key
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Write our certificate out to disk.
        with open(cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        # Write our private key out to disk.
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        logging.info(f"证书生成于 {cert_path}，密钥生成于 {key_path}。")

def run_cmd(cmd, timeout=20, working_dir=None, show_output=False, input=None):
    """
    执行指定的 shell 命令，并根据参数决定是否捕获或直接显示输出。
    
    参数:
    - cmd (str): 要执行的命令。
    - timeout (int): 命令执行的超时时间（秒）。默认为 20 秒。
    - working_dir (str): 命令的工作目录。如果未指定，则使用当前目录。
    - show_output (bool): 是否在终端直接显示命令的输出。默认为 False，即捕获输出。
    - input (str): 如果提供，则传递到命令的标准输入。
    
    返回:
    - str: 如果 show_output 为 False，则返回命令的标准输出。否则返回 None。
    
    异常:
    - RuntimeError: 如果命令执行失败，抛出异常。
    """
    if show_output:
        # 当需要显示输出时，不重定向 stdout 和 stderr
        process = subprocess.Popen(cmd, shell=True, cwd=working_dir,
                                   stdin=subprocess.PIPE, encoding='utf-8')
    else:
        process = subprocess.Popen(cmd, shell=True, cwd=working_dir,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, encoding='utf-8')
    try:
        stdout, stderr = process.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        raise RuntimeError("命令执行超时")

    if not show_output:
        if process.returncode != 0:
            raise RuntimeError(stderr.strip() or "命令执行出错，但没有提供错误输出。")
        return stdout.strip()
