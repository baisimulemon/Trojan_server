import os
import re
import glob
import json
import shutil
import subprocess
import logging
from pathlib import Path
from utils import ColoredFormatter, GeneratePrivateKey, run_cmd

filepath = Path().resolve()
cur_path = filepath.cwd().as_posix()
dockerfiles_path = f'{cur_path}/dockerfiles'
content_path = f'{dockerfiles_path}/content'
script_path = f'{cur_path}/script'

# 配置根日志记录器
logger = logging.getLogger()
# 设置默认的日志级别
logger.setLevel(logging.INFO)  
# 创建一个 console 处理器并使用彩色格式化器
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColoredFormatter())
# 添加处理器到日志记录器
logger.addHandler(console_handler)

class TrojanServer():
    """
    TrojanServer 类用于自动构建、配置和管理 Trojan 服务器的 Docker 容器。
    它封装了从读取配置文件、创建 Docker 镜像、启动容器到配置 Nginx 和 Trojan 服务的一系列操作。
    """
    
    def __init__(self):
        """
        初始化 TrojanServer 实例。
        设置 Docker 镜像和容器的基本信息，读取配置文件，并定义了服务所需的配置文件路径。
        """
        #HOST上的配置
        self.docker_file = f'{dockerfiles_path}/Dockerfile.trojan_server'
        self.config_file = f'{cur_path}/config.json'
        self.image_name = 'trojan_server'
        self.container_name = 'trojan_server'
        self.container_host_name = 'trojan_server'
        self.image_tag = 'v1'
        self.content_path = content_path
        self.cert_path = f'{self.content_path}/certs'
        self.script_path = script_path
        self.dockerfiles_path = dockerfiles_path
        self.config = self.load_config(self.config_file)
        #server中的配置
        self.server_config_file = '/etc/trojan/server.json'
        #工具类函数
        self.run_cmd = run_cmd

    @staticmethod
    def load_config(config_file):
        """
        静态方法，用于从指定的 JSON 配置文件中加载配置。
        
        参数:
        - config_file (str): 配置文件的路径。
        
        返回:
        - dict: 配置文件中的内容。
        """
        with open(config_file, 'r') as file:
            return json.load(file)
    
    # @staticmethod
    # def run_cmd(cmd: str, timeout = 20, working_dir = None, show_output = False):
    #     """
    #     执行指定的 shell 命令，并根据参数决定是否捕获或直接显示输出。
        
    #     参数:
    #     - cmd (str): 要执行的命令。
    #     - timeout (int): 命令执行的超时时间（秒）。默认为 20 秒。
    #     - working_dir (str): 命令的工作目录。如果未指定，则使用当前目录。
    #     - show_output (bool): 是否在终端直接显示命令的输出。默认为 False，即捕获输出。
        
    #     返回:
    #     - str: 如果 show_output 为 False，则返回命令的标准输出。否则返回 None。
        
    #     异常:
    #     - RuntimeError: 如果命令执行失败，抛出异常。
    #     """
    #     if show_output:
    #         p = subprocess.Popen(cmd, shell=True, cwd=working_dir)
    #     else:
    #         p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
    #                         stderr=subprocess.PIPE, encoding='utf-8', cwd=working_dir)
    #     time_start = time.time()
    #     try:
    #         p.wait(timeout)
    #     except subprocess.TimeoutExpired:
    #         logging.warning('命令执行超时...')
    #         p.kill()
    #         raise
    #     time_end = time.time()

    #     if not show_output:
    #         stdout, stderr = p.communicate()
    #         return_code = p.returncode
    #         if return_code != 0:
    #             error_msg = f"""
    #                 RETURN CODE : {return_code}
    #                 COMMAND     : {cmd}
    #                 RUN TIME    : {time_end - time_start}
    #                 DETAIL      : {p.stderr.read()}
    #             """
    #             logging.warning('命令执行出错...')
    #             logging.error(f'error_msg')
    #             raise RuntimeError(error_msg)
    #         return stdout.strip()
        
    def _ensure_ssl_certs(self):
        """
        确保 SSL 证书和密钥被正确配置。从配置文件获取路径，复制到正确的目录，
        或者在路径不存在时自动生成它们。
        """
        ssl_config = self.config.get('trojan_config', {}).get('ssl', {})
        cert_src_path = ssl_config.get('cert')
        key_src_path = ssl_config.get('key')

        # 创建 certs 目录，如果它不存在的话
        os.makedirs(self.cert_path, exist_ok=True)

        if cert_src_path and key_src_path:
            # 如果路径存在，则复制和重命名证书和密钥
            self._copy_and_rename_certs(cert_src_path, key_src_path)
        else:
            # 如果路径不存在，则生成新的证书和密钥
            logging.warning('证书或密钥的路径不存在，在指定目录中自动生成。')
            self._generate_ssl_certs_if_needed()

    def _copy_and_rename_certs(self, cert_src_path, key_src_path):
        """
        将给定路径的证书和密钥文件复制到 Docker 内容目录的证书子目录，并重命名它们。
        """
        try:
            shutil.copy(cert_src_path, os.path.join(self.cert_path, 'cert.pem'))
            shutil.copy(key_src_path, os.path.join(self.cert_path, 'cert.key'))
            logging.info('证书和密钥已复制和重命名。')
        except Exception as e:
            logging.error(f'复制证书和密钥时出现错误: {e}')
            logging.info('尝试自动生成证书和密钥。')
            self._generate_ssl_certs_if_needed()

    def _generate_ssl_certs_if_needed(self):
        """
        生成 SSL 证书和密钥文件，并将它们保存到 Docker 内容目录的证书子目录。
        """
        generator = GeneratePrivateKey()
        generator.generate_cert_and_key(
            os.path.join(self.cert_path, 'cert.pem'), 
            os.path.join(self.cert_path, 'cert.key')
        )

    def _grand_script_permission(self):
        """
        提升 script 文件夹内所有 shell 脚本的执行权限。
        通过对文件夹内的每个 .sh 文件执行 'chmod +x' 命令来实现。
        """
        sh_script = glob.glob(f'{script_path}/*.sh')
        logging.info(f'{sh_script} 将会提升可执行权限...')
        for script in sh_script:
            self.run_cmd(f'chmod +x {script}')
    
    def _build_docker_image(self):
        """
        构建 Docker 镜像。
        使用 Dockerfile 和相关的配置文件创建 Trojan 服务器的 Docker 镜像。
        """
        self._remove_trojan_server()
        logging.info(f'开始建立trojan server镜像...')
        cmd = f'docker build -f {self.docker_file} -t {self.image_name}:{self.image_tag} {self.content_path}'
        self.run_cmd(cmd, timeout = None, working_dir=self.dockerfiles_path, show_output=True)
        logging.info(f'trojan server镜像建立完毕...')
    
    def _remove_docker_image(self):
        """
        删除已有的 Docker 镜像。
        使用 'docker image rm' 命令来移除指定的 Trojan 服务器 Docker 镜像。
        """
        self._remove_trojan_server()
        logging.info(f'开始移除trojan server镜像...')
        cmd = f'docker image rm {self.image_name}:{self.image_tag}'
        self.run_cmd(cmd, show_output=True)
        logging.info(f'trojan server镜像移除完毕...')

    def _create_trojan_server(self):
        """
        创建并启动 Trojan 服务器的 Docker 容器。
        使用 'docker run' 命令来基于已构建的镜像启动容器，并设置必要的网络和卷挂载选项。
        """
        self._remove_trojan_server
        logging.info(f'开始启动trojan server容器...')
        map_port = self.config['nginx_config']['listen_port']
        cmd = f'docker run -dit --privileged --init --net=bridge -p {map_port}:{map_port}\
                -v /etc/localtime:/etc/localtime:ro -v /etc/timezone:/etc/timezone:ro \
                --name={self.container_name} --hostname={self.container_host_name} \
                {self.image_name}:{self.image_tag}'
        self.run_cmd(cmd, show_output=True)
        logging.info(f'trojan server容器已启动...')
    
    def _remove_trojan_server(self):
        """
        停止并移除已有的 Trojan 服务器容器。
        使用 'docker rm -f' 命令来强制移除指定的容器，确保启动新容器前旧容器不会产生冲突。
        """
        logging.info(f'开始移除trojan server容器...')
        cmd = f'docker rm -f {self.container_name}'
        self.run_cmd(cmd, show_output=True)
        logging.info(f'trojan server容器已移除...')
    
    def _restart_trojan_server(self):
        """
        重启 Trojan 服务器的 Docker 容器。
        使用 'docker restart' 命令来重启指定的容器，使配置更改生效。
        """
        logging.info(f'重启trojan server容器...')
        cmd = f'docker restart {self.container_name}'
        self.run_cmd(cmd, show_output=True)
        logging.info(f'trojan server容器重启完毕...')
    
    def _update_server_config(self):
        """
        从 config.json 更新并应用配置到容器中的 server.json 文件。
        首先将容器中的 server.json 文件复制到宿主机进行修改，然后再复制回容器内。
        通过读取 config.json 中的配置，更新 server.json 中的特定字段，包括端口、密码等信息。
        """
        # 从容器中取出 server.json 
        server_json_path = f'{self.content_path}/server.json'
        cmd1 = f'docker cp {self.container_name}:{self.server_config_file} {server_json_path}'
        self.run_cmd(cmd1, show_output=True)

        # 读取 server.json 的默认配置
        server_config = self.load_config(server_json_path)

        # 根据 config.json 更新 server.json
        trojan_config = self.config.get('trojan_config', {})
        server_config['local_port'] = trojan_config.get('local_port', server_config['local_port'])
        server_config['remote_port'] = trojan_config.get('remote_port', server_config['remote_port'])
        server_config['password'] = trojan_config.get('password', server_config['password'])
        server_config['log_level'] = trojan_config.get('log_level', server_config['log_level'])
        server_config['ssl']['cert'] = "/etc/trojan/certs/cert.pem"
        server_config['ssl']['key'] = "/etc/trojan/certs/cert.key"

        if 'ssl' in trojan_config:
            # 获取 ssl 配置中的特定参数
            ssl_config = trojan_config['ssl']
            server_config['ssl']['key_password'] = ssl_config.get('key_password')
            server_config['ssl']['session_timeout'] = ssl_config.get('session_timeout')
        
        # 写回更新后的 server.json
        with open(server_json_path, 'w') as file:
            json.dump(server_config, file, indent=4)
        
        # 将 server.json放回容器中
        cmd2 = f'docker cp {server_json_path} {self.container_name}:{self.server_config_file}'
        self.run_cmd(cmd2, show_output=True)
        
        # 清理 server.json
        cmd3 = f'rm {server_json_path}'
        self.run_cmd(cmd3, show_output=True)

    def _update_nginx_config(self):
        """
        根据 config.json 中的配置更新 nginx 配置文件。
        读取 config.json 中的 nginx 相关配置，并更新宿主机上的 nginx.conf 文件中的监听端口和上游服务器端口。
        使用正则表达式来查找并替换配置文件中的相关端口设置。
        """
        nginx_conf_path = f'{self.content_path}/nginx.conf'
        # 读取 config.json
        
        # 读取 config.json 中与nginx配置相关的参数
        server_listen_port = self.config["nginx_config"]["listen_port"]
        upstream_port = self.config["trojan_config"]["local_port"]

        # 读取 nginx.conf 文件
        with open(nginx_conf_path, 'r') as file:
            lines = file.readlines()

        # 准备正则表达式模式
        upstream_pattern = re.compile(r'(server\s+127\.0\.0\.1:)\d+;')
        server_listen_pattern = re.compile(r'(listen\s+0\.0\.0\.0:)\d+;')

        # 更新端口号
        with open(nginx_conf_path, 'w') as file:
            for line in lines:
                # 更新 upstream 中的端口号
                if upstream_pattern.search(line):
                    line = upstream_pattern.sub(r'\g<1>{};'.format(upstream_port), line)
                # 更新 server 块中的监听端口
                elif server_listen_pattern.search(line):
                    line = server_listen_pattern.sub(r'\g<1>{};'.format(server_listen_port), line)
                file.write(line)

    def auto_build_trojan_server(self):
        """
        自动化流程以构建、配置和启动 Trojan 服务器容器。
        此方法依次执行权限提升、配置更新、Docker 镜像构建、容器创建与启动，并应用最终的服务配置。
        包括 Nginx 和 Trojan 服务的配置更新，以及必要时重启容器以应用配置更改。
        """
        logging.info("开始自动构建 Trojan 服务器...")
        try:
            #[step1] 提升所有shell脚本的权限
            logging.info('[step1] 提升所有shell脚本的权限...')
            self._grand_script_permission()
            #[step2] 准备好构建镜像需要的SSL认证文件与nginx.conf文件
            logging.info('[step2] 准备好构建镜像需要的SSL认证文件与nginx.conf文件...')
            self._ensure_ssl_certs()
            self._update_nginx_config()
            #[step3] 创建trojan_server镜像
            logging.info('[step3] 创建trojan_server镜像...')
            self._build_docker_image()
            #[step4] 创建trojan_server容器并启动服务
            logging.info('[step4] 创建trojan_server容器并启动服务...')
            self._create_trojan_server()
            #[step5] 更新容器中的server.json以及nginx.conf文件
            logging.info('[step5] 更新容器中的server.json文件，重启trojan server...')
            self._update_server_config()
            self._restart_trojan_server()
        except Exception as e:
            logging.error(f"自动构建 Trojan 服务器过程中出现错误: {e}")

class DockerSetup():
    def __init__(self):
        self.config_file = f'{cur_path}/config.json'
        self.config = self._load_config(self.config_file)
        self.host_config = self.config.get("host_config", {})
        self.user = self.host_config.get("user")
        self.password = self.host_config.get("password")
        self.run_cmd = run_cmd

    @staticmethod
    def _load_config(config_path):
        with open(config_path, 'r') as file:
            return json.load(file)

    def verify_password(self):
        if self.user == 'root':
            logging.warning("不建议使用 root 用户执行，请切换为普通用户后重试")
            return False

        if self.password:
            return self._check_password(self.password)

        # 如果密码不存在，提示用户输入
        return self._prompt_for_password()

    def _check_password(self, password):
        cmd = 'sudo -k -S ls'
        try:
            self.run_cmd(cmd, input=password, show_output=False)
            logging.info("密码验证成功")
            return True
        except RuntimeError as e:
            logging.error(f"密码验证失败: {e}")
            return False

    def _prompt_for_password(self):
        try:
            self.password = input("请输入 {} 的密码: ".format(self.user))
            return self._check_password(self.password)
        except TimeoutError:
            logging.warning("输入超时, 请重试")
            return False

    def check_and_install_docker(self):
        logging.info("检查 docker 是否已安装 ...")
        docker_installed = self._check_docker_installed()

        if not docker_installed:
            self._install_docker()
        
        self._ensure_user_in_docker_group()

    def _check_docker_installed(self):
        if shutil.which('docker') is None:
            logging.warning('Docker 不在系统路径中，需要安装。')
            return False
        
        try:
            result = self.run_cmd('docker version', show_output=False)
            if 'Client:' in result and 'Server:' in result:
                logging.info("Docker 已正确安装")
                return True
            else:
                logging.warning("未正确安装或未安装 Docker，将尝试重新安装")
                return False
        except RuntimeError as e:
            logging.error(f"检查 Docker 版本时出错: {e}")
            return False

    def _install_docker(self):
        logging.info("安装依赖: apt-transport-https、ca-certificates、curl、gnupg2、software-properties-common")
        dependencies = 'apt-transport-https ca-certificates curl gnupg2 software-properties-common'
        self.run_cmd(f'echo {self.password} | sudo -S apt-get install -y {dependencies}', show_output=True, timeout=None)

        logging.info("配置信任Docker的GPG公钥")
        self.run_cmd(f'echo {self.password} | sudo -S curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -', show_output=True, timeout=60)

        logging.info("增加Docker官方APT源")
        add_apt_repository_command = (
            f"echo {self.password} | sudo -S add-apt-repository "
            f"\"deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable\""
        )
        self.run_cmd(add_apt_repository_command, show_output=True, timeout=60)

        logging.info("更新APT包索引")
        self.run_cmd(f'echo {self.password} | sudo -S apt-get update -y', show_output=True, timeout=None)

        logging.info("安装 docker-ce")
        self.run_cmd(f'echo {self.password} | sudo -S apt-get install -y docker-ce', show_output=True, timeout=None)

        logging.info("Docker 安装完成")
    
    def _ensure_user_in_docker_group(self):
        """
        检测当前用户是否在 docker 用户组中，如果不是，则自动将用户添加到该组。
        """
        logging.info(f"检查用户 {self.user} 是否在 docker 组中...")
        
        # 检查当前用户是否属于 docker 组
        check_group_cmd = f'getent group docker | grep "\\b{self.user}\\b"'
        result = self.run_cmd(check_group_cmd, show_output=False)
        
        # 如果用户不在 docker 组中，将其添加到该组
        if not result:
            logging.info(f"用户 {self.user} 不在 docker 组中，正在尝试添加...")
            add_group_cmd = f'echo {self.password} | sudo -S usermod -aG docker {self.user}'
            try:
                self.run_cmd(add_group_cmd, show_output=True)
                logging.info(f"用户 {self.user} 已成功添加到 docker 组。你可能需要重新登录或重启以使组变更生效。")
            except RuntimeError as e:
                logging.error(f"尝试将用户 {self.user} 添加到 docker 组时出现错误: {e}")
        else:
            logging.info(f"用户 {self.user} 已经是 docker 组的成员。")

    def auto_check_and_install_docker(self):
        try:
            if self.verify_password():
                self.check_and_install_docker()
            else:
                logging.error("用户密码验证失败。")
                raise ValueError("用户密码验证失败。")
        except Exception as e:
            logging.error(f"检查或安装Docker过程中发生错误：{e}")
            raise
            
    
if __name__ == "__main__":
    docker_setup = DockerSetup()
    docker_setup.auto_check_and_install_docker()
    del docker_setup
    trojan_server = TrojanServer()
    trojan_server.auto_build_trojan_server()
    del trojan_server


