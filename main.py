import re
import glob
import time
import json
import subprocess
import logging
from pathlib import Path
from utils import *

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
        self.script_path = script_path
        self.dockerfiles_path = dockerfiles_path
        self.config = self.load_config(self.config_file)
        #server中的配置
        self.server_config_file = '/etc/trojan/server.json'

        

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
    
    @staticmethod
    def run_cmd(cmd: str, timeout = 20, working_dir = None, show_output = False):
        """
        执行指定的 shell 命令，并根据参数决定是否捕获或直接显示输出。
        
        参数:
        - cmd (str): 要执行的命令。
        - timeout (int): 命令执行的超时时间（秒）。默认为 20 秒。
        - working_dir (str): 命令的工作目录。如果未指定，则使用当前目录。
        - show_output (bool): 是否在终端直接显示命令的输出。默认为 False，即捕获输出。
        
        返回:
        - str: 如果 show_output 为 False，则返回命令的标准输出。否则返回 None。
        
        异常:
        - RuntimeError: 如果命令执行失败，抛出异常。
        """
        if show_output:
            p = subprocess.Popen(cmd, shell=True, cwd=working_dir)
        else:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, encoding='utf-8', cwd=working_dir)
        time_start = time.time()
        try:
            p.wait(timeout)
        except subprocess.TimeoutExpired:
            logging.warning('命令执行超时...')
            p.kill()
            raise
        time_end = time.time()

        if not show_output:
            stdout, stderr = p.communicate()
            return_code = p.returncode
            if return_code != 0:
                error_msg = f"""
                    RETURN CODE : {return_code}
                    COMMAND     : {cmd}
                    RUN TIME    : {time_end - time_start}
                    DETAIL      : {p.stderr.read()}
                """
                logging.warning('命令执行出错...')
                logging.error(f'error_msg')
                raise RuntimeError(error_msg)
            return stdout.strip()
        
            
    
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
        cmd = f'docker run -dit --privileged --init --net=bridge \
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
        
        # 读取 config.json
        with open(self.config_file, 'r') as file:
            config = json.load(file)

        # 读取 server.json 的默认配置
        with open(server_json_path, 'r') as file:
            server_config = json.load(file)

        # 根据 config.json 更新 server.json
        trojan_config = config.get('trojan_config', {})
        server_config['local_port'] = trojan_config.get('local_port', server_config['local_port'])
        server_config['remote_port'] = trojan_config.get('remote_port', server_config['remote_port'])
        server_config['password'] = trojan_config.get('password', server_config['password'])
        server_config['log_level'] = trojan_config.get('log_level', server_config['log_level'])

        if 'ssl' in trojan_config:
            # 获取 ssl 配置中的特定参数
            ssl_config = trojan_config['ssl']
            server_config['ssl']['cert'] = ssl_config.get('cert')
            server_config['ssl']['key'] = ssl_config.get('key')
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
        with open(self.config_file, 'r') as file:
            config = json.load(file)
        
        
        # 读取 config.json 中与nginx配置相关的参数
        server_listen_port = config["nginx_config"]["listen_port"]
        upstream_port = config["trojan_config"]["local_port"]

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
        #[step1] 提升所有shell脚本的权限
        logging.info('[step1] 提升所有shell脚本的权限...')
        self._grand_script_permission()
        #[step2] 根据config.json更改容器中nginx的监听端口与转发端口
        logging.info('[step2] 根据config.json更改容器中nginx的监听端口与转发端口...')
        self._update_nginx_config()
        #[step3] 创建trojan_server镜像
        logging.info('[step3] 创建trojan_server镜像...')
        self._build_docker_image()
        #[step4] 创建trojan_server容器并启动服务
        logging.info('[step4] 创建trojan_server容器并启动服务...')
        self._create_trojan_server()
        #[step5] 更新容器中的server.json以及nginx.conf文件
        logging.info('[step5] 更新容器中的server.json以及nginx.conf文件，重启trojan server...')
        self._update_server_config()
        self._restart_trojan_server()

if __name__ == "__main__":
    trojan_server = TrojanServer()
    trojan_server.auto_build_trojan_server()


