import re
import glob
import time
import subprocess
import json
from pathlib import Path

filepath = Path().resolve()
cur_path = filepath.cwd().as_posix()
dockerfiles_path = f'{cur_path}/dockerfiles'
content_path = f'{dockerfiles_path}/content'
script_path = f'{cur_path}/script'

class TrojanServer():
    """
    """
    
    def __init__(self):
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
        加载config.json文件中的配置。
        Load config.json.
        """
        with open(config_file, 'r') as file:
            return json.load(file)
    
    @staticmethod
    def run_cmd(cmd: str, timeout = 20, working_dir = None, show_output = False):
        """
        执行给定的命令并处理其输出。

        这个方法使用 subprocess.Popen 来异步执行一个 shell 命令，并根据需要捕获或直接显示其输出。这对于执行外部程序或脚本特别有用。

        参数:
        cmd (str): 需要执行的命令字符串。
        timeout (int, 可选): 命令执行的超时时间（秒）。默认为 20 秒。
        working_dir (str, 可选): 设置命令执行时的工作目录。如果未指定，默认为当前 Python 脚本的工作目录。
        show_output (bool, 可选): 是否直接在终端中显示命令的输出。默认为 False，即捕获输出并在执行失败时抛出异常。

        返回:
        str: 如果 show_output 为 False 且命令执行成功，返回命令的标准输出。否则不返回任何内容。

        异常:
        RuntimeError: 如果命令执行失败（即返回码不为 0），则抛出包含错误详情的异常。

        注意:
        - 当 show_output 为 True 时，命令的输出和错误将直接打印到终端，不会返回输出内容。
        - 若命令执行时间超过 timeout 指定的秒数，则会尝试终止命令并抛出 TimeoutExpired 异常。
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
                raise RuntimeError(error_msg)
            return stdout.strip()
        
            
    
    def _grand_script_permission(self):
        """
        提升所有script文件中的shell脚本的权限。
        Grand all shell script with execute permission.
        """
        sh_script = glob.glob(f'{script_path}/*.sh')
        for script in sh_script:
            self.run_cmd(f'chmod +x {script}')
    
    def _build_docker_image(self):
        self._remove_trojan_server()
        cmd = f'docker build -f {self.docker_file} -t {self.image_name}:{self.image_tag} {self.content_path}'
        self.run_cmd(cmd, timeout = None, working_dir=self.dockerfiles_path, show_output=True)
    
    def _remove_docker_image(self):
        self._remove_trojan_server()
        cmd = f'docker image rm {self.image_name}:{self.image_tag}'
        self.run_cmd(cmd, show_output=True)

    def _create_trojan_server(self):
        self._remove_trojan_server
        cmd = f'docker run -dit --privileged --init --net=bridge \
                -v /etc/localtime:/etc/localtime:ro -v /etc/timezone:/etc/timezone:ro \
                --name={self.container_name} --hostname={self.container_host_name} \
                {self.image_name}:{self.image_tag}'
        self.run_cmd(cmd, show_output=True)
    
    def _remove_trojan_server(self):
        cmd = f'docker rm -f {self.container_name}'
        self.run_cmd(cmd, show_output=True)
    
    def _restart_trojan_server(self):
        cmd = f'docker restart {self.container_name}'
        self.run_cmd(cmd, show_output=True)
    
    def _update_server_config(self):
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
        自动建立trojan服务器虚拟容器并开启服务。
        Auto build up trojan server docker container and initiate service.
        """
        #[step1] 提升所有shell脚本的权限
        self._grand_script_permission()
        #[step2] 根据config.json更改容器中nginx的监听端口与转发端口
        self._update_nginx_config()
        #[step3] 创建trojan_server镜像
        self._build_docker_image()
        #[step4] 创建trojan_server容器并启动服务
        self._create_trojan_server()
        #[step5] 更新容器中的server.json以及nginx.conf文件
        self._update_server_config()
        self._restart_trojan_server()
    


if __name__ == "__main__":
    trojan_server = TrojanServer()
    trojan_server.auto_build_trojan_server()


