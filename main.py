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
        self.docker_file = f'{dockerfiles_path}/Dockerfile.trojan_server'
        self.config_file = f'{cur_path}/config.json'
        self.image_name = 'trojan_server'
        self.image_tag = 'v1'
        self.content_path = content_path
        self.script_path = script_path
        self.dockerfiles_path = dockerfiles_path
        self.config = self.load_config(self.config_file)

        

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
            if p.returncode != 0:
                error_msg = f"""
                    RETURN CODE : {return_code}
                    COMMAND     : {cmd}
                    RUN TIME    : {time_end - time_start}
                    DETAIL      : {p.stderr.read()}
                """
                raise RuntimeError(error_msg)
            return stdout.strip()
        
            
    
    def grand_script_permission(self):
        """
        提升所有script文件中的shell脚本的权限。
        Grand all shell script with execute permission.
        """
        sh_script = glob.glob(f'{script_path}/*.sh')
        for script in sh_script:
            self.run_cmd(f'chmod +x {script}')
    
    def build_docker_image(self):
        cmd = f'docker build -f {self.docker_file} -t {self.image_name}:{self.image_tag} {self.content_path}'
        self.run_cmd(cmd, working_dir=self.dockerfiles_path, show_output=True)

    def auto_build_trojan_server(self):
        """
        自动建立trojan服务器虚拟容器并开启服务。
        Auto build up trojan server docker container and initiate service.
        """
        #[step1] 提升所有shell脚本的权限
        self.grand_script_permission()
        #[step2] 将config.json复制到content文件中，使容器可以读取配置对server.json进行更改
        self.run_cmd(f'cp {self.config_file} {content_path}')
        #[step3] 创建trojan_server镜像
        # self.run_cmd(f'{self.script_path}/build_image.sh')
        self.build_docker_image()
        #[step4] 创建trojan_server容器并启动服务
        self.run_cmd(f'{self.script_path}/create_server.sh')


    

if __name__ == "__main__":
    trojan_server = TrojanServer()
    trojan_server.auto_build_trojan_server()


