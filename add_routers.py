import os
import sys
import json
import subprocess
import re

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)
ip_comiple = re.compile(r'(\d+\.){3}(\d+)')

import xlogging


def _excute_cmd_and_return_code(cmd):
    with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True) as p:
        stdout, stderr = p.communicate()
    return p.returncode, (stdout or stderr)


def route_filter(line):
    s1 = ip_comiple.match(line.strip())  # 是IP
    s2 = len(re.split('\s+', line.strip())) == 4  # 永久路由
    return s1 and s2


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'add_routers.py', 79)
        self.routers = []

    def work_real(self):
        if self.logger_dir == "None":
            self.logger.warning(r'not logger dir')
            return

        self.logger.info(r'will add_routers')
        src_path = os.path.join(current_dir, 'agentServiceCfg.txt')
        self.logger.debug(src_path)
        with open(src_path, 'r') as sp:
            source_content = json.load(sp)
        if source_content['routers']['is_save'] == 1: #保留路由 不做任何事
            return None
        self.get_current_routes()
        if self.routers:
            self.truncate_routes()
        self.add_route(source_content['routers']['router_list'])

    # 添加永久路由
    def add_route(self, routers):
        for router in routers:
            try:
                cmd = "route add {ip} mask {mask} {gateway} -p".format(ip=router['route_ip'],
                                                                       mask=router['route_mask'],
                                                                       gateway=router['route_gateway'])

                self.logger.info("_excute_cmd_and_return_code {cmd}".format(cmd=cmd))
                code, content = _excute_cmd_and_return_code(cmd)
                self.logger.info(r'exe cmd return code:{code},msg:{msg}'.format(code=code, msg=content))
            except Exception as e:
                self.logger.error(r'add_route error:{}'.format(e))

    # 获取永久路由信息
    def get_current_routes(self):
        code, content = _excute_cmd_and_return_code('route print')
        lines = content.split('\n')
        routers = list(filter(route_filter, lines))
        routers = list(map(lambda x: re.split('\s+', x.strip()), routers))
        self.routers = routers

    # 清除永久路由(非默认网关)
    def truncate_routes(self):
        for route in self.routers:
            if route[0] == '0.0.0.0':
                continue
            cmd = "route delete {ip}".format(ip=route[0])
            self.logger.info("_excute_cmd_and_return_code {cmd}".format(cmd=cmd))
            code, content = _excute_cmd_and_return_code(cmd)
            self.logger.info(r'exe cmd return code:{code},msg:{msg}'.format(code=code, msg=content))

if __name__ == "__main__":
    r = Runner()
    r.work()
