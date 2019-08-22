import configparser
import itertools
import json
import os
import subprocess
import sys
import shutil

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging
import copy_by_reg


def _excute_cmd_and_return_code(cmd):
    with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True) as p:
        stdout, stderr = p.communicate()
    return p.returncode, (stdout or stderr)


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'modify AgentService.cfg', 78)

    def work_real(self):
        if self.logger_dir == "None":
            self.logger.warning(r'not logger dir')
            return

        self.logger.info(r'will modify AgentService.config')
        src_path = os.path.join(current_dir, 'agentServiceCfg.txt')
        self.logger.debug(src_path)
        dest_path = os.path.join(os.path.dirname(self.logger_dir), 'AgentService.config')
        self.logger.debug(dest_path)
        with open(src_path, 'r') as sp:
            source_content = json.load(sp)

        self.modify_cfg(source_content['aio_ip'], dest_path)

        self.del_tunnel_mod()

        self.add_tunnel(source_content['aio_ip'], source_content['tunnel_ip'], source_content['tunnel_port'])

        copy_by_reg.copy_file(dest_path, self.logger)

        self.copy_non_master_nics_configs_file_from_iso_to_agent_dir()

    def copy_non_master_nics_configs_file_from_iso_to_agent_dir(self):
        iso_nics_file = os.path.join(current_dir, 'ht.json')
        agent_nics_file = os.path.join(os.path.dirname(self.logger_dir), 'ht.json')
        self.logger.info('will copy {} to {}'.format(iso_nics_file, agent_nics_file))
        try:
            shutil.copyfile(iso_nics_file, agent_nics_file)
        except Exception as e:
            self.logger.error('copy_non_master_nics_configs_file_to_agent_dir failed {}'.format(e))

    @staticmethod
    def modify_cfg(ip, path):
        config = configparser.ConfigParser()
        config.optionxform = str
        config.read_file(itertools.chain(['[fake_name] \n'], open(path, 'rt')))
        config.set('fake_name', 'Ice.Default.Host', ip)
        config.set('fake_name', 'SessionFactory.Proxy', 'agent:ssl -p 20011 -t 30000')
        config.set('fake_name', 'SessionFactoryTcp.Proxy', 'agent:tcp -p 20010 -t 30000')
        with open(path, 'w') as p1:
            for key, value in config.items('fake_name'):
                if ip != '127.0.0.1' and key in ('SessionFactory.Proxy', 'SessionFactoryTcp.Proxy'):
                    continue
                p1.write('{} = {}\n'.format(key, value))

    def del_tunnel_mod(self):
        cmd = r'"{}" proxy_del'.format(os.path.join(os.path.dirname(self.logger_dir), 'install_disksbd.exe'))
        info = _excute_cmd_and_return_code(cmd)
        if info[0] != 0:
            self.logger.warning(r'del_tunnel_mod fail:{}'.format(info[1]))

    def add_tunnel(self, aio_ip, tunnel_ip, tunnel_port):
        if aio_ip == "127.0.0.1":
            cmd = r'"{exec}" net {t_ip} {t_port} 20010^|20011^|20002^|20003'.format(
                exec=os.path.join(os.path.dirname(self.logger_dir), 'install_disksbd.exe'),
                t_ip=tunnel_ip, t_port=tunnel_port)
            info = _excute_cmd_and_return_code(cmd)
            if info[0] != 0:
                self.logger.warning(r'add_tunnel fail:{}'.format(info[1]))
        else:
            return None


if __name__ == "__main__":
    r = Runner()
    r.work()
