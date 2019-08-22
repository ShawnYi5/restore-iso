import os
import sys
import json
import configparser
import time

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging
import copy_by_reg


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'modify AgentService.ini', 77)

    def work_real(self):
        if self.logger_dir == "None":
            self.logger.warning(r'not logger dir')
            return

        self.logger.info(r'will modify AgentService.ini')
        src_path = os.path.join(current_dir, 'agentServiceCfg.txt')
        self.logger.debug(src_path)
        dest_path = os.path.join(os.path.dirname(self.logger_dir), 'AgentService.ini')
        self.logger.debug(dest_path)
        with open(src_path, 'r') as sp:
            source_content = json.load(sp)
        if not source_content['user_info']:
            return None

        self.modify_init(source_content, dest_path)

        copy_by_reg.copy_file(dest_path, self.logger)

    @staticmethod
    def modify_init(source_content, path):
        us_info = source_content['user_info'].split('|')
        config = configparser.ConfigParser()
        config.read_file(open(path, 'rt'))
        config.has_section('client') or config.add_section('client')
        config.set('client', 'userid', us_info[0])
        config.set('client', 'username', us_info[1])
        config.set('client', 'timestamp', str(time.time()))
        if source_content['aio_ip'] == '127.0.0.1':
            tunnel_ip = source_content['tunnel_ip']
            tunnel_port = source_content['tunnel_port']
            config.has_section('tunnel') or config.add_section('tunnel')
            config.set('tunnel', 'tunnelIP', tunnel_ip)
            config.set('tunnel', 'tunnelPort', tunnel_port)
            config.set('tunnel', 'proxy_listen', '20010|20011|20002|20003')
        else:
            config.remove_section('tunnel')

        config.has_section('restore') or config.add_section('restore')
        if source_content.get('restore_target', ''):
            config.set('restore', 'restore_target', source_content['restore_target'])
        else:
            pass
        if source_content.get('htb_task_uuid', ''):
            config.set('restore', 'htb_task_uuid', source_content['htb_task_uuid'])
        else:
            pass

        config.write(open(path, 'wt'))


if __name__ == "__main__":
    r = Runner()
    r.work()
