import json
import os
import shutil
import subprocess
import sys

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
        xlogging.WorkWithLogger.__init__(self, r'htb_logic', 66)

    def work_real(self):
        if self.logger_dir == "None":
            self.logger.warning(r'not logger dir')
            return

        src_path = os.path.join(current_dir, 'agentServiceCfg.txt')
        with open(src_path) as sp:
            source_content = json.load(sp)
        htb_task_uuid = source_content.get('htb_task_uuid', None)

        if htb_task_uuid and len(htb_task_uuid) == 32:
            self.modify_reg_add(htb_task_uuid)
            self.copy_and_remove_file()
            self.clean_ht_json()
        else:
            self.modify_reg_del()

    @staticmethod
    def modify_reg_del():
        pass

    def clean_ht_json(self):
        ht_json_path = os.path.join(os.path.dirname(self.logger_dir), 'ht.json')
        with open(ht_json_path, 'w') as f:
            f.write('')
        copy_by_reg.copy_file(ht_json_path, self.logger)

    def modify_reg_add(self, task_uuid):
        cmd = r"REG ADD HKLM\System\CurrentControlSet\servic" \
              r"es\disksbd\Parameters /v HotReadyTask /t REG_BINARY /d {} /f".format(task_uuid)
        info = _excute_cmd_and_return_code(cmd)
        if info[0] != 0:
            self.logger.warning(r'excute cmd:{},fail:{}'.format(cmd, info[1]))
            raise Exception(r'excute cmd:{},fail:{}'.format(cmd, info[1]))

        cmd1 = r"REG ADD HKLM\System\CurrentControlSet\services\sbdsys /v HotReady /t REG_DWORD /d 1 /f"
        info1 = _excute_cmd_and_return_code(cmd1)
        if info1[0] != 0:
            self.logger.warning(r'excute cmd:{},fail:{}'.format(cmd1, info[1]))
            raise Exception(r'excute cmd:{},fail:{}'.format(cmd1, info[1]))

    def copy_and_remove_file(self):
        file_names = ['hotreadyvol.bin', 'hotreadyvol_ntfs.bin']
        win_dir = os.environ['WINDIR']
        for file_name in file_names:
            src = os.path.join(win_dir, file_name)
            dst = os.path.join(self.logger_dir, file_name)
            self._copy_and_remove_file(src, dst)

    @staticmethod
    def _copy_and_remove_file(src, dst):
        if os.path.exists(src):
            shutil.copyfile(src, dst)
            os.remove(dst)


if __name__ == "__main__":
    r = Runner()
    r.work()
