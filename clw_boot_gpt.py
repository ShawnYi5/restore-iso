import os
import shutil
import subprocess
import sys

import win32api
import win32file

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging


class Runner(xlogging.WorkWithLogger):

    def _excute_cmd_and_return_code(self, cmd, wow64=True):
        save_64_value = None

        if wow64 and self.bIs64:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()

        try:
            with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  universal_newlines=True) as p:
                stdout, stderr = p.communicate()
            return p.returncode, (stdout or stderr)
        finally:
            if wow64 and self.bIs64:
                win32file.Wow64RevertWow64FsRedirection(save_64_value)

    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'clw_boot_gpt', 147)
        sys_info = win32api.GetNativeSystemInfo()
        if sys_info[0] == 0:  # 如果是32位系统 PROCESSOR_ARCHITECTURE_INTEL
            self.bIs64 = False
        else:
            self.bIs64 = True
        self.logger.info(r'bIs64 : {}'.format(self.bIs64))

    def work_real(self):
        boot_gpt_vol = self.fetch_boot_gpt_vol()
        if not boot_gpt_vol:
            self.logger.info(r'do NOT find gpt vol')
            return

        self.logger.info(r'find gpt vol : {}'.format(boot_gpt_vol))
        temp_dir = self.get_temp_dir()
        bcd_edit_path = self.get_bcd_edit_path()
        bcd_path = self.export_bcd(bcd_edit_path, temp_dir)
        self.fix_boot_bcd(bcd_edit_path, bcd_path)
        self.check_boot_bcd(bcd_edit_path, bcd_path)
        boot_bcd_path = self.copy_bcd(bcd_path, boot_gpt_vol)
        self.logger.info(r'boot_bcd_path : {}'.format(boot_bcd_path))

    @staticmethod
    def get_bcd_edit_path():
        system_dir = win32api.GetSystemDirectory()
        return os.path.join(system_dir, 'bcdedit')

    def fetch_boot_gpt_vol(self):
        cmd = 'ShowDisk.exe -bootvol'
        self.logger.info(r'will run {}'.format(cmd))
        pr = self._excute_cmd_and_return_code(cmd, False)
        self.logger.info(r'pr : {}'.format(pr))
        if pr[0] != 0 or not isinstance(pr[1], str) or not pr[1].startswith('success is 1'):
            return None

        boot_gpt_vol = (pr[1].split(':')[1]).strip()
        return boot_gpt_vol

    def get_temp_dir(self):
        result = os.path.join(self.logger_dir, 'clw_boot_gpt')
        if os.path.isdir(result):
            shutil.rmtree(result, True)
        os.makedirs(result, exist_ok=True)
        return result

    def export_bcd(self, bcd_edit_path, temp_dir):
        bcd_path = os.path.join(temp_dir, 'BCD')
        if os.path.isfile(bcd_path):
            os.remove(bcd_path)
        cmd = r'{} /export "{}"'.format(bcd_edit_path, bcd_path)
        self.logger.info(r'will run : {}'.format(cmd))
        rcode = self._excute_cmd_and_return_code(cmd)
        if os.path.isfile(bcd_path) and os.path.getsize(bcd_path) != 0:
            self.logger.info(r'export bcd ok : {}'.format(bcd_path))
            return bcd_path
        else:
            raise Exception(r'export bcd failed : {}'.format(rcode))

    def copy_bcd(self, bcd_path, boot_gpt_vol):
        boot_bcd_path = os.path.join(boot_gpt_vol, 'boot', 'BCD')
        self.logger.info(r'boot_bcd_path : {}'.format(boot_bcd_path))
        if os.path.exists(boot_bcd_path):
            os.remove(boot_bcd_path)
        shutil.copyfile(bcd_path, boot_bcd_path)
        return boot_bcd_path

    def fix_boot_bcd(self, bcd_edit_path, bcd_path):
        cmd = r'{} /store "{}" /set {{default}} path \Windows\system32\winload.exe'.format(bcd_edit_path, bcd_path)
        self.logger.info(r'will run : {}'.format(cmd))
        rcode = self._excute_cmd_and_return_code(cmd)
        self.logger.info(r'cmd return : {}'.format(rcode))

    def check_boot_bcd(self, bcd_edit_path, bcd_path):
        cmd = r'{} /store "{}" /enum {{default}}'.format(bcd_edit_path, bcd_path)
        self.logger.info(r'will run : {}'.format(cmd))
        rcode = self._excute_cmd_and_return_code(cmd)
        self.logger.info(r'cmd return : {}'.format(rcode))
        if r'\Windows\system32\winload.exe' not in rcode[1]:
            self.logger.error(r'fix boot bcd failed ??!!')
            raise Exception(r'fix boot bcd failed ??!!')


if __name__ == "__main__":
    r = Runner()
    r.work()
