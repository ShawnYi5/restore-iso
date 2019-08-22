import os
import subprocess
import sys
import win32api
import win32file

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)
import xlogging

tasks = ['r_service.exe', ]


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'kill spec', 183)
        self._bIs64OS = self.check_32_or_64()
        self.logger.info(r'_bIs64OS : {}'.format(self._bIs64OS))

    @staticmethod
    def check_32_or_64():
        sys_info = win32api.GetNativeSystemInfo()
        if sys_info[0] == 0:  # 如果是32位系统 PROCESSOR_ARCHITECTURE_INTEL
            return False
        return True

    def exe_cmd_and_get_ret(self, in_cmd_line):
        try:
            self.logger.info(r'begin call : {}'.format(in_cmd_line))
            p = subprocess.Popen(in_cmd_line, stdout=subprocess.PIPE)
            out = p.communicate()
            p.stdout.close()
            rc = p.returncode
            self.logger.info(r'return {}. {}'.format(rc, out))
            return rc, out[0].decode()
        except Exception as e:
            self.logger.warning(r'return error. {}'.format(e))
            return -1, ''

    def work_real(self):
        save_64_value = None
        if self._bIs64OS:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()

        for task in tasks:
            self.exe_cmd_and_get_ret(r'cmd /c "chcp 437 && taskkill /F /IM "{}""'.format(task))

        if self._bIs64OS:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)


if __name__ == "__main__":
    r = Runner()
    r.work()
