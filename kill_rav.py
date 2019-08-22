import os
import subprocess
import sys
import win32api

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)
import xlogging


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'kill rav', 387)
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
        try:
            self.logger.info('UninstRavNetMonThread run begin')
            if self._bIs64OS:
                exec_path = os.path.join(current_dir, r'netcfg.x64.exe')
            else:
                exec_path = os.path.join(current_dir, r'netcfg.x86.exe')

            os.system(exec_path + r' -u RS_RFWNDIS ')
            os.system(exec_path + r' -u RS_RFWARP ')
            os.system(exec_path + r' -u MS_IMPLAT ')

            self.logger.info('UninstRavNetMonThread run end')
        except Exception as e:
            self.logger.info('UninstRavNetMonThread failed {}'.format(e), exc_info=True)


if __name__ == "__main__":
    r = Runner()
    r.work()
