import os
import platform
import sys
import win32api

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)
import xlogging


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'uninstall_ms_wlbs', 106)
        self._bIs64OS = self.check_32_or_64()
        self.logger.info(r'_bIs64OS : {}'.format(self._bIs64OS))

    @staticmethod
    def check_32_or_64():
        sys_info = win32api.GetNativeSystemInfo()
        if sys_info[0] == 0:  # 如果是32位系统 PROCESSOR_ARCHITECTURE_INTEL
            return False
        return True

    def proc_2003_xp(self, exec_path):
        self.logger.info(r'proc_2003_xp begin')
        # my_class = CUnAntiProcErr(self.logger)
        # # 2003 , xp
        # param = r' -u ms_wlbs '
        # my_class.RunExe(exec_path, param, current_dir)

        self.logger.info(r'proc_2003_xp end')

    def proc_greater_2003_xp(self, exec_path):
        self.logger.info(r'proc_greater_2003_xp begin')
        # win7
        param = r' -u ms_psched '
        os.system(exec_path + param)
        # 2008 及以上...
        param = r' -u ms_pacer'
        os.system(exec_path + param)
        self.logger.info(r'proc_greater_2003_xp end')
        return

    def work_real(self):
        self.logger.info(r'work_real begin')
        if self._bIs64OS:
            exec_path = os.path.join(current_dir, r'netcfg.x64.exe')
        else:
            exec_path = os.path.join(current_dir, r'netcfg.x86.exe')
        self.logger.info(r'work_real exec_path = {}'.format(exec_path))

        log_path = os.path.join(self.logger_dir, 'netcfg.log')
        ver_info = win32api.GetVersionEx()
        self.logger.info(r'work_real ver_info = {}'.format(ver_info))
        if ver_info[0] < 6:
            self.proc_2003_xp(exec_path)
            return
        else:
            self.proc_greater_2003_xp(exec_path)
            return


if __name__ == "__main__":
    r = Runner()
    r.work()
