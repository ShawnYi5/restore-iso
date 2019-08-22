import os
import platform
import sys
import win32api
import win32file

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)
import xlogging


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'rename vmware tools', 131)
        self._bIs64OS = self.check_32_or_64()
        self.logger.info(r'_bIs64OS : {}'.format(self._bIs64OS))

    @staticmethod
    def check_32_or_64():
        sys_info = win32api.GetNativeSystemInfo()
        if sys_info[0] == 0:  # 如果是32位系统 PROCESSOR_ARCHITECTURE_INTEL
            return False
        if platform.architecture()[0] == '64bit':
            return False
        return True

    @staticmethod
    def safe_remove(path):
        try:
            os.remove(path)
        except Exception as e:
            pass

    def work_real(self):
        if self._bIs64OS:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()

        file_path = os.path.join(win32api.GetSystemDirectory(), 'VMUpgradeAtShutdownWXP.dll')
        if os.path.exists(file_path):
            self.logger.info(r'find file : {}'.format(file_path))
            new_file_path = file_path + '_bak'
            self.safe_remove(new_file_path)
            os.rename(file_path, new_file_path)
        else:
            self.logger.info(r'NOT find file : {}'.format(file_path))

        if self._bIs64OS:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)


if __name__ == "__main__":
    r = Runner()
    r.work()
