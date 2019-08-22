import os
import sys
import win32api
import win32file

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'update_files', 104)
        self._bIs64OS = self.check_32_or_64()
        self.major, self.min = self.get_ver()
        self.logger.info(r'_bIs64OS : {}'.format(self._bIs64OS))

    @staticmethod
    def check_32_or_64():
        sys_info = win32api.GetNativeSystemInfo()
        if sys_info[0] == 0:  # 如果是32位系统 PROCESSOR_ARCHITECTURE_INTEL
            return False
        return True

    def get_ver(self):
        ver_info = win32api.GetVersionEx()
        self.logger.info('ver_info = {}'.format(ver_info))
        return ver_info[0], ver_info[1]

    def copy_files(self, source_dir, target_dir):
        for file in os.listdir(source_dir):
            source_file = os.path.join(source_dir, file)
            target_file = os.path.join(target_dir, file)
            if os.path.isfile(source_file):
                if not os.path.exists(target_dir):
                    self.logger.info('create dir : {}'.format(target_dir))
                    os.makedirs(target_dir)
                self.logger.info('cp {} --> {}'.format(source_file, target_file))
                open(target_file, "wb").write(open(source_file, "rb").read())
            if os.path.isdir(source_file):
                self.copy_files(source_file, target_file)

    def work_real(self):
        self.logger.info('work_real begin')

        update_src_dir = os.path.join(current_dir, 'update_files')
        if not os.path.exists(update_src_dir):
            self.logger.warning(r'not exist : {}'.format(update_src_dir))
            return

        self.update_drivers()

        self.logger.info('work_real end')

    def update_drivers(self):
        self.logger.info('update_drivers begin')

        if self._bIs64OS:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()
            update_src_dir = os.path.join(current_dir, 'update_files', 'drivers', 'x64')
        else:
            save_64_value = None
            update_src_dir = os.path.join(current_dir, 'update_files', 'drivers', 'x86')

        if not os.path.exists(update_src_dir):
            self.logger.warning(r'not exist : {}'.format(update_src_dir))
        else:
            dest_dir = os.path.join(win32api.GetSystemDirectory(), 'drivers')
            self.copy_files(update_src_dir, dest_dir)

        if self._bIs64OS:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)

        self.logger.info('update_drivers end')


if __name__ == "__main__":
    r = Runner()
    r.work()
