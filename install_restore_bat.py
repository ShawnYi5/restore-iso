import os
import sys

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging
import copy_by_reg


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'install_restore_bat', 133)

    def work_real(self):
        if self.logger_dir == "None":
            self.logger.warning(r'not logger dir')
            return

        self.logger.info(r'will copy file : restore.bat')
        src_path = os.path.join(current_dir, 'restore.bat')
        dest_path = os.path.join(self.logger_dir, 'restore.bat')
        cmd = r'copy /V /Y "{}" "{}"'.format(src_path, dest_path)
        self.logger.info(r'cmd : {}'.format(cmd))
        returned_code = os.system(cmd)

        self.logger.info(r'will copy file : WaitSysI.exe')
        src_path = os.path.join(current_dir, 'WaitSysI.exe')
        dest_dir = os.path.dirname(self.logger_dir)
        dest_path = os.path.join(dest_dir, 'WaitSysI.exe')
        cmd = r'copy /V /Y "{}" "{}"'.format(src_path, dest_path)
        self.logger.info(r'cmd : {}'.format(cmd))
        returned_code = os.system(cmd)

        self.logger.info(r'cmd returned : {}'.format(returned_code))

        copy_by_reg.copy_file(dest_path, self.logger)

if __name__ == "__main__":
    r = Runner()
    r.work()
