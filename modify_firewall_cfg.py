import os
import sys

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'modify_firewall_cfg', 133)

    def work_real(self):
        if self.logger_dir == "None":
            self.logger.warning(r'not logger dir')
            return

        self.logger.info("logger_dir=" + self.logger_dir)
        exe_path = os.path.join(os.path.dirname(self.logger_dir), 'TaskWorker.exe')
        self.logger.info("exe_path=" + exe_path)

        self.logger.info(r'begin to disable firewall')
        cmd_line = r'"{}" disable_firewall'.format(exe_path)

        self.logger.info(r'cmd_line : {}'.format(cmd_line))
        returned_code = os.system(cmd_line)
        self.logger.info(r'returned : {}'.format(returned_code))


if __name__ == "__main__":
    r = Runner()
    r.work()
