import os
import sys

import win32api
import win32con
import win32file
import time
import traceback

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'chk_reg', 187)

    def show_and_exe_cmd_line_and_get_ret(self, in_cmd_line, chk_err_str=''):
        try:
            cmd_line = in_cmd_line
            self.logger.info(cmd_line)
            with os.popen(cmd_line) as out_put:
                out_put_lines = out_put.readlines()
                if '' == chk_err_str:
                    self.logger.info('0'), self.logger.info(out_put_lines)
                    return 0, out_put_lines
                for one_line in out_put_lines:
                    if -1 != one_line.find(chk_err_str):
                        self.logger.info('-1'), self.logger.info(out_put_lines)
                        return -1, out_put_lines
            self.logger.info('0'), self.logger.info(out_put_lines)
            return 0, out_put_lines
        except:
            self.logger.warning('show_and_exe_cmd_line_and_get_ret exe = {} failed'.format(in_cmd_line))
            self.logger.info('-1'), self.logger.info(out_put_lines)
            return -1, out_put_lines

    def add_disk_sys_vol(self):
        window_dir = win32api.GetWindowsDirectory()
        will_set_str = r'\??\{}'.format(os.path.dirname(window_dir[0:2]))
        disksbd_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                          r"SYSTEM\CurrentControlSet\Services\disksbd\Parameters",
                                          0,
                                          win32con.KEY_ALL_ACCESS)
        win32api.RegSetValueEx(disksbd_key, "SystemDrive", 0, win32con.REG_SZ,will_set_str)
        win32api.RegCloseKey(disksbd_key)

    def work_real(self):
        try:
            key_nadrv = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                            "SYSTEM\\CurrentControlSet\\services\\NAdrvIst\\Parameters\\000",
                                            0, win32con.KEY_ALL_ACCESS)
            win32api.RegCloseKey(key_nadrv)
        except:
            self.logger.warning(
                r'RegOpenKey SYSTEM\CurrentControlSet\services\NAdrvIst\Parameters\000 failed in to sleep')
            while True:
                time.sleep(1)
        try:
            key_filter = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                             "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E97D-E325-11CE-BFC1-08002BE10318}",
                                             0, win32con.KEY_ALL_ACCESS)
            LowerFilters_Read_Value = win32api.RegQueryValueEx(key_filter, "LowerFilters")
            if 0 == LowerFilters_Read_Value[0].count("NAdrvIst"):
                self.logger.warning(
                    r'RegOpenKey SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E97D-E325-11CE-BFC1-08002BE10318} Read LowerFilter failed in to sleep')
                while True:
                    time.sleep(1)
            win32api.RegCloseKey(key_filter)
        except:
            self.logger.warning(
                r'RegOpenKey SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E97D-E325-11CE-BFC1-08002BE10318} LowerFilter failed in to sleep')
            while True:
                time.sleep(1)

        cmd = "reg delete \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Network\" /v Config /f"
        returned_code = os.system(cmd)
        self.logger.info(r'work_real call "{}" returned_code {}'.format(cmd, returned_code))
        self.add_disk_sys_vol()


if __name__ == "__main__":
    r = Runner()
    r.work()
