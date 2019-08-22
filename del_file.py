import os
import sys
import traceback
import win32api

import win32con

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'del_file', 189)

    def show_and_exe_cmd_line_and_get_ret(self, in_cmd_line, chk_err_str=''):
        out_put_lines = 'none'
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
        except Exception as e:
            self.logger.warning('show_and_exe_cmd_line_and_get_ret exe = {} failed. {}'.format(in_cmd_line, e))
            self.logger.info('-1'), self.logger.info(out_put_lines)
            return -1, out_put_lines

    def fix_list_to_upper(self, proc_list):
        try:
            if proc_list is not None:
                for i in range(0, len(proc_list)):
                    proc_list[i] = proc_list[i].upper()
        except:
            self.logger.error(traceback.format_exc())

    def add_mul_reg(self, key, subKey, valu_name, valu_value):
        try:
            h_reg_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
            key_value_list = list()
            try:
                key_value_list, type = win32api.RegQueryValueEx(h_reg_key, valu_name)
            except:
                pass
            valu_value = valu_value.upper()
            self.fix_list_to_upper(key_value_list)
            if valu_value not in key_value_list:
                key_value_list.append(valu_value)
                win32api.RegSetValueEx(h_reg_key, valu_name, 0, win32con.REG_MULTI_SZ, key_value_list)
            win32api.RegCloseKey(h_reg_key)
        except:
            self.logger.error(traceback.format_exc())

    def del_mul_reg(self, key, subKey, valu_name, valu_value):
        try:
            h_reg_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
            key_value_list = list()
            try:
                key_value_list, type = win32api.RegQueryValueEx(h_reg_key, valu_name)
            except:
                pass
            valu_value = valu_value.upper()
            self.fix_list_to_upper(key_value_list)
            if valu_value in key_value_list:
                key_value_list.remove(valu_value)
                win32api.RegSetValueEx(h_reg_key, valu_name, 0, win32con.REG_MULTI_SZ, key_value_list)
            win32api.RegCloseKey(h_reg_key)
        except:
            self.logger.error(traceback.format_exc())

    def disable_Prefetch(self):
        try:
            key_1 = win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE,
                                          "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters")
            win32api.RegSetValueEx(key_1, "EnableSuperfetch", 0, win32con.REG_DWORD, 0)
            win32api.RegSetValueEx(key_1, "EnablePrefetcher", 0, win32con.REG_DWORD, 0)
            win32api.RegCloseKey(key_1)
        except Exception as e:
            self.logger.error(r'disable_Prefetch failed. {}'.format(e), exc_infp=True)

    def disable_PrefetchByService(self):
        self.logger.info('will disable PrefetchByService')
        returned = os.system(r'sc config SysMain start= disabled')
        self.logger.info('disable PrefetchByService return : {}'.format(returned))

    def disable_rdyboost(self):
        try:
            rdyboost_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                            "SYSTEM\\CurrentControlSet\\Services\\rdyboost",
                                            0,
                                            win32con.KEY_ALL_ACCESS)
            win32api.RegSetValueEx(rdyboost_key, "Start", 0, win32con.REG_DWORD, 4)
            win32api.RegCloseKey(rdyboost_key)
            self.del_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                        r'SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}', 'LowerFilters',
                        'rdyboost')
        except:
            self.logger.error(traceback.format_exc())

    def work_real(self):
        # windows_dir = win32api.GetWindowsDirectory()

        # for file in self.list_dir_without_except(os.path.join(windows_dir, 'Prefetch')):
        #    if file.lower().endswith('.pf'):
        #        self.remove_without_except(os.path.join(windows_dir, 'Prefetch', file))

        # for file in self.list_dir_without_except(os.path.join(windows_dir, 'Prefetch', 'ReadyBoot')):
        #    if file.lower().endswith('.fx'):
        #        self.remove_without_except(os.path.join(windows_dir, 'Prefetch', 'ReadyBoot', file))

        self.disable_Prefetch()
        self.disable_PrefetchByService()
        self.disable_rdyboost()

    def remove_without_except(self, file_path):
        try:
            os.remove(file_path)
            self.logger.warning(r'remove_without_except file_path = {}'.format(file_path))
        except Exception as e:
            self.logger.warning(r'remove {} failed {}'.format(file_path, e))

    def list_dir_without_except(self, dir_path):
        try:
            ret = os.listdir(dir_path)
            self.logger.warning(r'list_dir_without_except list = {}'.format(ret))
            return ret
        except Exception as e:
            self.logger.warning(r'listdir {} failed {}'.format(dir_path, e))
            return []


if __name__ == "__main__":
    r = Runner()
    r.work()
