import json
import os
import sys
import traceback
import win32api
import win32file

import time

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

try:
    import xlogging
except ImportError:
    import logging as xlogging

copy_opt_add = 1
copy_opt_over_write = 2
copy_opt_over_write_rename = 3
copy_failed_retry = 1
copy_failed_retry_times_ignore = 2


class UpdateV1(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'common_update_files', 124)
        self.bIs64OS = self.check_32_or_64()
        self.cat_ver = self.get_cat_ver()
        self.logger.info(r'bIs64OS : {}'.format(self.bIs64OS))
        self.logger.info(r'cat_ver : {}'.format(self.cat_ver))
        self.update_src_dir = os.path.join(current_dir, 'common_update_files')
        self.update_table_path = os.path.join(self.update_src_dir, 'update_table.json')
        self.update_table_list = list()

    def show_and_exe_cmd_line_and_get_ret(self, in_cmd_line, chk_err_str='', bPrint=True):
        try:
            cmd_line = in_cmd_line
            if bPrint:
                self.logger.info(cmd_line)
            with os.popen(cmd_line) as out_put:
                out_put_lines = out_put.readlines()
                if '' == chk_err_str:
                    if bPrint:
                        self.logger.info('0')
                        self.logger.info(out_put_lines)
                    return 0, out_put_lines
                for one_line in out_put_lines:
                    if -1 != one_line.find(chk_err_str):
                        if bPrint:
                            self.logger.info('show_and_exe_cmd_line_and_get_ret return -1')
                        return -1, []
            if bPrint:
                self.logger.info('0')
                self.logger.info(out_put_lines)
            return 0, out_put_lines
        except:
            if bPrint:
                self.logger.info(traceback.format_exc())
                self.logger.info('show_and_exe_cmd_line_and_get_ret excption return -1')
            return -1, []

    @staticmethod
    def check_32_or_64():
        sys_info = win32api.GetNativeSystemInfo()
        if sys_info[0] == 0:  # 如果是32位系统 PROCESSOR_ARCHITECTURE_INTEL
            return False
        return True

    def get_cat_ver(self):
        ret, lines = self.show_and_exe_cmd_line_and_get_ret(os.path.join(current_dir, 'NewCatName.exe'))
        for one in lines:
            if 0 == one.find('err:'):
                return ''
            return one

    def Load_file_list(self):
        try:
            with open(self.update_table_path, 'r') as update_table_handle:
                json_str = update_table_handle.read()
                self.update_table_list = json.loads(json_str)
        except:
            self.logger.info(traceback.format_exc())

    def get_real_des_path(self, one_file):
        try:
            ret_str = one_file['des'].lower()
            windows_path = win32api.GetWindowsDirectory()
            ret_str = ret_str.replace('%win%', windows_path)
            return ret_str
        except:
            print(traceback.format_exc())
            self.logger.info(traceback.format_exc())
            return ''

    def copy_one_file(self, one_file):
        try:
            # 获许修改后路径。
            self.logger.info('copy_one_file begin one_file = {}'.format(one_file))
            real_des_path = self.get_real_des_path(one_file)
            real_src_path = os.path.join(self.update_src_dir, one_file['src'])
            self.logger.info('copy_one_file real_des_path = {},real_src_path={}'.format(real_des_path, real_src_path))
            # 开始拷贝文件。
            if one_file['copy_opt'] == copy_opt_add:
                if os.path.exists(real_des_path) is not True:
                    win32api.CopyFile(real_src_path, real_des_path, 1)
                    self.logger.info('copy_one_file succ copy_opt_add real_des_path = {}'.format(real_des_path))
            elif one_file['copy_opt'] == copy_opt_over_write:
                if os.path.exists(real_des_path):
                    win32api.DeleteFile(real_des_path)
                win32api.CopyFile(real_src_path, real_des_path, 1)
                self.logger.info('copy_one_file succ copy_opt_over_write real_des_path = {}'.format(real_des_path))
            elif one_file['copy_opt'] == copy_opt_over_write_rename:
                self.logger.info('one_file[copy_opt] err = {}'.format(one_file['copy_opt']))
                return False
            else:
                self.logger.info('one_file[copy_opt] err = {}'.format(one_file['copy_opt']))
                return False
            self.logger.info('copy_one_file return True one_file = {}'.format(one_file))
            return True
        except:
            self.logger.info(traceback.format_exc())
            return False

    def chk_cat_ver(self, system_need):
        try:
            comp_len = min(len(system_need), len(self.cat_ver))
            for i in range(comp_len):
                if system_need[i] == '?':
                    continue
                if system_need[i] != self.cat_ver[i]:
                    return False
            return True
        except:
            self.logger.info(traceback.format_exc())

    def proc_one_file(self, one_file):
        try:
            # 判断操作系统是否匹配。
            if self.chk_cat_ver(one_file['system_need']) is not True:
                return
            # 判断将来出了错，该怎么处理。
            if one_file['copy_failed'] == copy_failed_retry:
                while self.copy_one_file(one_file) is False:
                    time.sleep(0.3)
            elif one_file['copy_failed'] == copy_failed_retry_times_ignore:
                have_run_times = 0
                while self.copy_one_file(one_file) is False:
                    time.sleep(0.3)
                    if have_run_times > one_file['retry_times']:
                        break
                    have_run_times = have_run_times + 1
            else:
                self.logger.info('one_file[copy_failed] err = {}'.format(one_file['copy_failed']))
                return
        except:
            self.logger.info(traceback.format_exc())

    def work_real(self):
        self.logger.info('work_real begin')

        if not os.path.exists(self.update_src_dir):
            self.logger.warning(r'not exist : {}'.format(self.update_src_dir))
            return

        if not os.path.exists(self.update_table_path):
            self.logger.warning(r'not exist : {}'.format(self.update_table_path))
            return
        if self.bIs64OS:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()

        self.Load_file_list()
        for one_file in self.update_table_list:
            self.proc_one_file(one_file)

        if self.bIs64OS:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)

        self.logger.info('work_real end')

    def gen_one_json(self):
        table_list = list()
        one_copy = {'copy_opt': copy_opt_over_write, 'retry_times': 2,
                    'copy_failed': copy_failed_retry_times_ignore,
                    'src': '05.01.00\\e1000325.sys',
                    'des': '%win%\\system32\\drivers\\e1000325.sys',
                    'system_need': '05.01.00.??',
                    'serv_pack_need': ''}
        table_list.append(one_copy)
        one_copy = {'copy_opt': copy_opt_over_write, 'retry_times': 2,
                    'copy_failed': copy_failed_retry_times_ignore,
                    'src': '05.02.00\\e1000325.sys',
                    'des': '%win%\\system32\\drivers\\e1000325.sys',
                    'system_need': '05.02.00.??',
                    'serv_pack_need': ''}
        table_list.append(one_copy)
        json_str = json.dumps(table_list)
        with open(self.update_table_path, 'w') as update_table_handle:
            update_table_handle.write(json_str)


if __name__ == "__main__":
    r = UpdateV1()
    r.work()
