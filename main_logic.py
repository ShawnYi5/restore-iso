import datetime
import os
import shutil
import subprocess
import sys
import threading
import time

import win32api
import win32con

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)
FLAG_FILE_PATH = os.path.join(win32api.GetWindowsDirectory(), 'f5df5cf4b79c4afcb7da7df4359562b8')

import xlogging

python_path = os.path.join(current_dir, 'python.exe')
run_cmd_as_path = os.path.join(current_dir, 'runCMDas.exe')
logger_in_system_32_path = os.path.join(win32api.GetSystemDirectory(), 'restore_iso_logger')
fixpage_path = os.path.join(current_dir, 'FixPag.exe')


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'main_logic', 111)
        shutil.rmtree(logger_in_system_32_path, ignore_errors=True)
        os.makedirs(logger_in_system_32_path, exist_ok=True)

    def work_real(self):
        self.check_debug_flag('_debug_pause_in_kvm_begin')
        kill_rav_thread = threading.Thread(target=self.while_call_py_until_failed,
                                           args=(os.path.join(current_dir, 'kill_rav.py'), 10,),
                                           daemon=True)
        kill_rav_thread.start()
        kill_oracle_thread = threading.Thread(target=self.while_call_py_until_failed,
                                              args=(os.path.join(current_dir, 'kill_oracle.py'), 10,),
                                              daemon=True)
        kill_oracle_thread.start()
        kill_spec_task_thread = threading.Thread(target=self.while_call_py_until_failed,
                                                 args=(os.path.join(current_dir, 'kill_spec_task.py'), 60,),
                                                 daemon=True)
        kill_spec_task_thread.start()
        install_patch_thread = threading.Thread(target=self.while_call_py_until_success,
                                                args=(os.path.join(current_dir, 'install_patch.py'),),
                                                daemon=True)
        install_patch_thread.start()
        self.while_call_py_until_success(os.path.join(current_dir, 'update_files.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'install_restore_bat.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'modify_agent_cfg.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'modify_agent_ini.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'modify_soft_ident.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'pr_read.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'filesys_read.py'))
        self.while_call_winlogon_until_success(os.path.join(current_dir, 'install_drv.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'install_reg.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'chk_reg.py'))
        # self.reboot_once()  # 某些环境需要重启一次系统
        backup_drivers_path = os.path.join(current_dir, 'backup_drivers.py')
        if os.path.exists(backup_drivers_path):
            self.while_call_py_until_success(backup_drivers_path)
        self.while_call_py_until_success(os.path.join(current_dir, 'add_routers.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'del_file.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'rename_vmware_tools.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'uninstall_ms_wlbs.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'modify_firewall_cfg.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'common_update_files.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'htb_logic.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'replace_efi.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'disable_bootopt.py'))

        self.logger.info(r'begin check install_patch_thread is_alive')
        while install_patch_thread.is_alive():
            time.sleep(1)
        self.logger.info(r'check install_patch_thread stopped')

        self.while_call_py_until_success(os.path.join(current_dir, 'clw_boot_gpt.py'))
        self.while_call_py_until_success(os.path.join(current_dir, 'bmf_proc.py'))
        try:
            self.execute_cmd_and_return_code(fixpage_path)
        except:
            pass
        self.flush_reg()
        self.create_success()

        self.check_debug_flag('_debug_pause_in_kvm_end')

    def check_debug_flag(self, file_name):
        debug_flag_path = os.path.join(current_dir, file_name)
        pause_flag_path = os.path.join(self.logger_dir, file_name)
        try:
            if os.path.exists(debug_flag_path):
                self.logger.info(r'create pause flag file')
                with open(pause_flag_path, 'w') as f:
                    f.flush()
                time.sleep(1)
            elif os.path.exists(pause_flag_path):
                os.remove(pause_flag_path)
        except Exception as e:
            self.logger.warning('check_debug_flag : {}'.format(e))

        while os.path.exists(pause_flag_path):
            time.sleep(10)
            self.logger.warning(r'!!! need remove pause flag file : {}'.format(pause_flag_path))

    def create_success(self):
        success_path = os.path.join(self.logger_dir, r'check_success')
        with open(success_path, 'w') as f:
            f.write('success')
        time.sleep(1)

    def flush_reg(self):
        try:
            win32api.RegFlushKey(win32con.HKEY_LOCAL_MACHINE)
            self.logger.info(r'call win32api.RegFlushKey ok')
        except Exception as e:
            self.logger.error(r'call win32api.RegFlushKey failed {}'.format(e))

    def call_py_with_winlogon(self, file_path):
        cmd = r'{run_cmd_as_path} winlogon {python_path} {file_path} {logger_dir_flag} {logger_dir}' \
            .format(run_cmd_as_path=run_cmd_as_path, python_path=python_path, file_path=file_path,
                    logger_dir_flag=xlogging.LOGGER_DIR_FLAG, logger_dir=logger_in_system_32_path)

        self.logger.info(r'wait py exit: {}'.format(file_path))
        self.waite_py_exit(file_path)
        self.logger.info(r'call_py_with_winlogon os.system : {}'.format(cmd))
        self.make_file()
        returned_code = os.system(cmd)
        self.logger.info(r'call_py_with_winlogon os.sysytem returned : {}'.format(returned_code))
        self.waite_py_exit(file_path)  # 在有一个客户那里，tasklist执行失败。所以用文件检查的方法来处理。
        # while os.path.exists(FLAG_FILE_PATH):
        #    self.logger.info(r'wait for driver install!')
        #    time.sleep(6)
        #    #self.raise_logic_error(r'flag file exists', returned_code)            

    def call_py(self, file_path):
        cmd = r'{python_path} "{file_path}" {logger_dir_flag} "{logger_dir}"' \
            .format(python_path=python_path, file_path=file_path, logger_dir_flag=xlogging.LOGGER_DIR_FLAG,
                    logger_dir=self.logger_dir)

        self.logger.info(r'call_py os.system : {}'.format(cmd))
        returned_code = os.system(cmd)
        self.logger.info(r'call_py os.sysytem returned : {}'.format(returned_code))
        if returned_code != 0:
            self.raise_logic_error(r'returned_code != 0 : {} '.format(cmd), returned_code)

    def while_call_winlogon_until_success(self, file_path):
        while True:
            try:
                self.call_py_with_winlogon(file_path)
                break
            except xlogging.LogicError as e:
                self.logger.warning(r'call {} return {}'.format(file_path, e.returned_code))

            time.sleep(10)

    def while_call_py_until_success(self, file_path):
        while True:
            try:
                self.call_py(file_path)
                break
            except xlogging.LogicError as e:
                self.logger.warning(r'call {} return {}'.format(file_path, e.returned_code))

            time.sleep(10)

    def while_call_py_until_failed(self, file_path, seconds=10):
        while True:
            try:
                self.call_py(file_path)
            except xlogging.LogicError as e:
                self.logger.warning(r'call {} return {}'.format(file_path, e.returned_code))
                break

            time.sleep(seconds)

    def execute_cmd_and_return_code(self, cmd):
        self.logger.info('execute_cmd_and_return_code cmd:{}'.format(cmd))
        with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True) as p:
            stdout, stderr = p.communicate()
        self.logger.info('execute_cmd_and_return_code cmd:{},output:{}|{}|{}'.format(cmd, p.returncode, stdout, stderr))
        return p.returncode, (stdout or stderr)

    def make_file(self):
        with open(FLAG_FILE_PATH, 'w') as f:
            pass

    # 最多等待15分钟内, 在局域网内应该没问题了，互联网上，又要遇到进程提前退出，建立文件失败的情况就比较小了。
    # 等待，30秒超时，30秒内都没有建立文件，则认为模块已经退出。模块中每5秒在定时器中建立文件。
    def waite_py_exit(self, file_name):
        end_time = datetime.datetime.now() + datetime.timedelta(seconds=15 * 60)
        self.logger.info(r'start waite_py_exit {}'.format(file_name))
        while datetime.datetime.now() < end_time:
            self.logger.info(r'waite_py_exit remove file:{}'.format(FLAG_FILE_PATH))
            try:
                os.remove(FLAG_FILE_PATH)
            except Exception as e:
                self.logger.warning('remove file{} warning : {}'.format(FLAG_FILE_PATH, e))

            for timeout in range(3):
                if os.path.exists(FLAG_FILE_PATH):
                    self.logger.info(r'file exists:{}'.format(FLAG_FILE_PATH))
                    break  # 文件存在了，退出循环重新检查。
                time.sleep(10)
            if not os.path.exists(FLAG_FILE_PATH):
                self.logger.info(r'file nexists:{} and return'.format(FLAG_FILE_PATH))
                return

    def reboot_once(self):
        self.logger.info(r'reboot_once begin')
        flag_path = os.path.join(self.logger_dir, '..', 'reboot.kvm.flag')

        if os.path.isfile(flag_path):
            os.remove(flag_path)
            self.logger.info(r'find reboot flag, delete it')
            return

        open(flag_path, 'w').close()
        self.logger.info(r'need reboot')

        os.system('shutdown /r /t 0 /f /d p:2:4')
        while True:
            time.sleep(1)


if __name__ == "__main__":
    r = Runner()
    r.work()
