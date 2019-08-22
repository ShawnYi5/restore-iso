import os
import platform
import subprocess
import sys
import win32api
import win32file
import logging

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging


def get_system_arch():
    sys_info = win32api.GetNativeSystemInfo()
    if sys_info[0] == 0:  # 如果是32位系统 PROCESSOR_ARCHITECTURE_INTEL
        is_x64 = False
    else:
        is_x64 = True
    return is_x64


class DisableBlueScreenAndRepairReboot(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'disable_blue_screen_reboot_and_repair_reboot', 208)

    def _excute_cmd_and_return_code(self, cmd):
        try:
            with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  universal_newlines=True) as p:
                stdout, stderr = p.communicate()
            return p.returncode, stdout, stderr
        except Exception as e:
            self.logger.warning("cmd {} execute failed!the detail is {}".format(cmd, e))

    def work_real(self):
        version_first_num = int(platform.version().split(".")[0])
        if version_first_num >= 6:
            self.disable_repair_reboot()
        self.disable_blue_screen_reboot()

    def disable_blue_screen_reboot(self):
        cmd = 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\CrashControl" /v "AutoReboot" /t "REG_DWORD" /d "0x00000000" /f'
        self.logger.info(r'will run : {}'.format(cmd))

        rcode, outs, errs = self._excute_cmd_and_return_code(cmd)

        if rcode == 0:
            self.logger.info(r'close blue screen reboot success! ')
        else:
            self.logger.info(r'rcode:{},outs:{},err:{} '.format(rcode, outs, errs))
            self.raise_logic_error(r'close blue screen reboot failed!', 1)


    def disable_repair_reboot(self):
        cmd = "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures"
        self.logger.info(r'will run : {}'.format(cmd))

        org_val = None
        is_x64 = get_system_arch()

        try:
            if is_x64:
                org_val = win32file.Wow64DisableWow64FsRedirection()

            rcode, outs, errs = self._excute_cmd_and_return_code(cmd)

            if is_x64:
                win32file.Wow64RevertWow64FsRedirection(org_val)

            if rcode == 0:
                self.logger.info(r'close repair reboot success! ')
            else:
                self.logger.info(r'rcode:{},outs:{},errs:{} '.format(rcode, outs, errs))
                self.raise_logic_error(r'close repair failed!', 1)

        except Exception as e:
            self.logger.warning("cmd:{} execute failed!the detail is {}".format(cmd, e))


if __name__ == "__main__":
    r = DisableBlueScreenAndRepairReboot()
    r.work()
