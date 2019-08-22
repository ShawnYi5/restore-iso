import os
import sys
import win32api
import win32event
import win32file
import win32process
import traceback

import win32con

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'install_patch', 135)
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

    def ChkIsSha2562008R2(self, file_path):
        try:
            cmd_line = '"' + current_dir + r'\signtool\amd64\signtool.exe' + '" verify /kp "' + file_path + '"'
            ret, lines = self.show_and_exe_cmd_line_and_get_ret(cmd_line)
            if lines is not None:
                for one_line in lines:
                    if -1 != one_line.find('sha256'):
                        return True
            return False

        except Exception as e:
            self.logger.warning(r'return error. {}'.format(e))
            return False

    def add2reg(self, file):
        hMutex = win32event.CreateMutex(None, False, 'Global\\ClerwareBackUpFile')
        if hMutex is None:
            self.logger.error('can not create mutex Global\\ClerwareBackUpFile')
            return
        win32event.WaitForSingleObject(hMutex,win32event.INFINITE)
        try:
            file = '{}{}'.format('\\??\\', file)
            filelist_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                               "SYSTEM\\CurrentControlSet\\Services\\disksbd\\Parameters",
                                               0,
                                               win32con.KEY_ALL_ACCESS)
            try:
                filelist_value, i = win32api.RegQueryValueEx(filelist_key, "HotReadyReserveFileList")
            except:
                filelist_value = list()
            filelist_value.append(file)
            filelist_value = list(set(filelist_value))
            win32api.RegSetValueEx(filelist_key, "HotReadyReserveFileList", 0, win32con.REG_MULTI_SZ, filelist_value)
            win32api.RegCloseKey(filelist_key)

        except Exception as e:
            self._logger.debug(traceback.format_exc())
        win32event.ReleaseMutex(hMutex)
        win32api.CloseHandle(hMutex)

    def addSha256FileToReg(self):
        try:
            # 调用函数已经处理重定向。
            windows_dir = win32api.GetWindowsDirectory()
            windows_disk = windows_dir[0:2]
            system_dir = win32api.GetSystemDirectory()
            wow64_dir = windows_dir + "\\SysWOW64"
            # 2003 x64 安装补丁。
            if self.major == 5 and self.min == 2 and self._bIs64OS is True:
                self.add2reg(windows_dir + '\\inf\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\branches.inf')

                self.add2reg(system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\KB968730.cat')
                self.add2reg(system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\TimeStamp')
                self.add2reg(system_dir + '\\CatRoot2\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\catdb')
                self.add2reg(system_dir + '\\CatRoot2\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\TimeStamp')

                self.add2reg(system_dir + '\\crypt32.dll')
                self.add2reg(system_dir + '\\perfc009.dat')
                self.add2reg(system_dir + '\\perfh009.dat')
                self.add2reg(system_dir + '\\PerfStringBackup.INI')
                self.add2reg(system_dir + '\\prfc0804.dat')
                self.add2reg(system_dir + '\\prfh0804.dat')
                self.add2reg(system_dir + '\\spmsg.dll')

                self.add2reg(wow64_dir + '\\crypt32.dll')

            # 2008 x64 r2 安装补丁。
            if self.major == 6 and self.min == 1 and self._bIs64OS is True:
                self.add2reg(windows_disk + "\\Boot\\EFI\\memtest.efi")
                self.add2reg(windows_disk + "\\Boot\\PCAT\\memtest.exe")

                self.add2reg(system_dir + "\\Boot\\zh-CN\\winload.efi.mui")
                self.add2reg(system_dir + "\\Boot\\zh-CN\\winload.exe.mui")
                self.add2reg(system_dir + "\\Boot\\zh-CN\\winresume.efi.mui")
                self.add2reg(system_dir + "\\Boot\\zh-CN\\winresume.exe.mui")

                self.add2reg(system_dir + "\\Boot\\winload.efi")
                self.add2reg(system_dir + "\\Boot\\winload.exe")
                self.add2reg(system_dir + "\\Boot\\winresume.efi")
                self.add2reg(system_dir + "\\Boot\\winresume.exe")

                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_54_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_56_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_57_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_58_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_74_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_76_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_78_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_79_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_112_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_114_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_115_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_116_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_117_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_118_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_119_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_156_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_161_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_183_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_185_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_186_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_187_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_188_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_189_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_190_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_191_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_192_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_193_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_194_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_195_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_196_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_197_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_198_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_199_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_200_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_201_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_202_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_for_KB3033929_SP1~31bf3856ad364e35~amd64~~6.1.1.1.cat')
                self.add2reg(
                    system_dir + '\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\Package_for_KB3033929~31bf3856ad364e35~amd64~~6.1.1.1.cat')

                self.add2reg(system_dir + '\\catroot2\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\catdb')

                self.add2reg(system_dir + '\\Dism\\CbsProvider.dll')
                self.add2reg(system_dir + '\\Dism\\CompatProvider.dll')
                self.add2reg(system_dir + '\\Dism\\DmiProvider.dll')
                self.add2reg(system_dir + '\\Dism\\IntlProvider.dll')
                self.add2reg(system_dir + '\\Dism\\OSProvider.dll')
                self.add2reg(system_dir + '\\Dism\\SmiProvider.dll')
                self.add2reg(system_dir + '\\Dism\\UnattendProvider.dll')
                self.add2reg(system_dir + '\\Dism\\WimProvider.dll')

                self.add2reg(system_dir + '\\drivers\\appid.sys')
                self.add2reg(system_dir + '\\drivers\\cng.sys')
                self.add2reg(system_dir + '\\drivers\\ksecdd.sys')
                self.add2reg(system_dir + '\\drivers\\ksecpkg.sys')
                self.add2reg(system_dir + '\\drivers\\mountmgr.sys')
                self.add2reg(system_dir + '\\drivers\\PEAuth.sys')

                self.add2reg(system_dir + '\\en-US\\adtschema.dll.mui')
                self.add2reg(system_dir + '\\en-US\\auditpol.exe.mui')
                self.add2reg(system_dir + '\\en-US\\ci.dll.mui')
                self.add2reg(system_dir + '\\en-US\\msaudite.dll.mui')
                self.add2reg(system_dir + '\\en-US\\msobjs.dll.mui')

                self.add2reg(system_dir + '\\zh-CN\\adtschema.dll.mui')
                self.add2reg(system_dir + '\\zh-CN\\auditpol.exe.mui')
                self.add2reg(system_dir + '\\zh-CN\\crypt32.dll.mui')
                self.add2reg(system_dir + '\\zh-CN\\lsasrv.dll.mui')
                self.add2reg(system_dir + '\\zh-CN\\msaudite.dll.mui')
                self.add2reg(system_dir + '\\zh-CN\\msobjs.dll.mui')
                self.add2reg(system_dir + '\\zh-CN\\winload.efi.mui')
                self.add2reg(system_dir + '\\zh-CN\\winload.exe.mui')
                self.add2reg(system_dir + '\\zh-CN\\winresume.efi.mui')
                self.add2reg(system_dir + '\\zh-CN\\winresume.exe.mui')

                self.add2reg(system_dir + '\\adtschema.dll')
                self.add2reg(system_dir + '\\apisetschema.dll')
                self.add2reg(system_dir + '\\appidapi.dll')
                self.add2reg(system_dir + '\\appidcertstorecheck.exe')
                self.add2reg(system_dir + '\\appidpolicyconverter.exe')
                self.add2reg(system_dir + '\\appidsvc.dll')
                self.add2reg(system_dir + '\\audiodg.exe')
                self.add2reg(system_dir + '\\AudioEng.dll')
                self.add2reg(system_dir + '\\AUDIOKSE.dll')
                self.add2reg(system_dir + '\\AudioSes.dll')
                self.add2reg(system_dir + '\\audiosrv.dll')
                self.add2reg(system_dir + '\\auditpol.exe')
                self.add2reg(system_dir + '\\ci.dll')
                self.add2reg(system_dir + '\\credssp.dll')
                self.add2reg(system_dir + '\\crypt32.dll')
                self.add2reg(system_dir + '\\cryptnet.dll')
                self.add2reg(system_dir + '\\cryptsp.dll')
                self.add2reg(system_dir + '\\cryptsvc.dll')
                self.add2reg(system_dir + '\\cryptui.dll')
                self.add2reg(system_dir + '\\csrsrv.dll')
                self.add2reg(system_dir + '\\EncDump.dll')
                self.add2reg(system_dir + '\\kerberos.dll')
                self.add2reg(system_dir + '\\lsasrv.dll')
                self.add2reg(system_dir + '\\lsass.exe')
                self.add2reg(system_dir + '\\msaudite.dll')
                self.add2reg(system_dir + '\\msmmsp.dll')
                self.add2reg(system_dir + '\\msobjs.dll')
                self.add2reg(system_dir + '\\msv1_0.dll')
                self.add2reg(system_dir + '\\ncrypt.dll')
                self.add2reg(system_dir + '\\ntoskrnl.exe')
                self.add2reg(system_dir + '\\perfc009.dat')
                self.add2reg(system_dir + '\\perfh009.dat')
                self.add2reg(system_dir + '\\PerfStringBackup.INI')
                self.add2reg(system_dir + '\\prfc0804.dat')
                self.add2reg(system_dir + '\\prfh0804.dat')
                self.add2reg(system_dir + '\\qdvd.dll')
                self.add2reg(system_dir + '\\quartz.dll')
                self.add2reg(system_dir + '\\schannel.dll')
                self.add2reg(system_dir + '\\secur32.dll')
                self.add2reg(system_dir + '\\setbcdlocale.dll')
                self.add2reg(system_dir + '\\smss.exe')
                self.add2reg(system_dir + '\\sspicli.dll')
                self.add2reg(system_dir + '\\sspisrv.dll')
                self.add2reg(system_dir + '\\TSpkg.dll')
                self.add2reg(system_dir + '\\wdigest.dll')
                self.add2reg(system_dir + '\\winload.efi')
                self.add2reg(system_dir + '\\winload.exe')
                self.add2reg(system_dir + '\\winresume.efi')
                self.add2reg(system_dir + '\\winresume.exe')
                self.add2reg(system_dir + '\\wintrust.dll')

                self.add2reg(wow64_dir + '\\Dism\\CbsProvider.dll')
                self.add2reg(wow64_dir + '\\Dism\\CompatProvider.dll')
                self.add2reg(wow64_dir + '\\Dism\\DmiProvider.dll')
                self.add2reg(wow64_dir + '\\Dism\\IntlProvider.dll')
                self.add2reg(wow64_dir + '\\Dism\\OSProvider.dll')
                self.add2reg(wow64_dir + '\\Dism\\SmiProvider.dll')
                self.add2reg(wow64_dir + '\\Dism\\UnattendProvider.dll')
                self.add2reg(wow64_dir + '\\Dism\\WimProvider.dll')

                self.add2reg(wow64_dir + '\\en-US\\adtschema.dll.mui')
                self.add2reg(wow64_dir + '\\en-US\\auditpol.exe.mui')
                self.add2reg(wow64_dir + '\\en-US\\msaudite.dll.mui')
                self.add2reg(wow64_dir + '\\en-US\\msobjs.dll.mui')

                self.add2reg(wow64_dir + '\\zh-CN\\adtschema.dll.mui')
                self.add2reg(wow64_dir + '\\zh-CN\\auditpol.exe.mui')
                self.add2reg(wow64_dir + '\\zh-CN\\crypt32.dll.mui')
                self.add2reg(wow64_dir + '\\zh-CN\\msaudite.dll.mui')
                self.add2reg(wow64_dir + '\\zh-CN\\msobjs.dll.mui')

                self.add2reg(wow64_dir + '\\adtschema.dll')
                self.add2reg(wow64_dir + '\\apisetschema.dll')
                self.add2reg(wow64_dir + '\\appidapi.dll')
                self.add2reg(wow64_dir + '\\AudioEng.dll')
                self.add2reg(wow64_dir + '\\AUDIOKSE.dll')
                self.add2reg(wow64_dir + '\\AudioSes.dll')
                self.add2reg(wow64_dir + '\\auditpol.exe')
                self.add2reg(wow64_dir + '\\credssp.dll')
                self.add2reg(wow64_dir + '\\crypt32.dll')
                self.add2reg(wow64_dir + '\\cryptnet.dll')
                self.add2reg(wow64_dir + '\\cryptsp.dll')
                self.add2reg(wow64_dir + '\\cryptsvc.dll')
                self.add2reg(wow64_dir + '\\cryptui.dll')
                self.add2reg(wow64_dir + '\\kerberos.dll')
                self.add2reg(wow64_dir + '\\msaudite.dll')
                self.add2reg(wow64_dir + '\\msobjs.dll')
                self.add2reg(wow64_dir + '\\msv1_0.dll')
                self.add2reg(wow64_dir + '\\ncrypt.dll')
                self.add2reg(wow64_dir + '\\ntkrnlpa.exe')
                self.add2reg(wow64_dir + '\\ntoskrnl.exe')
                self.add2reg(wow64_dir + '\\qdvd.dll')
                self.add2reg(wow64_dir + '\\quartz.dll')
                self.add2reg(wow64_dir + '\\schannel.dll')
                self.add2reg(wow64_dir + '\\secur32.dll')
                self.add2reg(wow64_dir + '\\sspicli.dll')
                self.add2reg(wow64_dir + '\\TSpkg.dll')
                self.add2reg(wow64_dir + '\\wdigest.dll')
                self.add2reg(wow64_dir + '\\wintrust.dll')

        except Exception as e:
            self._logger.debug(traceback.format_exc())

    def work_real(self):
        self.logger.info('work_real begin')

        # if self.logger_dir == "None":
        #     self.logger.warning(r'not logger dir')
        #     return
        if self._bIs64OS is not True:
            self.logger.info('work_real self._bIs64OS is not True')
            return
        if (self.major != 5) and (self.major != 6):
            self.logger.info('(self.major != 5) and (self.major != 6)')
            return
        if self.major == 5 and (self.min != 1 and self.min != 2):
            self.logger.info('self.major == 5 and self.min != 2')
            return
        if self.major == 6 and self.min != 1:
            self.logger.info('self.major == 6 and self.min != 1')
            return

        #如果没有安装标志，不安装。
        inf_dir = os.path.join(current_dir, 'inf')
        only_sha256_flag = os.path.join(inf_dir, 'only_sha256.flag')
        if not os.path.exists(only_sha256_flag):
            self.logger.info('not find .\inf\only_sha256.flag')
            return

        exe_name = ''
        commandLine = ''
        work_dir = ''
        # 2003 x64 安装补丁。
        if self.major == 5 and self.min == 2 and self._bIs64OS is True:
            work_dir = os.path.join(current_dir, 'KB968730')
            exe_name = os.path.join(win32api.GetSystemDirectory(), 'cmd.exe')
            commandLine = os.path.join(work_dir, 'WindowsServer2003.WindowsXP-KB968730-x64-CHS.exe')
            commandLine = ' /c "' + commandLine + '" /quiet /norestart '

        # 2008 x64 r2 安装补丁。
        if self.major == 6 and self.min == 1 and self._bIs64OS is True:
            # 检查当前驱动库目录下是否有 sha256 签名的驱动。
            # bFindSha256 = False
            # for root, dirs, files in os.walk(inf_dir):
            #     for file in files:
            #         if file.lower().endswith('.sys'):
            #             bIsSha256 = self.ChkIsSha2562008R2(os.path.join(root, file))
            #             if bIsSha256:
            #                 bFindSha256 = True
            # # 如果没有，退出。
            # if bFindSha256 is not True:
            #     self.logger.info('not find sha256')
            #     return

            exe_name = os.path.join(win32api.GetSystemDirectory(), 'wusa.exe')
            work_dir = os.path.join(current_dir, 'KB3033929')
            commandLine = os.path.join(work_dir, 'Windows6.1-KB3033929-x64.msu')
            commandLine = ' "' + commandLine + '" /quiet /norestart '

        self.logger.info('work_real exe_name = {}'.format(exe_name))
        self.logger.info('work_real commandLine = {}'.format(commandLine))
        save_64_value = win32file.Wow64DisableWow64FsRedirection()
        for one in range(2):  # 最多重试2次。每次3分钟。
            # 记录开始时间。
            self.logger.info('install times = {}'.format(one))
            start_count = win32api.GetTickCount()
            # 启动进程。
            PyStarInfo = win32process.STARTUPINFO()
            proc_info = win32process.CreateProcess(exe_name, commandLine, None, None, 0, 0, None, work_dir, PyStarInfo)
            ret = win32event.WaitForSingleObject(proc_info[0], 3 * 60 * 1000)
            # ret = win32event.WaitForSingleObject(proc_info[0], 1 * 60 * 1000)
            if ret == win32con.WAIT_OBJECT_0:
                # 操作完成,成功退出。
                exitCode = win32process.GetExitCodeProcess(proc_info[0])
                if (0 == exitCode) or (0 == 0xBC2):
                    self.addSha256FileToReg()
                self.logger.info('ret == win32con.WAIT_OBJECT_0')
                win32file.Wow64RevertWow64FsRedirection(save_64_value)
                return
            self.logger.info('ret != win32con.WAIT_OBJECT_0')
            # 否则杀掉进程，继续循环安装。
            win32api.TerminateProcess(proc_info[0], 0)
            win32event.WaitForSingleObject(proc_info[0], win32event.INFINITE)
        win32file.Wow64RevertWow64FsRedirection(save_64_value)


if __name__ == "__main__":
    r = Runner()
    r.work()
