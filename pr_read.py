import glob
import os
import queue
import re
import sys
import threading
import traceback
import win32api
import win32file

import win32con

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)
import xlogging

g_bIs64OS = True


def Check32Or64OS():
    global g_bIs64OS

    sys_info = win32api.GetNativeSystemInfo()
    if sys_info[0] == 0:  # 如果是32位系统 PROCESSOR_ARCHITECTURE_INTEL
        g_bIs64OS = False
    return True


def win_CommandLineToArgvW(cmd):
    import ctypes
    nargs = ctypes.c_int()
    ctypes.windll.shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    lpargs = ctypes.windll.shell32.CommandLineToArgvW(cmd, ctypes.byref(nargs))
    args = [lpargs[i] for i in range(nargs.value)]
    if ctypes.windll.kernel32.LocalFree(lpargs):
        raise AssertionError
    return args


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'pr_read', 181)
        self.files = queue.Queue(64)
        self.worker_threads = list()
        for _ in range(10):
            t = threading.Thread(target=self.read_file_worker)
            t.daemon = True
            t.start()
            self.worker_threads.append(t)

    def read_file_worker(self):
        save_64_value = None
        try:
            if g_bIs64OS:
                save_64_value = win32file.Wow64DisableWow64FsRedirection()
            while True:
                path = self.files.get()
                self.read_bin_file_no_print_context(path)
                self.files.task_done()
        except Exception as e:
            self.logger.error(r'read_file_worker failed {} {}'.format(e, traceback.format_exc()))
        finally:
            if g_bIs64OS and save_64_value is not None:
                win32file.Wow64RevertWow64FsRedirection(save_64_value)

    def read_bin_file_no_print_context(self, file_path):
        try:
            max_buffer_bytes = 8 * 1024 * 1024
            with open(file_path, 'rb') as file_handle:
                while True:
                    read_bytes = len(file_handle.read(max_buffer_bytes))
                    self.logger.info("file_path = {},read len = {}".format(file_path, read_bytes))
                    if read_bytes < max_buffer_bytes or read_bytes == 0:
                        break
        except MemoryError:
            self.logger.error(r'read_bin_file_no_print_context {} failed. MemoryError'.format(file_path), exc_info=True)
            self.logger.error(r'kill self')
            os._exit(181)
        except Exception as e:
            self.logger.error(r'read_bin_file_no_print_context {} failed. {}'.format(file_path, e), exc_info=True)

    def read_all_file_and_sub_dir(self, dir_path):
        try:
            self.logger.info(r'read_all_file_and_sub_dir enum path:{}'.format(dir_path))
            if os.path.exists(dir_path):
                for root, dirs, files in os.walk(dir_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        self.files.put(file_path)
            else:
                self.logger.info('no dir path={}!'.format(dir_path))
        except Exception as e:
            self.logger.info(r'error enum path:{} failed. {}'.format(dir_path, e))

    def read_all_match_file(self, dir_path):
        try:
            self.logger.info(r'read_all_match_file enum path:{}'.format(dir_path))
            for name in glob.glob(dir_path):
                self.logger.info(r'match_file:{}'.format(name))
                self.files.put(name)
        except Exception as e:
            self.logger.info(r'error enum path:{} failed. {}'.format(dir_path, e))

    def read_all_file_without_sub_dir(self, dir_path):
        try:
            self.logger.info(r'read_all_file_without_sub_dir enum path:{}'.format(dir_path))

            if os.path.exists(dir_path):
                for file in os.listdir(dir_path):
                    file_path = os.path.join(dir_path, file)
                    if not os.path.isdir(file_path):
                        self.files.put(file_path)
            else:
                self.logger.info('no dir path={}!'.format(dir_path))
        except Exception as e:
            self.logger.info(r'error enum path:{} failed. {}'.format(dir_path, e))

    def read_all_file(self):
        save_64_value = None
        try:
            if g_bIs64OS:
                save_64_value = win32file.Wow64DisableWow64FsRedirection()

            windows_dir = win32api.GetWindowsDirectory()
            sys_dir = win32api.GetSystemDirectory()

            self.read_all_match_file(sys_dir + r"\mcupdat*.dll")

            filelist = [r"\SysWOW64\ntdll.dll", r"\SysWOW64\ntkrnlpa.exe", r"\SysWOW64\ntkrnlmp.exe",
                        r"\SysWOW64\ntoskrnl.exe", ]
            for file in filelist:
                self.files.put(windows_dir + file)

            filelist = [r"\ntdll.dll", r"\ntkrnlpa.exe", r"\ntkrnlmp.exe", r"\ntoskrnl.exe",
                        r"\SMSS.EXE", r"\kdcom.dll", r"\kd1394.dll", r"\kdusb.dll", r"\kdnet.dll", r"\autochk.exe",
                        r"\win32k.sys", r"\cdd.dll", r"\dispci.dll", r"\dispex.dll", r"\SVCHOST.EXE", r"\Srdelayed.exe",
                        r"\poqexec.exe", r"\setupcl.exe", r"\autochk.exe", r"\autoconv.exe", r"\autofmt.exe",
                        r"\APISETSCHEMA.DLL", r"\MSCTF.DLL", r"\acpitabl.dat", r"\mcupdate.dll", r"\ci.dll",
                        r"\bootvid.dll", r"\kdvm.dll", r"\kdhv1394.dll", r"\kdhvcom.dll", r"\hvloader.exe",
                        r"\pshed.dll", r"\kdstub.dll", r"\winload.exe"]
            for file in filelist:
                self.files.put(sys_dir + file)

            systemsubdirlist = [r"\Drivers", r"\CODEINTEGRITY", r"\CONFIG", r"\CATROOT", r"\CATROOT2", r"\Boot"]
            for subdir in systemsubdirlist:
                self.read_all_file_and_sub_dir(sys_dir + subdir)

            winsubdir = [r"\APPPATCH", r"\RESCACHE", r"\Boot"]
            for subdir in winsubdir:
                self.read_all_file_and_sub_dir(windows_dir + subdir)

            pass
            # self.read_all_file_without_sub_dir(sys_dir)

        except Exception as e:
            self.logger.error(r'read_all_file failed {} {}'.format(e, traceback.format_exc()))
        finally:
            if g_bIs64OS and save_64_value is not None:
                win32file.Wow64RevertWow64FsRedirection(save_64_value)

    def deal_reg_image_path(self, reg_image_path):
        try:
            if reg_image_path[1] == win32con.REG_SZ:
                files = [reg_image_path[0]]
            elif reg_image_path[1] == win32con.REG_EXPAND_SZ:
                files = reg_image_path[0].split('\0')
            else:
                self.logger.warning(r'invalid image path type : {} {}'.format(reg_image_path(1), reg_image_path(0)))
                files = []

            for file in files:
                file_path_upper = file.upper()
                if file_path_upper.startswith("\\SYSTEMROOT\\SYSTEM32\\DRIVERS\\") \
                        or file_path_upper.startswith("SYSTEM32\\DRIVERS\\"):
                    self.logger.info(r'ignore file in drivers {}'.format(file))
                    continue

                self.logger.info(r'deal {}'.format(file))
                if file_path_upper.startswith("\\??\\"):
                    file = file[4:]
                    file_path_upper = file.upper()
                    self.logger.info(r'startswith  \\??\\    {}'.format(file))

                if file_path_upper.startswith("\\SYSTEMROOT"):
                    file = re.sub("\\SYSTEMROOT", "%SYSTEMROOT%", file, 1, re.IGNORECASE)
                if r'%' in file:
                    file = os.path.expandvars(file)
                    self.logger.info(r'expandvars {}'.format(file))
                if file.startswith(r'"') or (not os.path.exists(file)):
                    file_parts = win_CommandLineToArgvW(file)
                    real_file_path = ''
                    for file_part in file_parts:
                        if len(real_file_path) == 0:
                            real_file_path = file_part
                        else:
                            real_file_path += (' ' + file_part)

                        if os.path.isfile(real_file_path):
                            break
                    else:
                        self.logger.info(r'not os.path.exists {}'.format(file))
                        continue
                else:
                    real_file_path = file

                file_path_upper = real_file_path.upper()
                if file_path_upper == 'SVCHOST' or file_path_upper == 'SVCHOST.EXE' or file_path_upper.endswith(
                        r'\SVCHOST.EXE') or file_path_upper.endswith(r'\SVCHOST'):
                    self.logger.info(r'ignore SVCHOST.EXE : {}'.format(file))
                    continue

                self.logger.info(r'will read {} in service'.format(real_file_path))
                self.files.put(real_file_path)
        except Exception as e:
            self.logger.warning(r'deal_reg_image_path ({}) failed {}'.format(reg_image_path, e), exc_info=True)

    def read_service_files(self):
        reg = None
        save_64_value = None
        try:
            if g_bIs64OS:
                save_64_value = win32file.Wow64DisableWow64FsRedirection()

            os.chdir(win32api.GetWindowsDirectory())

            reg = win32api.RegOpenKey(
                win32con.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\services", 0, win32con.KEY_READ)

            num = win32api.RegQueryInfoKey(reg)[0]

            for x in range(0, num):
                sub_reg = None
                svc = None
                try:
                    svc = win32api.RegEnumKey(reg, x)
                    sub_reg = win32api.RegOpenKey(reg, svc, 0, win32con.KEY_READ)
                    reg_image_path = win32api.RegQueryValueEx(sub_reg, 'ImagePath')
                    self.deal_reg_image_path(reg_image_path)
                except Exception as e:
                    self.logger.warning(r'deal sub reg {} ({}) failed {}'.format(x, svc, e), exc_info=True)
                finally:
                    if sub_reg is not None:
                        win32api.RegCloseKey(sub_reg)
        finally:
            if reg is not None:
                win32api.RegCloseKey(reg)
            if g_bIs64OS and save_64_value is not None:
                win32file.Wow64RevertWow64FsRedirection(save_64_value)

    # fix me: 当有软连接回绕的时候，python3.4 有bug。

    def work_real(self):
        self.logger.info("g_bIs64OS = {}".format(g_bIs64OS))
        self.read_all_file()
        self.read_service_files()
        self.files.join()


if __name__ == "__main__":
    Check32Or64OS()
    r = Runner()
    r.work()
