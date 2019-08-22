import os, hashlib, tempfile
import sys
import zipfile
import win32api
import win32con
import win32file
import win32event
import time
import traceback
from myfilesystem import CMyFileSystem

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging


class CBackupDrivers(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'backup_drivers', 190)
        self.devcon_name = "devcon_64.exe"
        self.bIs64 = True
        self.Check32Or64OS()
        self.major, self.min = self.get_ver()
        self.logger.info(r'bIs64OS : {}'.format(self.bIs64))

    def copy_drv_file(self, drv_file):
        system_path = win32api.GetSystemDirectory()
        drv_full_path = system_path + "\\drivers\\" + drv_file
        # 修正热备到华为xen,任务卡在切换IP
        if self.bIs64:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()
        if os.path.exists(drv_full_path):
            self.PreReadAndAdd2Reg(drv_full_path)
        if self.bIs64:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)

    def CopyOemOneDrvInfPnfSysCat(self, driver_file):
        try:
            return_list = list()
            win_path = win32api.GetWindowsDirectory()
            inf_path = win_path + '\\inf'
            inf_file_list = os.listdir(inf_path)
            get_inf_list = list()
            for one in inf_file_list:
                if one.lower().endswith('.inf'):
                    if -1 == one.lower().find('oem'):
                        continue
                    full_path = os.path.join(inf_path, one)
                    print('will read inf = {}'.format(full_path))
                    with open(full_path, 'r') as inf_handle:
                        while True:
                            line = ''
                            try:
                                line = inf_handle.readline()
                                if not line:
                                    break
                                if -1 != line.lower().find(driver_file.lower()):
                                    get_inf_list.append(full_path)
                                    break
                            except:
                                pass
            for inf_full_path in get_inf_list:
                try:
                    inf_file_name = os.path.basename(inf_full_path)
                    search_str, ext = inf_file_name.split('.')
                    pnf_full_path = win_path + '\\inf\\' + search_str + '.pnf'
                    drv_full_path = win_path + '\\system32\\drivers\\' + driver_file
                    cat_full_path = win_path + '\\system32\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\' + search_str + '.cat'
                    return_list.append(inf_full_path)
                    return_list.append(pnf_full_path)
                    return_list.append(drv_full_path)
                    return_list.append(cat_full_path)
                except:
                    pass
            return return_list
        except Exception as e:
            self.logger.error(r'CopyOneDrvInfPnfSysCat driver_file = {} failed. {}'.format(driver_file, e),
                              exc_info=True)
            return []

    def GetWillCopyFileByDir(self, file_list, dir_path, bSearchSub=True):
        try:
            return_list = list()
            if bSearchSub:
                for root, dirs, files in os.walk(dir_path):
                    for file in files:
                        for one in file_list:
                            if file.lower() == one.lower():
                                full_path = os.path.join(root, file)
                                if os.path.isfile(full_path):
                                    return_list.append(full_path)
                                break
            else:
                dir_list = os.listdir(dir_path)
                for file in dir_list:
                    for one in file_list:
                        if file.lower() == one.lower():
                            full_path = os.path.join(dir_path, file)
                            if os.path.isfile(full_path):
                                return_list.append(full_path)
                            break
            return return_list
        except Exception as e:
            self.logger.error(r'GetWillCopyFileByDir file_list = {},dir_path = {},bSearchSub = {}, failed. {}'
                              .format(file_list, dir_path, bSearchSub, e), exc_info=True)
            return []

    def copy_must_file(self):
        if self.bIs64:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()
        self.copy_drv_file("wdfldr.sys")
        self.copy_drv_file("wdf01000.sys")
        # self.copy_drv_file("vdevbus.sys")
        self.copy_drv_file("vms3cap.sys")
        self.copy_drv_file("winhv.sys")

        win_path = win32api.GetWindowsDirectory()
        root_path = os.path.dirname(win_path)
        system_path = win32api.GetSystemDirectory()

        inf_file_path = win_path + '\\inf\\INFCACHE.1'
        self.PreReadAndAdd2Reg_force(inf_file_path)
        inf_file_path = win_path + '\\inf\\infpub.dat'
        self.PreReadAndAdd2Reg_force(inf_file_path)
        inf_file_path = win_path + '\\inf\\infstor.dat'
        self.PreReadAndAdd2Reg_force(inf_file_path)
        inf_file_path = win_path + '\\inf\\infstrng.dat'
        self.PreReadAndAdd2Reg_force(inf_file_path)

        file_path = os.path.join(system_path, 'CatRoot2')
        self.backup_dir_force(file_path)

        # file_path = os.path.join(win_path, 'SoftwareDistribution')
        # self.backup_dir_force(file_path)
        file_path = win_path + '\\SoftwareDistribution\\DataStore\\DataStore.edb'
        self.PreReadAndAdd2Reg_force(file_path)
        file_path = os.path.join(win_path, '{5FD6856A-5D60-474a-9610-9283737FDD1E}')
        self.backup_dir_force(file_path)

        e1k_file_list = ['e1000325.din', 'e1000325.cat', 'e1000325.inf', 'e1000325.pnf', 'e1000325.sys',
                         'e1000msg.dll', 'NicCo2.dll', 'NicInstG.dll']
        get_list = self.GetWillCopyFileByDir(e1k_file_list, system_path, False)
        for one in get_list:
            self.PreReadAndAdd2Reg_force(one)
        get_list = self.GetWillCopyFileByDir(e1k_file_list, os.path.join(system_path, 'ReinstallBackups'), True)
        for one in get_list:
            self.PreReadAndAdd2Reg_force(one)

        Credentials_list = ['Credentials']
        get_list = self.GetWillCopyFileByDir(Credentials_list, os.path.join(root_path, '\\Documents and Settings'),
                                             True)
        for one in get_list:
            self.PreReadAndAdd2Reg_force(one)

        get_list = self.CopyOemOneDrvInfPnfSysCat('e1000325.sys')
        for one in get_list:
            self.PreReadAndAdd2Reg_force(one)

        # self.backup_dir_force(self.logger_dir)
        # self.backup_dir_force(win_path + r'\System32\restore_iso_logger')
        # self.backup_dir_force(win_path + r'\SysWOW64\restore_iso_logger')
        # if self.major < 6:  # xp,2003
        #     file_path = os.path.join(system_path, 'CatRoot2')
        #     self.backup_dir_force(file_path)
        # else:

        dir_path = os.path.join(system_path, 'DriverStore')
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                full_path = os.path.join(root, file)
                if -1 == full_path.upper().find('FILEREPOSITORY'):  # FileRepository 不备份。
                    if os.path.isfile(full_path):
                        self.PreReadAndAdd2Reg_force(full_path)

        if self.bIs64:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)

    def Check32Or64OS(self):
        try:
            sys_info = win32api.GetNativeSystemInfo()
            if sys_info[0] == 0:  # 如果是32位系统 PROCESSOR_ARCHITECTURE_INTEL
                self.devcon_name = "devcon_32.exe"
                self.bIs64 = False
            self.logger.info("devcon name is %s" % self.devcon_name)
        except:
            self.logger.error(traceback.format_exc())

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

    def _MD5(self, src):
        m2 = hashlib.md5()
        m2.update(src.encode('utf-8'))
        return m2.hexdigest()

    def get_driverfiles_by_reg(self, instance, file_list):
        try:
            self.logger.info(r'get_driverfiles_by_reg begin, instance = {}'.format(instance))
            # 检查注册表驱动项看驱动是否正常安装。
            Driver_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                             "SYSTEM\\CurrentControlSet\\Enum\\" + instance, 0, win32con.KEY_READ)
            Driver_value, type = win32api.RegQueryValueEx(Driver_key, 'Driver')
            self.logger.info(r'get_driverfiles_by_reg Driver_value = {}'.format(Driver_value))
            Service_value, type = win32api.RegQueryValueEx(Driver_key, 'Service')
            self.logger.info(r'get_driverfiles_by_reg Service_value = {}'.format(Service_value))
            class_open_key_str = "SYSTEM\\CurrentControlSet\\Control\\Class\\" + Driver_value
            Class_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, class_open_key_str, 0, win32con.KEY_READ)
            InfPath_value, type = win32api.RegQueryValueEx(Class_key, 'InfPath')
            self.logger.info(r'get_driverfiles_by_reg InfPath_value = {}'.format(InfPath_value))

            serv_open_key_str = "SYSTEM\\CurrentControlSet\\Services\\" + Service_value
            Serv_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, serv_open_key_str, 0, win32con.KEY_READ)
            ImagePath_value, type = win32api.RegQueryValueEx(Serv_key, 'ImagePath')
            self.logger.info(r'get_driverfiles_by_reg ImagePath_value = {}'.format(ImagePath_value))

            win_dir = win32api.GetWindowsDirectory()
            Image_full_path = win_dir + '\\' + ImagePath_value
            self.logger.info(r'get_driverfiles_by_reg Image_full_path = {}'.format(Image_full_path))
            if os.path.exists(Image_full_path):
                file_list.append(Image_full_path)
            else:
                self.logger.info(r'get_driverfiles_by_reg err, Image_full_path = {}'.format(Image_full_path))
                win32api.RegCloseKey(Serv_key)
                win32api.RegCloseKey(Class_key)
                win32api.RegCloseKey(Driver_key)
                return ''
            win32api.RegCloseKey(Serv_key)
            win32api.RegCloseKey(Class_key)
            win32api.RegCloseKey(Driver_key)
            Inf_full_path = win_dir + '\\inf\\' + InfPath_value
            self.logger.info(r'get_driverfiles_by_reg Inf_full_path = {}'.format(Inf_full_path))
            return Inf_full_path
        except Exception as e:
            self.logger.error(r'get_driverfiles_by_reg {} failed.'.format(instance), exc_info=True)
            return ''

    def devcon_driverfiles(self, id):
        ret = {"id": "", "name": "", "inf": "", "files": list()}
        cmd = '{} driverfiles "{}"'.format(self.devcon_name, id)
        for retry in range(3):
            code, out_put_lines = self.show_and_exe_cmd_line_and_get_ret(cmd)
            i = -1
            instance = None
            for one_line in out_put_lines:
                one_line = one_line.strip()
                if instance is None:
                    instance = one_line
                if one_line == '--dump_begin--':
                    i = 0
                    continue
                if one_line == '--dump___end--':
                    break
                if i == -1:
                    continue

                if i == 0:
                    ret['id'] = one_line
                elif i == 1:
                    ret['name'] = one_line
                elif i == 2:
                    ret['inf'] = one_line
                elif i > 2:
                    ret["files"].append(one_line)
                i = i + 1
            if 0 != len(ret["files"]):
                self.logger.info(r'get_driverfiles_by_reg 0 != len(ret["files"]) , break.')
                break
            else:
                self.logger.info(r'get_driverfiles_by_reg 0 == len(ret["files"]) , retry!')
                time.sleep(1)
                continue
        if 0 == len(ret["files"]):
            # 某些驱动，比如Vmware pvscsi 的驱动，系统不能正常显示出来。需要自己查找安装。
            ret['inf'] = self.get_driverfiles_by_reg(instance, ret['files'])

        return ret

    def backup_driverfiles(self, id, path):
        myFileSystem = CMyFileSystem()
        if myFileSystem.disk_num == -1:
            raise Exception('backup_driverfiles Failed.myFileSystem.disk_num == -1')
        if self.bIs64:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()
        listfile = os.path.join(path, 'filelist.bat')
        if os.path.isfile(listfile) and len(listfile) > 12:
            os.remove(listfile)
        files = self.devcon_driverfiles(id)
        zipname = '{}.zip'.format(self._MD5(files["id"]))
        if myFileSystem.IsFileNameExist(zipname):
            if self.bIs64:
                win32file.Wow64RevertWow64FsRedirection(save_64_value)
            return
        file_object = open(listfile, 'a')
        file_object.write("rem ")
        file_object.write(files["id"])
        zipfilepath = os.path.join(path, zipname)
        file_object.write('\r\n')
        file_object.write("rem ")
        file_object.write(files["name"])
        file_object.write('\r\n')
        file_object.write("rem ")
        file_object.write(files["inf"])
        file_object.write('\r\n')
        z = zipfile.ZipFile(zipfilepath, 'w')
        for file in files["files"]:
            if os.path.isfile(file):
                basename = os.path.basename(file)
                cmd = r'if not exist "{}" (copy /Y "{}" "{}")'.format(file, basename, file)
                file_object.write(cmd)
                z.write(file, basename)
            else:
                err_str = 'backup_driverfiles Failed.id={},file={}'.format(id, file)
                file_object.write('rem {}'.format(err_str))
                self.logger.error(err_str)
            file_object.write('\r\n')
        file_object.close()
        z.write(listfile, 'filelist.bat')
        z.close()
        os.remove(listfile)
        myFileSystem.addOneFile(zipfilepath)
        os.remove(zipfilepath)

        if self.bIs64:
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
                return True
            return False
        except Exception as e:
            self.logger.error(r'read_bin_file_no_print_context {} failed. {}'.format(file_path, e), exc_info=True)
            return False

    def add2reg(self, file):
        hMutex = win32event.CreateMutex(None, False, 'Global\\ClerwareBackUpFile')
        if hMutex is None:
            self.logger.error('can not create mutex Global\\ClerwareBackUpFile')
            return
        win32event.WaitForSingleObject(hMutex, win32event.INFINITE)
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
            self.logger.debug(traceback.format_exc())
        win32event.ReleaseMutex(hMutex)
        win32api.CloseHandle(hMutex)

    def PreReadAndAdd2Reg(self, file):
        if self.read_bin_file_no_print_context(file):
            self.add2reg(file)  # 预读成功了才加入注册表

    def PreReadAndAdd2Reg_force(self, file):
        self.read_bin_file_no_print_context(file)
        self.add2reg(file)  # 预读成功了才加入注册表

    def clear_reg(self):
        filelist_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                           "SYSTEM\\CurrentControlSet\\Services\\disksbd\\Parameters",
                                           0,
                                           win32con.KEY_ALL_ACCESS)
        try:
            win32api.RegQueryValueEx(filelist_key, "HotReadyReserveFileList")
        except:
            win32api.RegCloseKey(filelist_key)
            return
        win32api.RegSetValueEx(filelist_key, "HotReadyReserveFileList", 0, win32con.REG_MULTI_SZ, list())
        win32api.RegCloseKey(filelist_key)

    def OneInfToCatLis(self, one_inf):
        try:
            ret_list = []
            if one_inf is None:
                return ret_list
            inf_base_name = os.path.basename(one_inf)
            cat_name = os.path.splitext(inf_base_name)[0] + ".cat"
            system_dir = win32api.GetSystemDirectory()

            for root, dirs, files in os.walk(system_dir + '\\CatRoot'):
                for name in files:
                    if name.upper() == cat_name.upper():
                        ret_list.append(os.path.join(root, name))
            for root, dirs, files in os.walk(system_dir + '\\catroot2'):
                for name in files:
                    if name.upper() == cat_name.upper():
                        ret_list.append(os.path.join(root, name))
            return ret_list
        except:
            self._logger.debug(traceback.format_exc())
            return []

    def OneDrvToDriverStore(self, one_drv):
        DriverStoreList = list()
        try:
            if self.major < 6:  # xp,2003
                return DriverStoreList

            # 有可能有多个相同的驱动文件，只是目录名不同。
            drv_name = os.path.basename(one_drv)
            system_path = win32api.GetSystemDirectory()
            dir_path = os.path.join(system_path, 'DriverStore')
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    if file.lower() == drv_name.lower():
                        file_list = os.listdir(root)
                        for one_file in file_list:
                            DriverStoreList.append(os.path.join(root, one_file))

            return DriverStoreList
        except:
            self._logger.debug(traceback.format_exc())
            return DriverStoreList

    def OneInfToPnf(self, one_inf):
        try:
            ret_str = ''
            inf_dir = os.path.dirname(one_inf)
            inf_file_name = os.path.basename(one_inf)
            inf_name, inf_ext = os.path.splitext(inf_file_name)
            pnf_name = inf_name + '.pnf'
            return os.path.join(inf_dir, pnf_name)
        except:
            self._logger.debug(traceback.format_exc())
            return ''

    def backup_driverfiles_reg(self, id):
        if self.bIs64:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()
        files = self.devcon_driverfiles(id)
        for file in files["files"]:
            if os.path.isfile(file):
                self.PreReadAndAdd2Reg(file)
                if file.lower().endswith('.sys'):
                    DriverStoreList = self.OneDrvToDriverStore(file)
                    for one_driver_store in DriverStoreList:
                        self.PreReadAndAdd2Reg(one_driver_store)

            else:
                err_str = 'backup_driverfiles_reg Failed.id={},file={}'.format(id, file)
                self.logger.error(err_str)
        self.PreReadAndAdd2Reg(files["inf"])

        pnf_path = self.OneInfToPnf(files["inf"])
        self.PreReadAndAdd2Reg(pnf_path)

        cat_list = self.OneInfToCatLis(files["inf"])
        for one_cat in cat_list:
            self.PreReadAndAdd2Reg(one_cat)

        if self.bIs64:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)

    def backup_dir_force(self, file_path):
        try:
            if self.bIs64:
                save_64_value = win32file.Wow64DisableWow64FsRedirection()
            for root, dirs, files in os.walk(file_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path):
                        self.PreReadAndAdd2Reg_force(file_path)
            if self.bIs64:
                win32file.Wow64RevertWow64FsRedirection(save_64_value)
        except:
            print(traceback.format_exc())
            self._logger.debug(traceback.format_exc())


def backup_driverfiles_disk(hardward_id_list):
    # 不再使用，老流程，保存到硬盘中
    for id in hardward_id_list:
        path = tempfile.mkdtemp("backup_drivers")
        CBackupDrivers().backup_driverfiles(id, path)


def backup_driverfiles_reg(hardward_id_list):
    for id in hardward_id_list:
        CBackupDrivers().backup_driverfiles_reg(id)


def backup_driverfiles(hardward_id_list):
    # backup_driverfiles_disk(hardward_id_list)
    backup_driverfiles_reg(hardward_id_list)


if __name__ == "__main__":
    CBackupDrivers().clear_reg()
    CBackupDrivers().copy_must_file()
    # backup_driverfiles([r'PCI\VEN_10EC&DEV_8168&SUBSYS_10011D05&REV_12'])
