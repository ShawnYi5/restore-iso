import os
import sys
import threading
import time
import traceback

import win32event
import win32api
import win32con
import win32gui
import win32process
import win32file
import shutil
from pywin32_testutil import str2bytes

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging

_logger = xlogging.getLogger('install_dev_org')

# def devcon_install_dev(instance_id, inf_path):
#     try:
#         os.system('devcon dp_add ' + inf_path)
#         os.system('devcon rescan')
#         while True:
#             output = os.popen('devcon.exe status ' + "\"@" + instance_id + "\"")
#             output_str=output.read()
#             _logger.info(output_str)
#             if -1 != output_str.find('Driver is running'):
#                 break;
#     except:
#         _logger.error(traceback.format_exc())

g_devcon_name = "devcon_64.exe"
g_b_devcon_install_dev_and_click_dialog_thread_run = True
g_bIsXenV1 = False
g_bIsXenV2 = False


def enmu_window(parent_handle, class_name, window_name):
    try:
        handle = win32gui.GetWindow(parent_handle, win32con.GW_CHILD)
        if 0 == handle:
            return handle
        if class_name == win32gui.GetClassName(handle) and window_name == win32gui.GetWindowText(handle):
            return handle
        ret = enmu_window(handle, class_name, window_name)
        if 0 != ret:
            return ret

        while 0 != handle:
            handle = win32gui.GetWindow(handle, win32con.GW_HWNDNEXT)
            if 0 == handle:
                return handle
            if class_name == win32gui.GetClassName(handle) and window_name == win32gui.GetWindowText(handle):
                return handle
            ret = enmu_window(handle, class_name, window_name)
            if 0 != ret:
                return ret
        return 0
    except:
        _logger.error(traceback.format_exc())
        return 0


def show_and_exe_cmd_line_and_get_ret(in_cmd_line, chk_err_str='', bPrint=True):
    try:
        cmd_line = in_cmd_line + ' 2>&1'
        if bPrint:
            _logger.debug(cmd_line)
        with os.popen(cmd_line) as out_put:
            out_put_lines = out_put.readlines()
            if '' == chk_err_str:
                if bPrint:
                    _logger.debug('0')
                    _logger.debug(out_put_lines)
                return 0, out_put_lines
            for one_line in out_put_lines:
                if -1 != one_line.find(chk_err_str):
                    if bPrint:
                        _logger.debug('show_and_exe_cmd_line_and_get_ret return -1')
                    return -1, []
        if bPrint:
            _logger.debug('0')
            _logger.debug(out_put_lines)
        return 0, out_put_lines
    except:
        if bPrint:
            _logger.debug(traceback.format_exc())
            _logger.debug('show_and_exe_cmd_line_and_get_ret excption return -1')
        return -1, []


def get_cat_ver():
    try:
        ret, lines = show_and_exe_cmd_line_and_get_ret(os.path.join(current_dir, 'NewCatName.exe'))
        for one in lines:
            if 0 == one.find('err:'):
                return ''
            return one
    except:
        _logger.debug(traceback.format_exc())
    return ''


def get_cat_used_ver():
    try:
        cat_ver_full_str = get_cat_ver()
        if 0 != len(cat_ver_full_str):
            return cat_ver_full_str[0:len(cat_ver_full_str) - 3]
        return ''
    except:
        _logger.debug(traceback.format_exc())
    return ''


def set_reg_value(key, subKey, valueName, type, value):
    try:
        hKey = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
        win32api.RegSetValueEx(hKey, valueName, 0, type, value)
        win32api.RegCloseKey(hKey)
    except:
        _logger.error(traceback.format_exc())


class TimerThread(threading.Thread):
    def __init__(self):
        super(TimerThread, self).__init__()
        self._Run = True

    def run(self):
        while self._Run:
            with open(CleanFile.FlAG_FILE_PATH, 'w') as f:
                pass
            time.sleep(5)

    def stop(self):
        self._Run = False


class c_devcon_install_dev_and_click_dialog(threading.Thread):
    def __init__(self, parent_class_name, parent_window_name, sub_class_name, sub_window_name):
        threading.Thread.__init__(self)
        self.parent_class_name = parent_class_name
        self.parent_window_name = parent_window_name
        self.sub_class_name = sub_class_name
        self.sub_window_name = sub_window_name

    def run(self):
        global g_b_devcon_install_dev_and_click_dialog_thread_run
        try:
            while g_b_devcon_install_dev_and_click_dialog_thread_run:
                parent_handle = win32gui.FindWindow(self.parent_class_name, self.parent_window_name)
                # if None != parent_handle: 查找不到会出异常自己跳出。

                # 查找窗体按钮
                hWnd = enmu_window(parent_handle, self.sub_class_name, self.sub_window_name)
                if 0 == hWnd:
                    _logger.info("not find window")
                else:
                    _logger.info("find window = 0x%x" % hWnd)
                    try:
                        win32gui.SetForegroundWindow(parent_handle)
                    except:
                        pass
                    win32gui.PostMessage(hWnd, win32con.WM_LBUTTONDOWN, 0, 0)
                    win32gui.PostMessage(hWnd, win32con.WM_LBUTTONUP, 0, 0)
                    _logger.info("click hwnd = 0x%x" % hWnd)
                time.sleep(1)
        except:
            _logger.error(traceback.format_exc())


# class c_set_need_file_dlg_and_click_dialog(threading.Thread):
#     def __init__(self, inf_dir, parent_class_name, parent_window_name, sub_class_name, sub_window_name):
#         threading.Thread.__init__(self)
#         self.inf_dir = inf_dir
#         self.parent_class_name = parent_class_name
#         self.parent_window_name = parent_window_name
#         self.sub_class_name = sub_class_name
#         self.sub_window_name = sub_window_name
#
#     def run(self):
#         global g_b_devcon_install_dev_and_click_dialog_thread_run
#         try:
#             while g_b_devcon_install_dev_and_click_dialog_thread_run:
#                 parent_handle = win32gui.FindWindow(self.parent_class_name, self.parent_window_name)
#                 # if None != parent_handle: 查找不到会出异常自己跳出。
#
#                 # 查找窗体按钮
#                 hWnd = enmu_window(parent_handle, 'Edit', '')
#                 if 0 == hWnd:
#                     _logger.info("c_set_need_file_dlg_and_click_dialog not find window edit")
#                 else:
#                     _logger.info("c_set_need_file_dlg_and_click_dialog find window edit = 0x%x" % hWnd)
#                     try:
#                         win32gui.SetForegroundWindow(parent_handle)
#                     except:
#                         pass
#                     win32gui.SendMessage(hWnd, win32con.WM_SETTEXT,0,self.inf_dir)
#                     # win32gui.SetWindowText(hWnd, self.inf_path)
#                     _logger.info("c_set_need_file_dlg_and_click_dialog SetWindowText hwnd = 0x%x" % hWnd)
#                 time.sleep(1)
#                 # 查找窗体按钮
#                 hWnd = enmu_window(parent_handle, self.sub_class_name, self.sub_window_name)
#                 if 0 == hWnd:
#                     _logger.info("c_set_need_file_dlg_and_click_dialog not find ok window")
#                 else:
#                     _logger.info("c_set_need_file_dlg_and_click_dialog find ok window = 0x%x" % hWnd)
#                     try:
#                         win32gui.SetForegroundWindow(parent_handle)
#                     except:
#                         pass
#                     win32gui.PostMessage(hWnd, win32con.WM_LBUTTONDOWN, 0, 0)
#                     win32gui.PostMessage(hWnd, win32con.WM_LBUTTONUP, 0, 0)
#                     _logger.info("c_set_need_file_dlg_and_click_dialog click ok hwnd = 0x%x" % hWnd)
#                 time.sleep(1)
#         except:
#             _logger.error(traceback.format_exc())


def inst_cer(inf_path):
    try:
        inf_dir = os.path.dirname(inf_path)
        for file in os.listdir(inf_dir):
            if file.lower().endswith('.cer'):
                load_cer_str = "CertMgr.exe /add " + inf_dir + "\\" + file + " /s /r localMachine trustedpublisher"
                os.system(load_cer_str)
    except:
        _logger.error(traceback.format_exc())


def safe_reg_chk_one_value(key, subkey, value_name):
    Driver_key = None
    try:
        if key is None or subkey is None or value_name is None:
            return False
        if 0 == len(subkey) or 0 == len(value_name):
            return False
        Driver_key = win32api.RegOpenKey(key, subkey, 0, win32con.KEY_READ)
        value_value = win32api.RegQueryValueEx(Driver_key, value_name)
        if value_value[0] == '':
            return False
        win32api.RegCloseKey(Driver_key)
        return True
    except:
        try:
            if Driver_key is not None:
                win32api.RegCloseKey(Driver_key)
        except:
            pass
        return False


def chk_reg_start_is_ok(harward_id):
    try:
        _logger.info("chk_reg_start_is_ok begin harward_id={}".format(harward_id))
        hardward_id_list = list()
        hardward_id_list.append(harward_id)
        wait_instance_ok_by_hardward_id_list(hardward_id_list)
        all_id_instance_path_list = get_all_instance_path_by_devcon_by_hardward_id_list(hardward_id_list)

        if 0 == len(all_id_instance_path_list):
            return False
        for one_instance_path in all_id_instance_path_list:
            Ret = safe_reg_chk_one_value(win32con.HKEY_LOCAL_MACHINE,
                                         "SYSTEM\\CurrentControlSet\\Enum\\" + one_instance_path, 'Driver')
            if Ret is False:
                return False
        return True
    except:
        _logger.error(traceback.format_exc())
        return False


def clean_dir_attrib(dir_path):
    try:
        system_path = win32api.GetSystemDirectory()
        for root, dirs, files in os.walk(dir_path):
            cmd_str = '{}\\cmd.exe /c attrib -R -S -H "{}"'.format(system_path, root)
            show_and_exe_cmd_line_and_get_ret(cmd_str)
            for file in files:
                file_path = os.path.join(root, file)
                cmd_str = '{}\\cmd.exe /c attrib -R -S -H "{}"'.format(system_path, file_path)
                show_and_exe_cmd_line_and_get_ret(cmd_str)
    except:
        _logger.error(traceback.format_exc())


def safe_del_dir(dir_path):
    try:
        while True:
            try:
                _logger.info('will del dir_path={}'.format(dir_path))
                shutil.rmtree(dir_path)
                _logger.info('have del dir_path={}'.format(dir_path))
            except:
                _logger.info('can not del path={}'.format(dir_path))
            if os.path.exists(dir_path):
                _logger.info('can not del path={},retry'.format(dir_path))
                clean_dir_attrib(dir_path)
                time.sleep(1)
            else:
                _logger.info('safe_del_dir del path={},success!'.format(dir_path))
                break
    except:
        _logger.error(traceback.format_exc())


def install_drv(inf_path, harward_id):
    try:
        _logger.info("install_drv begin")
        show_and_exe_cmd_line_and_get_ret(g_devcon_name + " update \"" + inf_path + "\" \"" + harward_id + "\"")
        _logger.info("install_drv end")
    except:
        _logger.error(traceback.format_exc())


def safe_copytree(src_dir, des_dir):
    try:
        safe_del_dir(des_dir)
        while True:
            try:
                _logger.info('safe_copytree will copy src_dir={} des_dir={}'.format(src_dir, des_dir))
                shutil.copytree(src_dir, des_dir)
                _logger.info('safe_copytree have copy src_dir={} des_dir={}'.format(src_dir, des_dir))
            except:
                _logger.info('safe_copytree can not copy src_dir={} des_dir={}'.format(src_dir, des_dir))
            if not os.path.exists(des_dir):
                _logger.info(
                    'safe_copytree can not copy 2 src_dir={} des_dir={}，will sleep and retry'.format(src_dir, des_dir))
                time.sleep(1)
            else:
                _logger.info('safe_copytree copy src_dir={} des_dir={},success'.format(src_dir, des_dir))
                clean_dir_attrib(des_dir)
                break
    except:
        _logger.error(traceback.format_exc())


def copy_dir_and_install_drv(inf_path, harward_id):
    try:
        _logger.info("copy_dir_and_install_drv begin")
        inf_tmp_path = inf_path.replace('/', '\\')
        inf_full_path = os.path.join(current_dir, inf_tmp_path)
        src_dir = os.path.dirname(inf_full_path)
        win_tmp_dir = win32api.GetWindowsDirectory()
        _logger.info("copy_dir_and_install_drv win_tmp_dir={}".format(win_tmp_dir))
        tmp_des_dir = os.path.join(win_tmp_dir, '{5FD6856A-5D60-474a-9610-9283737FDD1E}')
        _logger.info("copy_dir_and_install_drv will del tmp_des_dir={}".format(tmp_des_dir))
        safe_copytree(src_dir, tmp_des_dir)
        _logger.info("copy_dir_and_install_drv have copy dir src={},des={}".format(src_dir, tmp_des_dir))
        inf_tmp_des_path = os.path.join(tmp_des_dir, os.path.basename(inf_full_path))
        show_and_exe_cmd_line_and_get_ret(g_devcon_name + " update \"" + inf_tmp_des_path + "\" \"" + harward_id + "\"")
        _logger.info("copy_dir_and_install_drv end")
    except:
        _logger.error(traceback.format_exc())


def start_all_push_button_thread():
    global g_b_devcon_install_dev_and_click_dialog_thread_run
    try:
        thread_list = list()
        g_b_devcon_install_dev_and_click_dialog_thread_run = True
        # win 7
        click_thread_1 = c_devcon_install_dev_and_click_dialog("#32770",
                                                               "Windows 安全", "Button", "始终安装此驱动程序软件(&I)")
        click_thread_1e = c_devcon_install_dev_and_click_dialog("#32770",
                                                                "Windows Security", "Button",
                                                                "&Install this driver software anyway")
        click_thread_1f = c_devcon_install_dev_and_click_dialog("#32770",
                                                               "Windows 安全中心", "Button", "始终安装此驱动程序软件(&I)")
        # serv 2008 -- win 10
        click_thread_2 = c_devcon_install_dev_and_click_dialog("#32770",
                                                               "Windows 安全", "Button", "安装(&I)")
        click_thread_2e = c_devcon_install_dev_and_click_dialog("#32770",
                                                                "Windows Security", "Button", "&Install")
        click_thread_2f = c_devcon_install_dev_and_click_dialog("#32770",
                                                               "Windows 安全中心", "Button", "安装(&I)")
        # xp
        # setupapi > dialog > 2316
        click_thread_3 = c_devcon_install_dev_and_click_dialog("#32770",
                                                               "软件安装", "Button", "仍然继续(&C)")
        click_thread_3e = c_devcon_install_dev_and_click_dialog("#32770",
                                                                "Software Installation", "Button", "&Continue Anyway")
        # setupapi > dialog > 2317
        click_thread_31 = c_devcon_install_dev_and_click_dialog("#32770",
                                                                "软件安装", "Button", "确定")
        click_thread_31e = c_devcon_install_dev_and_click_dialog("#32770",
                                                                 "Software Installation", "Button", "OK")
        # serv 2003
        # setupapi > dialog > 2318,2319,2320,2321 dialog caption相同, 按钮相同, 提示内容不同
        click_thread_4 = c_devcon_install_dev_and_click_dialog("#32770",
                                                               "安全警报 - 驱动程序安装", "Button", "是(&Y)")
        click_thread_4e = c_devcon_install_dev_and_click_dialog("#32770",
                                                                "Security Alert - Driver Installation", "Button",
                                                                "&Yes")

        # setupapi > dialog > 2314, 没有通过 Windows 徽标测试，无法验证它同此 Windows 版本的兼容性。 您想继续为此硬件安装软件吗?
        click_thread_5 = c_devcon_install_dev_and_click_dialog("#32770",
                                                               "硬件安装", "Button", "仍然继续(&C)")
        click_thread_5e = c_devcon_install_dev_and_click_dialog("#32770",
                                                                "Hardware Installation", "Button", "&Continue Anyway")
        # setupapi > dialog > 2315, 没有通过 Windows 徽标测试，无法验证它同此 Windows 版本的兼容性。将不会安装硬件。请同系统管理员联系。
        click_thread_51 = c_devcon_install_dev_and_click_dialog("#32770",
                                                                "硬件安装", "Button", "确定")
        click_thread_51e = c_devcon_install_dev_and_click_dialog("#32770",
                                                                 "Hardware Installation", "Button", "OK")
        # setupapi > dialog > 400
        click_thread_6 = c_devcon_install_dev_and_click_dialog("#32770",
                                                               "确认文件替换", "Button", "是(&Y)")
        click_thread_6e = c_devcon_install_dev_and_click_dialog("#32770",
                                                                "Confirm File Replace", "Button", "&Yes")
        # setupapi > dialog > 2315
        click_thread_7 = c_devcon_install_dev_and_click_dialog("#32770",
                                                               "所需文件", "Button", "取消")
        click_thread_7e = c_devcon_install_dev_and_click_dialog("#32770",
                                                                "Files Needed", "Button", "Cancel")

        # setupapi > dialog > 5330
        click_thread_8 = c_devcon_install_dev_and_click_dialog("#32770",
                                                               "不兼容的硬件或软件", "Button", "取消")
        click_thread_8e = c_devcon_install_dev_and_click_dialog("#32770",
                                                                "Incompatible Hardware or Software", "Button", "Cancel")

        # setupapi > dialog > 57
        click_thread_9 = c_devcon_install_dev_and_click_dialog("#32770",
                                                               "选择设备", "Button", "取消")
        click_thread_9e = c_devcon_install_dev_and_click_dialog("#32770",
                                                                "Select Device", "Button", "Cancel")

        # setupapi > dialog > 200
        click_thread_10 = c_devcon_install_dev_and_click_dialog("#32770",
                                                                "文件错误", "Button", "取消")
        click_thread_10e = c_devcon_install_dev_and_click_dialog("#32770",
                                                                 "File Error", "Button", "Cancel")

        # click_thread_7 = c_devcon_install_dev_and_click_dialog(inf_path, "#32770",
        #                                                        "插入磁盘", "Button", "确定")
        click_thread_1.start()
        thread_list.append(click_thread_1)
        click_thread_1e.start()
        thread_list.append(click_thread_1e)
        click_thread_1f.start()
        thread_list.append(click_thread_1f)
        click_thread_2.start()
        thread_list.append(click_thread_2)
        click_thread_2e.start()
        thread_list.append(click_thread_2e)
        click_thread_2f.start()
        thread_list.append(click_thread_2f)
        click_thread_3.start()
        thread_list.append(click_thread_3)
        click_thread_3e.start()
        thread_list.append(click_thread_3e)
        click_thread_31.start()
        thread_list.append(click_thread_31)
        click_thread_31e.start()
        thread_list.append(click_thread_31e)
        click_thread_4.start()
        thread_list.append(click_thread_4)
        click_thread_4e.start()
        thread_list.append(click_thread_4e)
        click_thread_5.start()
        thread_list.append(click_thread_5)
        click_thread_5e.start()
        thread_list.append(click_thread_5e)
        click_thread_51.start()
        thread_list.append(click_thread_51)
        click_thread_51e.start()
        thread_list.append(click_thread_51e)
        click_thread_6.start()
        thread_list.append(click_thread_6)
        click_thread_6e.start()
        thread_list.append(click_thread_6e)
        click_thread_7.start()
        thread_list.append(click_thread_7)
        click_thread_7e.start()
        thread_list.append(click_thread_7e)
        click_thread_8.start()
        thread_list.append(click_thread_8)
        click_thread_8e.start()
        thread_list.append(click_thread_8e)
        click_thread_9.start()
        thread_list.append(click_thread_9)
        click_thread_9e.start()
        thread_list.append(click_thread_9e)
        click_thread_10.start()
        thread_list.append(click_thread_10)
        click_thread_10e.start()
        thread_list.append(click_thread_10e)

        return thread_list
    except:
        _logger.error(traceback.format_exc())


def wait_stop_all_push_button_thread(thread_list):
    global g_b_devcon_install_dev_and_click_dialog_thread_run
    try:
        g_b_devcon_install_dev_and_click_dialog_thread_run = False
        for one_thread in thread_list:
            one_thread.join()
    except:
        _logger.error(traceback.format_exc())


def devcon_install_dev(harward_id, inf_path, bForce=False, bCopyToTmpDir=True):
    try:
        inst_cer(inf_path)
        wait_instance_ok_by_one_hardward_id(harward_id)
        if bForce is False:  # 强制安装就不要求检查注册表。
            bRet = chk_reg_start_is_ok(harward_id)
            if bRet is True:
                _logger.info("devcon_install_dev chk_reg_start_is_ok is True")
                return

        thread_list = start_all_push_button_thread()

        if bCopyToTmpDir is True:
            copy_dir_and_install_drv(inf_path, harward_id)
        else:
            install_drv(inf_path, harward_id)

        wait_stop_all_push_button_thread(thread_list)

        _logger.info("f_devcon_install_dev_and_click_dialog install end")
    except:
        _logger.error(traceback.format_exc())


def safe_devcon_install_dev(harward_id, inf_list, bForce=False):
    try:
        while True:
            for one_inf in inf_list:
                devcon_install_dev(harward_id, one_inf, bForce)
            if chk_reg_start_is_ok(harward_id):
                break
            _logger.info(
                "safe_devcon_install_dev chk_reg_start_is_ok failed ,retry harward_id={},inf_list={}".format(harward_id,
                                                                                                             inf_list))
            time.sleep(1)
    except:
        _logger.error(traceback.format_exc())


# def dism_insall_dev(inf_path):
#     try:
#         os.system('dism /Online /Add-driver /Driver:' + inf_path)
#     except:
#         _logger.error(traceback.format_exc())


def cur_file_dir():
    return current_dir


def Check32Or64OS():
    global g_devcon_name
    try:
        sys_info = win32api.GetNativeSystemInfo()
        if sys_info[0] == 0:  # 如果是32位系统 PROCESSOR_ARCHITECTURE_INTEL
            g_devcon_name = "devcon_32.exe"
            return False
        _logger.info("devcon name is %s" % g_devcon_name)
        return True
    except:
        _logger.error(traceback.format_exc())
        return False


def get_all_instance_path_by_devcon_by_one_hardward_id(one_hardward_id):
    out_instance_path_list = []
    _logger.info('get_all_instance_path_by_devcon_by_one_hardward_id one_hardward_id={}'.format(one_hardward_id))
    try:
        output = os.popen(g_devcon_name + ' hwids \"' + one_hardward_id + "\"")
        list_line = output.readlines()
        for one_line in list_line:
            _logger.info(one_line)
            if one_line[0] != ' ':
                if one_line.find('&') != -1:
                    if one_line[-1] == '\n':
                        one_line = one_line[0:len(one_line) - 1]
                    out_instance_path_list.append(one_line)
        return out_instance_path_list
    except:
        _logger.error(traceback.format_exc())
        return out_instance_path_list


def get_all_instance_path_by_devcon_by_hardward_id_list(hardward_id_list):
    all_id_instance_path_list = []
    try:
        for one_hardward_id in hardward_id_list:
            one_list = get_all_instance_path_by_devcon_by_one_hardward_id(one_hardward_id)
            for i in one_list:
                bFindInAll = False
                for j in all_id_instance_path_list:
                    if i == j:
                        bFindInAll = True
                        break
                if not bFindInAll:
                    all_id_instance_path_list.append(i)
        all_id_instance_path_list.sort()
        return all_id_instance_path_list
    except:
        _logger.error(traceback.format_exc())
        return all_id_instance_path_list


def wait_instance_ok_by_one_hardward_id(hardward_id):
    try:
        while True:
            one_list = get_all_instance_path_by_devcon_by_one_hardward_id(hardward_id)
            if 0 != len(one_list):  # 找到instance
                return
            # 没有找到一个 instance ,等待。
            _logger.info(
                "wait_instance_ok_by_one_hardward_id not find instance,wait hardward_id = {}".format(hardward_id))
            os.system(g_devcon_name + ' rescan')
            time.sleep(1)
    except:
        _logger.error(traceback.format_exc())


def wait_instance_ok_by_hardward_id_list(hardward_id_list):
    try:
        while True:
            for one_hardward_id in hardward_id_list:
                one_list = get_all_instance_path_by_devcon_by_one_hardward_id(one_hardward_id)
                if 0 != len(one_list):  # 找到instance
                    return
            # 没有找到一个 instance ,等待。
            _logger.info("wait_instance_ok_by_hardward_id_list not find instance,wait hardward_id_list = {}".format(
                hardward_id_list))
            os.system(g_devcon_name + ' rescan')
            time.sleep(1)
    except:
        _logger.error(traceback.format_exc())

def chk_is_xen_v2_winhong(hardward_id_list):
    for one_id in hardward_id_list:
        if -1 != one_id.upper().find(r'PCI\VEN_5853&DEV_0002'):
            return True
    return False

def chk_reg_is_ok(hardward_id_list, bTimeOut=False):
    try:
        _logger.info("chk_reg_is_ok begin hardward_id_list={}".format(hardward_id_list))
        if chk_is_xen_v2_winhong(hardward_id_list):
            _logger.info("chk_reg_is_ok chk_is_xen_v2_winhong exit")
            return
        wait_instance_ok_by_hardward_id_list(hardward_id_list)
        all_id_instance_path_list = get_all_instance_path_by_devcon_by_hardward_id_list(hardward_id_list)

        num = 0
        for one_instance_path in all_id_instance_path_list:
            while True:
                Ret = safe_reg_chk_one_value(win32con.HKEY_LOCAL_MACHINE,
                                             "SYSTEM\\CurrentControlSet\\Enum\\" + one_instance_path, 'Driver')
                if Ret is False:
                    _logger.info("{},is no Service reg sleep one second and retry!".format(
                        "SYSTEM\\CurrentControlSet\\Enum\\" + one_instance_path))
                    time.sleep(1)
                    num += 1
                    if bTimeOut:
                        if num >= 25:
                            return
                else:
                    break

        instance_set = set()
        for one_instance_path in all_id_instance_path_list:
            find_num = one_instance_path.rfind('\\')
            if -1 != find_num:
                instance_set.add((one_instance_path[:find_num].upper(), one_instance_path[find_num + 1:].upper()))

        reg_set = set()
        for hwid_str, rand_str in instance_set:
            hwidpath = 'SYSTEM\\CurrentControlSet\\Enum\\' + hwid_str
            main_key = None
            try:
                main_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, hwidpath, 0, win32con.KEY_READ)
                size = win32api.RegQueryInfoKey(main_key)[0]
                # 遍历子项
                for i in range(size):
                    subkey_str = win32api.RegEnumKey(main_key, i)
                    reg_set.add((hwid_str, subkey_str.upper()))
            except:
                _logger.error(traceback.format_exc())
                if main_key is not None:
                    win32api.RegCloseKey(main_key)

        reg_del = reg_set - instance_set
        for hwid_str, rand_str in reg_del:
            try:
                del_reg_str = 'SYSTEM\\CurrentControlSet\\Enum\\' + hwid_str + "\\" + rand_str
                _logger.info('will del key = {}'.format(del_reg_str))
                win32api.RegDeleteTree(win32con.HKEY_LOCAL_MACHINE, del_reg_str)
                _logger.info('have del key = {}'.format(del_reg_str))
            except:
                _logger.error(traceback.format_exc())

        # instance 为 0 也要进行删除操作，因此修改到下面。
        num = 0
        if 0 == len(all_id_instance_path_list):
            while True:
                _logger.info("hardward_id_list = {},all_id_instance_path_list = 0".format(hardward_id_list))
                time.sleep(1)
                num += 1
                if bTimeOut:
                    if num >= 25:
                        return
    except:
        _logger.error(traceback.format_exc())


def RetryInstPatch(exe_name, commandLine, work_dir, retry_time, once_wait_mill_time):
    try:
        for one in range(retry_time):  # 最多重试次数
            # 记录开始时间。
            # start_count = win32api.GetTickCount()
            # 启动进程。
            PyStarInfo = win32process.STARTUPINFO()
            proc_info = win32process.CreateProcess(exe_name, commandLine, None, None, 0, 0, None, work_dir, PyStarInfo)
            ret = win32event.WaitForSingleObject(proc_info[0], once_wait_mill_time)
            # ret = win32event.WaitForSingleObject(proc_info[0], 1 * 60 * 1000)
            if ret == win32con.WAIT_OBJECT_0:
                # 操作完成,成功退出。
                return
            # 否则杀掉进程，继续循环安装。
            win32api.TerminateProcess(proc_info[0], 0)
            win32event.WaitForSingleObject(proc_info[0], win32event.INFINITE)
    except:
        _logger.error(traceback.format_exc())


def safe_copy_file(src, des):
    try:
        system_path = win32api.GetSystemDirectory()
        while os.path.exists(des) is True:
            cmd_str = '{}\\cmd.exe /c attrib -R -S -H "{}"'.format(system_path, des)
            show_and_exe_cmd_line_and_get_ret(cmd_str)
            _logger.info('cmd /c attrib -R -S -H "' + des + '"')
            win32api.DeleteFile(des)
            time.sleep(1)

        shutil.copy(src, des)
    except:
        _logger.error(traceback.format_exc())


def install_hyper_v():
    save_64_value = None
    try:
        ver_info = win32api.GetVersionEx()
        major = ver_info[0]
        min_os = ver_info[1]
        if major > 5:
            _logger.info('install_hyper_v ver != 5.2 ,ver_info = {}'.format(ver_info))
            return
        if (major == 5) and (min_os > 2):
            _logger.info('install_hyper_v ver != 5.2 ,ver_info = {}'.format(ver_info))
            return
        bIs64 = Check32Or64OS()

        des_winhv_sys = win32api.GetSystemDirectory() + r'\drivers\winhv.sys'
        des_vms3cap_sys = win32api.GetSystemDirectory() + r'\drivers\vms3cap.sys'
        if bIs64:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()
            src_winhv_sys = current_dir + r'\Hyper-v_Patch\64\winhv.sys'
            src_vms3cap_sys = current_dir + r'\Hyper-v_Patch\64\vms3cap.sys'
            work_dir = current_dir + r'\Hyper-v_Patch\64'
            wdf_patch = current_dir + r'\Hyper-v_Patch\64\Microsoft Kernel-Mode Driver Framework ' \
                                      r'Install-v1.9-Win2k-WinXP-Win2k3.exe'
            KB943295_patch = current_dir + r'\Hyper-v_Patch\64\WindowsServer2003.WindowsXP-KB943295-x64-CHS.exe'
        else:
            src_winhv_sys = current_dir + r'\Hyper-v_Patch\32\winhv.sys'
            src_vms3cap_sys = current_dir + r'\Hyper-v_Patch\32\vms3cap.sys'
            work_dir = current_dir + r'\Hyper-v_Patch\32'
            wdf_patch = current_dir + r'\Hyper-v_Patch\32\Microsoft Kernel-Mode Driver Framework ' \
                                      r'Install-v1.9-Win2k-WinXP-Win2k3.exe'
            KB943295_patch = current_dir + r'\Hyper-v_Patch\32\WindowsServer2003-KB943295-x86-CHS.exe'

        # 检测 wdf 注册表，如果已经写入，就不安装。
        try:
            key_Wdf01000 = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE,
                                                 "SYSTEM\\CurrentControlSet\\services\\Wdf01000")
            # 如果已经写入，就不安装。
            win32api.RegCloseKey(key_Wdf01000)
            if save_64_value is not None:
                win32file.Wow64RevertWow64FsRedirection(save_64_value)
            return
        except:
            # 没有写入注册表。继续安装。
            pass
        # 没有写入注册表。继续安装。
        # 拷贝2驱动。
        safe_copy_file(src_winhv_sys, des_winhv_sys)
        safe_copy_file(src_vms3cap_sys, des_vms3cap_sys)

        # 必须先安装2patch，再写注册表，因为 wdf101000 注册表 不同值
        exe_name = os.path.join(win32api.GetSystemDirectory(), 'cmd.exe')

        commandLine = ' /c "' + wdf_patch + '" /quiet /norestart '
        RetryInstPatch(exe_name, commandLine, work_dir, 3, 60 * 1000)
        commandLine = ' /c "' + KB943295_patch + '" /quiet /norestart '
        RetryInstPatch(exe_name, commandLine, work_dir, 3, 60 * 1000)

        try:
            key_GroupOrderList = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE,
                                                       "SYSTEM\\CurrentControlSet\\Control\\GroupOrderList", 0,
                                                       win32con.KEY_WRITE)
            win32api.RegSetValueEx(key_GroupOrderList, "WdfLoadGroup", 0, win32con.REG_BINARY,
                                   str2bytes('\x01\x00\x00\x00\x01\x00\x00\x00'))
            win32api.RegCloseKey(key_GroupOrderList)
        except:
            _logger.info(traceback.format_exc())
            # 关键注册表写入出错，怎么处理呢?...
            if save_64_value is not None:
                win32file.Wow64RevertWow64FsRedirection(save_64_value)
            return

        try:
            key_ServiceGroupOrder = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE,
                                                          "SYSTEM\\CurrentControlSet\\Control\\ServiceGroupOrder", 0,
                                                          win32con.KEY_ALL_ACCESS)
            order_list = win32api.RegQueryValueEx(key_ServiceGroupOrder, "List")
            if 'WdfLoadGroup' not in order_list[0]:
                num = order_list[0].index('Boot Bus Extender')
                order_list[0].insert(num + 1, 'WdfLoadGroup')
            win32api.RegSetValueEx(key_ServiceGroupOrder, "List", 0, win32con.REG_MULTI_SZ, order_list[0])
            win32api.RegCloseKey(key_ServiceGroupOrder)
        except:
            _logger.info(traceback.format_exc())
            # 关键注册表写入出错，怎么处理呢?...
            if save_64_value is not None:
                win32file.Wow64RevertWow64FsRedirection(save_64_value)
            return

        try:
            key_Wdf01000 = win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE,
                                                 "SYSTEM\\CurrentControlSet\\services\\Wdf01000")
            win32api.RegSetValueEx(key_Wdf01000, "ErrorControl", 0, win32con.REG_DWORD, 0)
            win32api.RegSetValueEx(key_Wdf01000, "Start", 0, win32con.REG_DWORD, 0)
            win32api.RegSetValueEx(key_Wdf01000, "Type", 0, win32con.REG_DWORD, 1)
            win32api.RegSetValueEx(key_Wdf01000, "ImagePath", 0, win32con.REG_EXPAND_SZ,
                                   'System32\Drivers\wdf01000.sys')
            win32api.RegSetValueEx(key_Wdf01000, "DisplayName", 0, win32con.REG_SZ,
                                   'Kernel Mode Driver Frameworks service')
            win32api.RegSetValueEx(key_Wdf01000, "Group", 0, win32con.REG_SZ, 'WdfLoadGroup')
            win32api.RegCloseKey(key_Wdf01000)
        except:
            # 关键注册表写入出错，怎么处理呢?...
            if save_64_value is not None:
                win32file.Wow64RevertWow64FsRedirection(save_64_value)
            return
    except:
        _logger.error(traceback.format_exc())
        if save_64_value is not None:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)


def install_micro_drv_addition(bIs64, inf_name, one_id):
    try:
        ver_info = win32api.GetVersionEx()
        major = ver_info[0]
        min_os = ver_info[1]
        if major > 5:
            _logger.info('install_micro_drv_addition ver != 5.2 ,ver_info = {}'.format(ver_info))
            return
        if (major == 5) and (min_os > 2):
            _logger.info('install_micro_drv_addition ver != 5.2 ,ver_info = {}'.format(ver_info))
            return
        inf_path = win32api.GetWindowsDirectory() + '\\inf\\' + inf_name

        thread_list = start_all_push_button_thread()
        install_drv(inf_path, one_id)
        wait_stop_all_push_button_thread(thread_list)
    except:
        _logger.error(traceback.format_exc())


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'install_drv', 185)


def devcon_install_system_driver(hardward_id_list):
    save_64_value = None
    main_key = None
    try:
        _logger.info("devcon_install_system_driver install begin,hardward_id_list = {}".format(hardward_id_list))
        ver_info = win32api.GetVersionEx()
        if ver_info[0] > 5:
            _logger.info('devcon_install_system_driver ver != 5.2 ,ver = {}'.format(ver_info))
            return
        if ver_info[0] == 5 and ver_info[1] > 2:
            _logger.info('devcon_install_system_driver ver != 5.2 ,ver = {}'.format(ver_info))
            return
        bIs64 = Check32Or64OS()
        if bIs64:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()

        wait_instance_ok_by_hardward_id_list(hardward_id_list)
        all_id_instance_path_list = get_all_instance_path_by_devcon_by_hardward_id_list(hardward_id_list)
        # num = 0
        if 0 == len(all_id_instance_path_list):
            _logger.info("devcon_install_dev_only_id not find instance")
            return

        one_reg = None
        for one_instance_path in all_id_instance_path_list:
            end_num = one_instance_path.rfind('\\')  # 找到要枚举的父键一个就好。
            if -1 != end_num:
                one_reg = one_instance_path[:end_num]
                break
        if one_reg is None:
            return
        # 打开注册表，开始枚举。
        hwidpath = 'SYSTEM\\CurrentControlSet\\Enum\\' + one_reg
        InfPathList = None
        main_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, hwidpath, 0, win32con.KEY_READ)
        size = win32api.RegQueryInfoKey(main_key)[0]
        # 遍历子项
        for i in range(size):
            sub_key = None
            subkey_str = hwidpath + '\\' + win32api.RegEnumKey(main_key, i)
            try:
                sub_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, subkey_str, 0, win32con.KEY_READ)
                DriverList = win32api.RegQueryValueEx(sub_key, "Driver")
                Driver_str = DriverList[0]
                class_key_str = 'SYSTEM\\CurrentControlSet\\Control\\Class\\' + Driver_str
                class_key = None
                try:
                    class_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, class_key_str, 0, win32con.KEY_READ)
                    InfPathList = win32api.RegQueryValueEx(class_key, "InfPath")
                    win32api.RegCloseKey(class_key)
                    break  # find inf name
                except:
                    _logger.error(traceback.format_exc())
                    if class_key_str is not None:
                        win32api.RegCloseKey(class_key)

                win32api.RegCloseKey(sub_key)
            except:
                _logger.error(traceback.format_exc())
                if sub_key is not None:
                    win32api.RegCloseKey(sub_key)
                continue
        if InfPathList is not None:
            inf_full_path = win32api.GetWindowsDirectory() + '\\inf\\' + InfPathList[0]
            devcon_install_dev(hardward_id_list[0], inf_full_path, False, False)
            # devcon_install_dev(hardward_id_list[0], inf_full_path, True, False)

        if main_key is not None:
            win32api.RegCloseKey(main_key)
        if save_64_value is not None:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)
        _logger.info("devcon_install_system_driver install end")
    except:
        _logger.error(traceback.format_exc())
        if main_key is not None:
            win32api.RegCloseKey(main_key)
        if save_64_value is not None:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)


def TimeOutWaitPlugAndPlay():
    try:
        _logger.info("TimeOutWaitPlugAndPlay begin")
        sys_dir = win32api.GetSystemDirectory()

        if os.path.exists(current_dir + '\\ClerWareSC.exe'):
            exe_path = current_dir + '\\ClerWareSC.exe'
        elif os.path.exists(sys_dir + '\\ClerWareSC.exe'):
            exe_path = sys_dir + '\\ClerWareSC.exe'
        elif os.path.exists(sys_dir + '\\sc.exe'):
            exe_path = sys_dir + '\\sc.exe'
        else:
            _logger.info("TimeOutWaitPlugAndPlay err end,no sc or ClerWareSC")
            return
        cmd = exe_path + ' query'
        for one in range(30):
            ret, lines = show_and_exe_cmd_line_and_get_ret(cmd)
            if 0 == ret:
                for one_line in lines:
                    if -1 != one_line.find("Plug and Play"):
                        # 即插即用服务启动成功。
                        _logger.info("TimeOutWaitPlugAndPlay find Plug and Play")
                        return
            time.sleep(1)
        _logger.info("TimeOutWaitPlugAndPlay end")
    except:
        _logger.debug(traceback.format_exc())


def fix_list_to_upper(proc_list):
    try:
        if proc_list is not None:
            for i in range(0, len(proc_list)):
                proc_list[i] = proc_list[i].upper()
    except:
        _logger.error(traceback.format_exc())


def add_mul_reg(key, subKey, valu_name, valu_value):
    _logger.info("[add_mul_reg] enter...")

    try:
        h_reg_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
        key_value_list = list()
        try:
            key_value_list, type = win32api.RegQueryValueEx(h_reg_key, valu_name)

            _logger.info("[add_mul_reg] subKey={}".format(subKey))
            _logger.info("[add_mul_reg] valu_name={}".format(valu_name))
            _logger.info("[add_mul_reg] key_value_list={}".format(key_value_list))

        except:
            pass
        valu_value = valu_value.upper()
        fix_list_to_upper(key_value_list)
        if valu_value not in key_value_list:
            key_value_list.append(valu_value)
            win32api.RegSetValueEx(h_reg_key, valu_name, 0, win32con.REG_MULTI_SZ, key_value_list)
        win32api.RegCloseKey(h_reg_key)

        _logger.info("[add_mul_reg] finish...")

    except:
        _logger.error(traceback.format_exc())


def del_mul_reg(key, subKey, valu_name, valu_value):
    try:
        h_reg_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
        key_value_list = list()
        try:
            key_value_list, type = win32api.RegQueryValueEx(h_reg_key, valu_name)
        except:
            pass
        valu_value = valu_value.upper()
        fix_list_to_upper(key_value_list)
        if valu_value in key_value_list:
            key_value_list.remove(valu_value)
            win32api.RegSetValueEx(h_reg_key, valu_name, 0, win32con.REG_MULTI_SZ, key_value_list)
        win32api.RegCloseKey(h_reg_key)
    except:
        _logger.error(traceback.format_exc())


def add_key(key, subKey):
    # 不处理异常，以便外部进行错误处理。
    h_local_key = win32api.RegCreateKey(key, subKey)
    win32api.RegCloseKey(h_local_key)


def add_reg_sz_value(key, subKey, value_name, value_value):
    h_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
    win32api.RegSetValueEx(h_key, value_name, 0, win32con.REG_SZ, value_value)
    win32api.RegCloseKey(h_key)


def add_reg_bin_value(key, subKey, value_name, value_value):
    h_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
    win32api.RegSetValueEx(h_key, value_name, 0, win32con.REG_BINARY, value_value)
    win32api.RegCloseKey(h_key)


def add_reg_out_bin_value(key, subKey, value_name, value_value):  # 加入注册表导出二进制格式转换。
    h_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
    new_bin_value = value_value.replace(',', '\\x')
    win32api.RegSetValueEx(h_key, value_name, 0, win32con.REG_BINARY, str2bytes(new_bin_value))
    win32api.RegCloseKey(h_key)


def add_reg_dw_value(key, subKey, value_name, value_value):
    h_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
    win32api.RegSetValueEx(h_key, value_name, 0, win32con.REG_DWORD, value_value)
    win32api.RegCloseKey(h_key)


def add_reg_qdw_value(key, subKey, value_name, value_value):
    h_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
    win32api.RegSetValueEx(h_key, value_name, 0, win32con.REG_QWORD, value_value)
    win32api.RegCloseKey(h_key)


def add_reg_mul_sz_value(key, subKey, value_name, value_value):
    h_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
    win32api.RegSetValueEx(h_key, value_name, 0, win32con.REG_MULTI_SZ, value_value)
    win32api.RegCloseKey(h_key)


def add_reg_expand_value(key, subKey, value_name, value_value):
    h_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
    win32api.RegSetValueEx(h_key, value_name, 0, win32con.REG_EXPAND_SZ, value_value)
    win32api.RegCloseKey(h_key)


def add_xen_search_full_name(key, subKey, search_name):
    enum_key = None
    find_reg_list = list()
    try:
        enum_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
        size_key, size_value, size_type = win32api.RegQueryInfoKey(enum_key)
        if 0 == size_key:
            win32api.RegCloseKey(enum_key)
            return find_reg_list
        for i in range(size_key):
            sub_key_str = win32api.RegEnumKey(enum_key, i)
            if 0 == sub_key_str.lower().find(search_name):
                win32api.RegCloseKey(enum_key)
                find_reg_list.append(subKey + '\\' + sub_key_str)
        win32api.RegCloseKey(enum_key)
        return find_reg_list
    except:
        _logger.error(traceback.format_exc())
        if enum_key is not None:
            win32api.RegCloseKey(enum_key)
        return find_reg_list


def add_xen_filter_max_win8_v2():
    try:
        # 版本最大值就 6.2
        ver_info = win32api.GetVersionEx()
        if ver_info[0] < 6:
            return
        if ver_info[1] < 2:
            return

        reg_drv_root_str_list = add_xen_search_full_name(win32con.HKEY_LOCAL_MACHINE,
                                                         r'SYSTEM\DriverDatabase\DriverPackages',
                                                         'xenvbd.inf_')
        if 0 == len(reg_drv_root_str_list):
            _logger.info("add_xen_filter_max_win8_v2 can not find xenvbd.inf_")
            return

        for one_reg_drv_root_str in reg_drv_root_str_list:
            add_key(win32con.HKEY_LOCAL_MACHINE,
                    one_reg_drv_root_str + r'\Configurations\XenVbd_Inst\Services\xenvbd\Parameters\PnpInterface')
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Configurations\XenVbd_Inst',
                             'Service', "xenvbd")
            add_reg_mul_sz_value(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Configurations\XenVbd_Inst',
                                 'UpperFilters', ["xendisk"])
            add_reg_dw_value(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Configurations\XenVbd_Inst',
                             'ConfigFlags', 0)

            add_reg_dw_value(win32con.HKEY_LOCAL_MACHINE,
                             one_reg_drv_root_str + r'\Configurations\XenVbd_Inst\Services\xenvbd\Parameters',
                             'BusType', 1)

            add_reg_dw_value(win32con.HKEY_LOCAL_MACHINE,
                             one_reg_drv_root_str + r'\Configurations\XenVbd_Inst\Services\xenvbd\Parameters\PnpInterface',
                             '5', 1)

            add_key(win32con.HKEY_LOCAL_MACHINE,
                    one_reg_drv_root_str + r'\Descriptors\XENBUS\VEN_XS0002&DEV_VBD&REV_08000009')

            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE,
                             one_reg_drv_root_str + r'\Descriptors\XENBUS\VEN_XS0002&DEV_VBD&REV_08000009',
                             'Configuration', "XenVbd_Inst")
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE,
                             one_reg_drv_root_str + r'\Descriptors\XENBUS\VEN_XS0002&DEV_VBD&REV_08000009',
                             'Manufacturer', "%vendor%")
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE,
                             one_reg_drv_root_str + r'\Descriptors\XENBUS\VEN_XS0002&DEV_VBD&REV_08000009',
                             'Description', "%xenvbddesc%")

            add_key(win32con.HKEY_LOCAL_MACHINE,
                    one_reg_drv_root_str + r'\Descriptors\XENBUS\VEN_XP0002&DEV_VBD&REV_08000009')

            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE,
                             one_reg_drv_root_str + r'\Descriptors\XENBUS\VEN_XP0002&DEV_VBD&REV_08000009',
                             'Configuration', "XenVbd_Inst")
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE,
                             one_reg_drv_root_str + r'\Descriptors\XENBUS\VEN_XP0002&DEV_VBD&REV_08000009',
                             'Manufacturer', "%vendor%")
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE,
                             one_reg_drv_root_str + r'\Descriptors\XENBUS\VEN_XP0002&DEV_VBD&REV_08000009',
                             'Description', "%xenvbddesc%")

            add_key(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Strings')
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Strings', 'xenvbddesc',
                             "XenServer PV Storage Host Adapter")
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Strings', 'vendor', "Citrix")

        reg_drv_root_str_list = add_xen_search_full_name(win32con.HKEY_LOCAL_MACHINE,
                                                         r'SYSTEM\DriverDatabase\DriverPackages',
                                                         'xenbus.inf_')
        if 0 == len(reg_drv_root_str_list):
            _logger.info("add_xen_filter_max_win8_v2 can not find xenbus.inf_")
            return

        for one_reg_drv_root_str in reg_drv_root_str_list:
            add_key(win32con.HKEY_LOCAL_MACHINE,
                    one_reg_drv_root_str + r'\Configurations\XenBus_Inst\Services\xenbus\Interrupt Management\MessageSignaledInterruptProperties')
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Configurations\XenBus_Inst',
                             'Service', "xenbus")
            add_reg_dw_value(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Configurations\XenBus_Inst',
                             'ConfigFlags', 0)

            add_reg_dw_value(win32con.HKEY_LOCAL_MACHINE,
                             one_reg_drv_root_str + r'\Configurations\XenBus_Inst\Services\xenbus\Interrupt Management\MessageSignaledInterruptProperties',
                             'MSISupported', 1)

            add_key(win32con.HKEY_LOCAL_MACHINE,
                    one_reg_drv_root_str + r'\Configurations\XenBus_Inst\Services\xenbus\Parameters')
            add_reg_mul_sz_value(win32con.HKEY_LOCAL_MACHINE,
                                 one_reg_drv_root_str + r'\Configurations\XenBus_Inst\Services\xenbus\Parameters',
                                 'SupportedClasses', ['VIF', 'VBD', 'IFACE'])
            add_reg_mul_sz_value(win32con.HKEY_LOCAL_MACHINE,
                                 one_reg_drv_root_str + r'\Configurations\XenBus_Inst\Services\xenbus\Parameters',
                                 'SyntheticClasses', ['IFACE'])

            add_key(win32con.HKEY_LOCAL_MACHINE,
                    one_reg_drv_root_str + r'\Configurations\XenBus_Inst\Services\xenfilt\Parameters')
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE,
                             one_reg_drv_root_str + r'\Configurations\XenBus_Inst\Services\xenfilt\Parameters',
                             'ACPI\\PNP0A03', "DEVICE")
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE,
                             one_reg_drv_root_str + r'\Configurations\XenBus_Inst\Services\xenfilt\Parameters',
                             'PCIIDE\\IDEChannel', "DISK")

            add_key(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Descriptors\PCI\VEN_5853&DEV_0002')
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Descriptors\PCI\VEN_5853&DEV_0002',
                             'Configuration', "XenBus_Inst")
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Descriptors\PCI\VEN_5853&DEV_0002',
                             'Manufacturer', "%vendor%")
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Descriptors\PCI\VEN_5853&DEV_0002',
                             'Description', "%xenbusdesc%")

            add_key(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Strings')
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Strings', 'xenbusdesc',
                             "XenServer PV Bus")
            add_reg_sz_value(win32con.HKEY_LOCAL_MACHINE, one_reg_drv_root_str + r'\Strings', 'vendor', "Citrix")

    except:
        _logger.debug(traceback.format_exc())


def add_xen_filter_v2():
    global g_bIsXenV2
    _logger.info("[add_xen_filter_v2] enter...")
    try:
        _logger.info("[add_xen_filter_v2] write Unplug")
        g_bIsXenV2 = True

        h_xen_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                        r'SYSTEM\CurrentControlSet\Services\XEN\Unplug',
                                        0, win32con.KEY_ALL_ACCESS)
        win32api.RegSetValueEx(h_xen_key, "DISKS", 0, win32con.REG_DWORD, 8)
        win32api.RegSetValueEx(h_xen_key, "NICS", 0, win32con.REG_DWORD, 8)
        win32api.RegCloseKey(h_xen_key)

        _logger.info("[add_xen_filter_v2] write xenfilt")

        h_filt_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                         r'SYSTEM\CurrentControlSet\Services\xenfilt\Parameters',
                                         0, win32con.KEY_ALL_ACCESS)
        win32api.RegSetValueEx(h_filt_key, "ACPI\\PNP0A03", 0, win32con.REG_SZ, 'DEVICE')
        win32api.RegSetValueEx(h_filt_key, "PCIIDE\\IDEChannel", 0, win32con.REG_SZ, 'DISK')
        win32api.RegSetValueEx(h_filt_key, "ActiveDeviceID", 0, win32con.REG_SZ,
                               'PCI\\VEN_5853&DEV_0002&SUBSYS_00025853&REV_02')
        win32api.RegSetValueEx(h_filt_key, "ActiveInstanceID", 0, win32con.REG_SZ, '88')
        win32api.RegCloseKey(h_filt_key)

        # 必须以上注册表键值有才行，否则异常退出。
        add_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e96a-e325-11ce-bfc1-08002be10318}',
                    'UpperFilters', 'XENFILT')
        add_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e97d-e325-11ce-bfc1-08002be10318}',
                    'UpperFilters', 'XENFILT')

        set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenfilt", "Start",
                      win32con.REG_DWORD, 0)
        set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenbus", "Start",
                      win32con.REG_DWORD, 0)
        set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenvbd", "Start",
                      win32con.REG_DWORD, 0)
        set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xendisk", "Start",
                      win32con.REG_DWORD, 0)

        _logger.info("[add_xen_filter_v2] call add_xen_filter_max_win8_v2")

        add_xen_filter_max_win8_v2()

        _logger.info("[add_xen_filter_v2] finish...")

    except:
        _logger.debug(traceback.format_exc())


def del_not_need_xen_filter_reg_v2():
    try:
        _logger.info('del_not_need_xen_filter_reg_v2 begin')
        del_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e96a-e325-11ce-bfc1-08002be10318}', 'UpperFilters',
                    'XENFILT')
        del_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}', 'UpperFilters',
                    'XENFILT')
        del_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e97b-e325-11ce-bfc1-08002be10318}', 'UpperFilters',
                    'XENFILT')
        del_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e97d-e325-11ce-bfc1-08002be10318}', 'UpperFilters',
                    'XENFILT')

        set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenfilt", "Start",
                      win32con.REG_DWORD, 3)
        set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenbus", "Start",
                      win32con.REG_DWORD, 3)
        set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xendisk", "Start",
                      win32con.REG_DWORD, 3)

        _logger.info('del_not_need_xen_filter_reg_v2 end')
    except:
        _logger.error(traceback.format_exc())


def add_xen_filter_v1():
    global g_bIsXenV1
    try:
        _logger.info('add_xen_filter_v1 begin')
        g_bIsXenV1 = True
        # 必须以上注册表键值有才行，否则异常退出。
        add_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e96a-e325-11ce-bfc1-08002be10318}',
                    'UpperFilters', 'XENPCI')
        add_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}',
                    'UpperFilters', 'XENPCI')
        add_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e97b-e325-11ce-bfc1-08002be10318}',
                    'UpperFilters', 'XENPCI')

        set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenpci", "Start",
                      win32con.REG_DWORD, 0)
        set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenscsi", "Start",
                      win32con.REG_DWORD, 0)
        set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenvbd", "Start",
                      win32con.REG_DWORD, 0)

        _logger.info('add_xen_filter_v1 end')
    except:
        _logger.debug(traceback.format_exc())


def del_not_need_xen_filter_reg_v1():
    try:
        _logger.info('del_not_need_xen_filter_reg_v1 begin')
        del_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e96a-e325-11ce-bfc1-08002be10318}', 'UpperFilters',
                    'XENPCI')
        del_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}', 'UpperFilters',
                    'XENPCI')
        del_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e97b-e325-11ce-bfc1-08002be10318}', 'UpperFilters',
                    'XENPCI')
        del_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e97d-e325-11ce-bfc1-08002be10318}', 'UpperFilters',
                    'XENPCI')

        set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenpci", "Start",
                      win32con.REG_DWORD, 3)
        set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenscsi", "Start",
                      win32con.REG_DWORD, 3)

        _logger.info('del_not_need_xen_filter_reg_v1 end')
    except:
        _logger.error(traceback.format_exc())


def install_one_e1g(harward_id):
    try:
        _logger.info('install_one_e1g begin harward_id={}'.format(harward_id))
        # 获取当前系统e1g的版本路径。准备开始安装。
        cat_ver_str = get_cat_used_ver()
        inf_path = current_dir + "\\e1g\\" + cat_ver_str + "\\e1gclerware.inf"
        if os.path.exists(inf_path):
            devcon_install_dev(harward_id, inf_path, True, False)
        else:
            _logger.info('install_one_e1g can not find inf = {}'.format(inf_path))
        _logger.info('install_one_e1g end')
        return
    except:
        _logger.debug(traceback.format_exc())
        return


def install_e1g():
    try:
        _logger.info('install_e1g begin')
        output = os.popen(g_devcon_name + ' hwids =net PCI\\VEN_8086')
        while True:
            one_line = output.readline()
            if not one_line:
                break
            if one_line.find('Hardware IDs:') != -1:
                id_line = output.readline()
                if not one_line:
                    break
                id_line = id_line.strip()
                install_one_e1g(id_line)
        _logger.info('install_e1g end')
    except:
        _logger.debug(traceback.format_exc())


def uninstall_iasotrF():
    try:
        _logger.info('uninstall_iasotrF begin')
        # 如果有iaStorF的服务键值，进行过滤键值的安装卸载操作。避免没有iaStorF还在处理造成误操作。
        iasotrF_key = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\services\\iaStorF",
                                            0, win32con.KEY_READ)
        _logger.info('uninstall_iasotrF find server key,will del {4d36e967-e325-11ce-bfc1-08002be10318}')
        del_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}', 'LowerFilters',
                    'iaStorF')
        _logger.info('uninstall_iasotrF find server key,will del {4d36e965-e325-11ce-bfc1-08002be10318}')
        del_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e965-e325-11ce-bfc1-08002be10318}', 'LowerFilters',
                    'iaStorF')
        win32api.RegCloseKey(iasotrF_key)
        _logger.info('uninstall_iasotrF end')
    except:
        _logger.debug(traceback.format_exc())


def install_iasotrF():
    try:
        _logger.info('install_iasotrF begin')
        # 如果有iaStorF的服务键值，进行过滤键值的安装卸载操作。避免没有iaStorF还在处理造成误操作。
        iasotrF_key = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\services\\iaStorF",
                                            0, win32con.KEY_READ)
        _logger.info('install_iasotrF find server key,will add {4d36e967-e325-11ce-bfc1-08002be10318}')
        add_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}', 'LowerFilters',
                    'iaStorF')
        _logger.info('install_iasotrF find server key,will add {4d36e965-e325-11ce-bfc1-08002be10318}')
        add_mul_reg(win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Class\{4d36e965-e325-11ce-bfc1-08002be10318}', 'LowerFilters',
                    'iaStorF')
        win32api.RegCloseKey(iasotrF_key)
        _logger.info('install_iasotrF end')
    except:
        _logger.debug(traceback.format_exc())


class CleanFile():
    """
    在主程序正常推出后，删除标记文件。
    """
    FlAG_FILE_PATH = os.path.join(win32api.GetWindowsDirectory(), 'f5df5cf4b79c4afcb7da7df4359562b8')

    def __enter__(self):
        self._TimerThread = TimerThread()
        self._TimerThread.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if g_bIsXenV1 is not True:
            del_not_need_xen_filter_reg_v1()
        if g_bIsXenV2 is not True:
            del_not_need_xen_filter_reg_v2()
        if (g_bIsXenV1 is not True) and (g_bIsXenV2 is not True):
            set_reg_value(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenvbd", "Start",
                          win32con.REG_DWORD, 3)
        install_e1g()

        self._TimerThread.stop()
        self._TimerThread.join()
        return exc_type is None


with CleanFile():
    r = Runner()
    _logger = r.logger

    cur_file_dir_str = cur_file_dir()
    _logger.info(cur_file_dir_str)
    os.chdir(cur_file_dir_str)

    Check32Or64OS()
    TimeOutWaitPlugAndPlay()
    os.system(g_devcon_name + ' rescan')
    time.sleep(70)
    os.system(os.path.join(cur_file_dir_str, 'WaitSysI.exe 60'))

    # devcon_install_dev(r'PCI\VEN_10EC&DEV_5287&SUBSYS_10011D05&REV_01', r'o:\a.inf', False, False)
    # chk_reg_start_is_ok(r'PCIa\VEN_10EC&DEV_5287&SUBSYS_10011D05&REV_01')
    # chk_reg_is_ok([r'PCI\VEN_10EC&DEV_5287&SUBSYS_10011D05&REV_01'])
    # devcon_install_system_driver([r'PCI\VEN_10EC&DEV_5287&SUBSYS_10011D05&REV_01'])
