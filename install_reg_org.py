# coding=utf-8
import json
import os
import sys
import time
import traceback
import uuid
import win32api

import win32con
import socket

import win32file

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging

_logger = xlogging.getLogger('install_reg_org')

g_have_use_instance_path_list_save_reg = []
g_have_use_instance_path_list_set_ip = []
g_save_reg_num = 0
g_devcon_name = "devcon_64.exe"
g_bIs64OS = True


def Check32Or64OS():
    global g_devcon_name, g_bIs64OS
    try:
        sys_info = win32api.GetNativeSystemInfo()
        if sys_info[0] == 0:  # 如果是32位系统 PROCESSOR_ARCHITECTURE_INTEL
            g_devcon_name = "devcon_32.exe"
            g_bIs64OS = False
        _logger.info("devcon name is %s" % g_devcon_name)
    except:
        _logger.error(traceback.format_exc())


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


def start_net_setup_svc():
    try:
        save_64_value = None
        if g_bIs64OS:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()
        show_and_exe_cmd_line_and_get_ret('sc start NetSetupSvc')
        if save_64_value is not None:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)
    except:
        _logger.error(traceback.format_exc())


def SetAtapiReg():
    try:
        try:
            win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE,
                                  r"SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\Internal_IDE_Channel")
            atapi_key_1 = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                              r"SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\Internal_IDE_Channel",
                                              0,
                                              win32con.KEY_ALL_ACCESS)
            win32api.RegSetValueEx(atapi_key_1, "ClassGUID", 0, win32con.REG_SZ,
                                   '{4D36E96A-E325-11CE-BFC1-08002BE10318}')
            win32api.RegSetValueEx(atapi_key_1, "Service", 0, win32con.REG_SZ, 'atapi')
            win32api.RegCloseKey(atapi_key_1)
        except:
            _logger.error(traceback.format_exc())
        try:
            win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE,
                                  r"SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\Primary_IDE_Channel")
            atapi_key_2 = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                              r"SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\Primary_IDE_Channel",
                                              0,
                                              win32con.KEY_ALL_ACCESS)
            win32api.RegSetValueEx(atapi_key_2, "ClassGUID", 0, win32con.REG_SZ,
                                   '{4D36E96A-E325-11CE-BFC1-08002BE10318}')
            win32api.RegSetValueEx(atapi_key_2, "Service", 0, win32con.REG_SZ, 'atapi')
            win32api.RegCloseKey(atapi_key_2)
        except:
            _logger.error(traceback.format_exc())
        try:
            win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE,
                                  r"SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\Secondary_IDE_Channel")
            atapi_key_3 = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                              r"SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\Secondary_IDE_Channel",
                                              0,
                                              win32con.KEY_ALL_ACCESS)
            win32api.RegSetValueEx(atapi_key_3, "ClassGUID", 0, win32con.REG_SZ,
                                   '{4D36E96A-E325-11CE-BFC1-08002BE10318}')
            win32api.RegSetValueEx(atapi_key_3, "Service", 0, win32con.REG_SZ, 'atapi')
            win32api.RegCloseKey(atapi_key_3)
        except:
            _logger.error(traceback.format_exc())

    except:
        _logger.error(traceback.format_exc())


def fix_list_to_upper(proc_list):
    try:
        if proc_list is not None:
            for i in range(0, len(proc_list)):
                proc_list[i] = proc_list[i].upper()
    except:
        _logger.error(traceback.format_exc())


def add_mul_reg(key, subKey, valu_name, valu_value):
    try:
        h_reg_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
        key_value_list = list()
        try:
            key_value_list, type = win32api.RegQueryValueEx(h_reg_key, valu_name)
        except:
            pass
        valu_value = valu_value.upper()
        fix_list_to_upper(key_value_list)
        if valu_value not in key_value_list:
            key_value_list.append(valu_value)
            win32api.RegSetValueEx(h_reg_key, valu_name, 0, win32con.REG_MULTI_SZ, key_value_list)
        win32api.RegCloseKey(h_reg_key)
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
        _logger.debug(traceback.format_exc())


def init_reg():
    try:
        global g_save_reg_num
        global g_have_use_instance_path_list_save_reg
        global g_have_use_instance_path_list_set_ip
        g_have_use_instance_path_list_save_reg.clear()
        g_have_use_instance_path_list_set_ip.clear()
        g_save_reg_num = 0
        try:
            atapi_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                            "SYSTEM\\CurrentControlSet\\Services\\atapi",
                                            0,
                                            win32con.KEY_ALL_ACCESS)
            win32api.RegSetValueEx(atapi_key, "Start", 0, win32con.REG_DWORD, 0)
            win32api.RegCloseKey(atapi_key)
        except:
            _logger.error(traceback.format_exc())

        try:
            IntelIde_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                               "SYSTEM\\CurrentControlSet\\Services\\IntelIde",
                                               0,
                                               win32con.KEY_ALL_ACCESS)
            win32api.RegSetValueEx(IntelIde_key, "Start", 0, win32con.REG_DWORD, 0)
            win32api.RegCloseKey(IntelIde_key)
        except:
            _logger.error(traceback.format_exc())

        version = win32api.GetVersionEx(0)
        if (version[0] == 6) and (version[1] <= 1):
            SetAtapiReg()
        if version[0] <= 5:
            SetAtapiReg()

        os.system("reg delete \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\NAdrvIst\\Parameters\" /f")
        key_1 = win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\services\\NAdrvIst")
        win32api.RegSetValueEx(key_1, "ErrorControl", 0, win32con.REG_DWORD, 0)
        win32api.RegSetValueEx(key_1, "Start", 0, win32con.REG_DWORD, 0)
        win32api.RegSetValueEx(key_1, "Type", 0, win32con.REG_DWORD, 1)
        key_2 = win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE,
                                      "SYSTEM\\CurrentControlSet\\services\\NAdrvIst\\Parameters")
        if version[0] == 5:  # xp,2003
            win32api.RegSetValueEx(key_2, "LoadServices", 0, win32con.REG_MULTI_SZ, ['GPC', 'IPSec', 'tcpip'])
        elif version[0] == 6 and version[1] <= 1:
            win32api.RegSetValueEx(key_2, "LoadServices", 0, win32con.REG_MULTI_SZ,
                                   ['tdx', 'WfpLwf', 'Psched', 'NdisCap'])
        else:
            win32api.RegSetValueEx(key_2, "LoadServices", 0, win32con.REG_MULTI_SZ,
                                   ['tdx', 'WFPLWFS', 'Psched', 'NdisCap'])

        win32api.RegSetValueEx(key_2, "SupportServices", 0, win32con.REG_MULTI_SZ,
                               ["{502AF93E-0837-4D9E-913F-FBB734CA29F2}", "{B5F4D659-7DAA-4565-8E41-BE220ED60542}",
                                "{B70D6460-3635-4D42-B866-B8AB1A24454C}", "{EA24CD6C-D17A-4348-9190-09F0D5BE83DD}"])

        try:
            key_3 = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                        "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E97D-E325-11CE-BFC1-08002BE10318}",
                                        0, win32con.KEY_ALL_ACCESS)
            LowerFilters_Read_Value = win32api.RegQueryValueEx(key_3, "LowerFilters")
            if 0 == LowerFilters_Read_Value[0].count("NAdrvIst"):
                LowerFilters_Read_Value[0].append("NAdrvIst")
                win32api.RegSetValueEx(key_3, "LowerFilters", 0, win32con.REG_MULTI_SZ, LowerFilters_Read_Value[0])
        except:
            win32api.RegSetValueEx(key_3, "LowerFilters", 0, win32con.REG_MULTI_SZ, ["NAdrvIst"])
            _logger.info(
                "init_reg RegOpenKey SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E97D-E325-11CE-BFC1-08002BE10318} exception")

        win32api.RegCloseKey(key_3)
        win32api.RegCloseKey(key_2)
        win32api.RegCloseKey(key_1)
    except:
        _logger.error(traceback.format_exc())


def cur_file_dir():
    return current_dir


# def get_instance_path(hardward_id_list)
#     try:
#         for i in hardward_id_list:
#             try:
#                 enum_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
#                                                "SYSTEM\\CurrentControlSet\\Enum\\" + i, 0,
#                                                win32con.KEY_READ)
#                 size = win32api.RegQueryInfoKey(enum_key)[0]
#                 if 0 == size:
#                     return
#                 for i in range(size):
#                     sub_key_str = win32api.RegEnumKey(enum_key, i)
#                 win32api.RegCloseKey(enum_key);
#                 return i+"\\"+sub_key_str
#             except:
#                 continue
#     except:
#         _logger.error(traceback.format_exc())
#     finally:
#         return ""


def get_all_instance_path_by_devcon_by_one_hardward_id(one_hardward_id):
    out_instance_path_list = []
    try:
        cmd = g_devcon_name + ' hwids \"' + one_hardward_id + "\""
        _logger.info(cmd)
        output = os.popen(cmd)
        list_line = output.readlines()
        for one_line in list_line:
            _logger.info(one_line)
            if one_line[0] != ' ':
                if one_line.find('&') != -1:
                    if one_line[-1] == '\n':
                        one_line = one_line[0:len(one_line) - 1]
                    _logger.info("will append list line = {}".format(one_line))
                    out_instance_path_list.append(one_line)
        return out_instance_path_list
    except:
        _logger.error(traceback.format_exc())
        return out_instance_path_list


def get_instance_path_by_devcon_by_one_hardward_id(one_hardward_id, global_save_have_use_list_info):
    try:
        get_instance_path_list = get_all_instance_path_by_devcon_by_one_hardward_id(one_hardward_id)
        # 查找此 instance path 是否已经被使用
        while True:
            find_num = ""
            for j in get_instance_path_list:
                for k in global_save_have_use_list_info:
                    if j == k:
                        find_num = j
                        break
            if 0 != len(find_num):
                get_instance_path_list.remove(find_num)
            else:
                break
        if len(get_instance_path_list) != 0:
            global_save_have_use_list_info.append(get_instance_path_list[0])
            return get_instance_path_list[0]
    except:
        _logger.error(traceback.format_exc())


def get_instance_path_by_devcon_by_hardward_id_list(hardward_id_list, global_save_have_use_list_info):
    get_str = ""
    try:
        for i in hardward_id_list:
            get_str = get_instance_path_by_devcon_by_one_hardward_id(i, global_save_have_use_list_info)
            if get_str is None:
                _logger.info("get_instance_path_by_devcon_by_hardward_id_list get_str is None")
                continue
            if 0 != len(get_str):
                _logger.info("get_instance_path_by_devcon_by_hardward_id_list get_str1 = {}".format(get_str))
                return get_str
        _logger.info("get_instance_path_by_devcon_by_hardward_id_list get_str2 = {}".format(get_str))
        return get_str
    except:
        _logger.error(traceback.format_exc())
        return get_str


def safe_reg_chk_one_value(key, subkey, value_name):
    try:
        Driver_key = None
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


def clean_reg_all_value(key, subKey):
    enum_key = None
    try:
        enum_key = win32api.RegOpenKey(key, subKey, 0, win32con.KEY_ALL_ACCESS)
        size = win32api.RegQueryInfoKey(enum_key)[1]
        if 0 == size:
            win32api.RegCloseKey(enum_key)
            return
        for i in range(size):
            sub_key_str = win32api.RegEnumValue(enum_key, 0)
            win32api.RegDeleteValue(enum_key, sub_key_str[0])
        win32api.RegCloseKey(enum_key)
    except:
        _logger.error(traceback.format_exc())
        if enum_key is not None:
            win32api.RegCloseKey(enum_key)


def reg_create_key_no_loop(key, subKey):
    create_key = None
    try:
        create_key = win32api.RegCreateKey(key, subKey)
        win32api.RegCloseKey(create_key)
    except:
        _logger.error(traceback.format_exc())
        if create_key is not None:
            win32api.RegCloseKey(create_key)


def set_nsi_ip(reg_class_str, IPAddress_List, SubnetMask_List, DefaultGateway_List):
    Class_key = None
    Nsi_10_key = None
    Nsi_16_key = None
    try:
        _logger.info("set_nsi_ip begin")
        ver_info = win32api.GetVersionEx()
        _logger.info("set_nsi_ip ver_info = {}".format(ver_info))
        if ver_info[0] != 6:
            _logger.info("set_nsi_ip ver_info[0] != 6")
            return
        if ver_info[1] != 0:
            _logger.info("set_nsi_ip ver_info[1] != 0")
            return
        if 0 != len(ver_info[4]):
            if -1 == ver_info[4].find('Service Pack 1'):
                _logger.info("-1 == ver_info[4].find('Service Pack 1')")
                return
        reg_create_key_no_loop(win32con.HKEY_LOCAL_MACHINE,
                               r'SYSTEM\CurrentControlSet\Control\Nsi\{eb004a00-9b1a-11d4-9123-0050047759bc}\10')
        reg_create_key_no_loop(win32con.HKEY_LOCAL_MACHINE,
                               r'SYSTEM\CurrentControlSet\Control\Nsi\{eb004a00-9b1a-11d4-9123-0050047759bc}\16')
        clean_reg_all_value(win32con.HKEY_LOCAL_MACHINE,
                            r'SYSTEM\CurrentControlSet\Control\Nsi\{eb004a00-9b1a-11d4-9123-0050047759bc}\10')
        clean_reg_all_value(win32con.HKEY_LOCAL_MACHINE,
                            r'SYSTEM\CurrentControlSet\Control\Nsi\{eb004a00-9b1a-11d4-9123-0050047759bc}\16')
        Nsi_10_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                         r'SYSTEM\CurrentControlSet\Control\Nsi\{eb004a00-9b1a-11d4-9123-0050047759bc}\10',
                                         0, win32con.KEY_ALL_ACCESS)
        Nsi_16_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                         r'SYSTEM\CurrentControlSet\Control\Nsi\{eb004a00-9b1a-11d4-9123-0050047759bc}\16',
                                         0, win32con.KEY_ALL_ACCESS)
        Class_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, reg_class_str, 0, win32con.KEY_READ)
        NetLuidIndex, value_type = win32api.RegQueryValueEx(Class_key, 'NetLuidIndex')
        for num in range(len(IPAddress_List)):
            dwIp = socket.inet_aton(IPAddress_List[num])
            str_dw_ip = ''.join("{:02x}".format(b) for b in dwIp)
            reg_key_name = '{:08x}00000600{}00000000'.format(NetLuidIndex, str_dw_ip)
            dwMask = socket.inet_aton(SubnetMask_List[num])
            reg_value = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
                         0x10, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
            bit_num = sum([bin(int(x)).count("1") for x in SubnetMask_List[num].split(".")])
            reg_value[0x10] = bit_num
            win32api.RegSetValueEx(Nsi_10_key, reg_key_name, 0, win32con.REG_BINARY, bytearray(reg_value))

        if len(DefaultGateway_List) > 0:
            dwIp = socket.inet_aton(DefaultGateway_List[0])
            str_dw_ip = ''.join("{:02x}".format(b) for b in dwIp)
            reg_key_name = '0000000000000000' \
                           '0000000000000000' \
                           '0000000000000000' \
                           '{:08x}00000600' \
                           '{:08x}00000600' \
                           '{}00000000'.format(NetLuidIndex, NetLuidIndex, str_dw_ip)
            reg_value = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
            win32api.RegSetValueEx(Nsi_16_key, reg_key_name, 0, win32con.REG_BINARY, bytearray(reg_value))

        win32api.RegCloseKey(Class_key)
        win32api.RegCloseKey(Nsi_10_key)
        win32api.RegCloseKey(Nsi_16_key)
        _logger.info("set_nsi_ip end")
    except:
        _logger.error(traceback.format_exc())
        if Class_key is not None:
            win32api.RegCloseKey(Class_key)
        if Nsi_10_key is not None:
            win32api.RegCloseKey(Nsi_10_key)
        if Nsi_16_key is not None:
            win32api.RegCloseKey(Nsi_16_key)


def clear_all_ip_no_change_dhcp():
    try:
        enum_key = None
        enum_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                       "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                                       0, win32con.KEY_READ)
        _logger.info(
            'clear_all_ip_no_change_dhcp RegOpenKey  SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces end')
        size = win32api.RegQueryInfoKey(enum_key)[0]
        _logger.info('clear_all_ip_no_change_dhcp RegQueryInfoKey size={}'.format(size))
        if 0 == size:
            return
        for i in range(size):
            sub_key_str = win32api.RegEnumKey(enum_key, i)
            _logger.info('clear_all_ip_no_change_dhcp RegEnumKey sub_key_str={}'.format(sub_key_str))
            one_interface_key = None
            try:
                reg_str = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" + sub_key_str
                one_interface_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, reg_str, 0,
                                                        win32con.KEY_ALL_ACCESS)
                _logger.info('clear_all_ip_no_change_dhcp RegOpenKey end, reg_str={}'.format(reg_str))
                # try:
                #     value_value = win32api.RegQueryValueEx(one_interface_key, "EnableDHCP")
                #     if value_value[0] != '':
                #         win32api.RegSetValueEx(one_interface_key, "EnableDHCP", 0, win32con.REG_DWORD, 0)
                # except:
                #     pass # 每一个都有可能异常。
                try:
                    value_value = win32api.RegQueryValueEx(one_interface_key, "NameServer")
                    _logger.info('clear_all_ip_no_change_dhcp RegQueryValueEx NameServer, value_value={}'
                                 .format(value_value))
                    if value_value[0] != '':
                        win32api.RegSetValueEx(one_interface_key, "NameServer", 0, win32con.REG_SZ, '')
                except:
                    pass  # 每一个都有可能异常。
                try:
                    value_value = win32api.RegQueryValueEx(one_interface_key, "IPAddress")
                    _logger.info('clear_all_ip_no_change_dhcp RegQueryValueEx IPAddress, value_value={}'
                                 .format(value_value))
                    if value_value[0] != '':
                        win32api.RegSetValueEx(one_interface_key, "IPAddress", 0, win32con.REG_MULTI_SZ, [])
                except:
                    pass  # 每一个都有可能异常。
                try:
                    value_value = win32api.RegQueryValueEx(one_interface_key, "SubnetMask")
                    _logger.info('clear_all_ip_no_change_dhcp RegQueryValueEx SubnetMask, value_value={}'
                                 .format(value_value))
                    if value_value[0] != '':
                        win32api.RegSetValueEx(one_interface_key, "SubnetMask", 0, win32con.REG_MULTI_SZ, [])
                except:
                    pass  # 每一个都有可能异常。
                try:
                    value_value = win32api.RegQueryValueEx(one_interface_key, "DefaultGateway")
                    _logger.info('clear_all_ip_no_change_dhcp RegQueryValueEx DefaultGateway, value_value={}'
                                 .format(value_value))
                    if value_value[0] != '':
                        win32api.RegSetValueEx(one_interface_key, "DefaultGateway", 0, win32con.REG_MULTI_SZ, [])
                except:
                    pass  # 每一个都有可能异常。
                if one_interface_key is not None:
                    win32api.RegCloseKey(one_interface_key);
            except:
                _logger.error(traceback.format_exc())
                if one_interface_key is not None:
                    win32api.RegCloseKey(one_interface_key);

        if enum_key is not None:
            win32api.RegCloseKey(enum_key);
    except:
        _logger.error(traceback.format_exc())
        if enum_key is not None:
            win32api.RegCloseKey(enum_key);


# def set_ip_by_hardwrd_id_list(hardward_id_list, NameServer, IPAddress_List, SubnetMask_List, DefaultGateway_List):
#     global g_have_use_instance_path_list_set_ip
#     try:
#         # clear_all_ip_no_change_dhcp()
#         while True:
#             get_instance_path = get_instance_path_by_devcon_by_hardward_id_list(hardward_id_list,
#                                                                                 g_have_use_instance_path_list_set_ip)
#             if get_instance_path is None:
#                 _logger.info('set_ip_by_hardwrd_id_list get_instance_path is None,hardward_id_list={}'.format(
#                     hardward_id_list))
#                 time.sleep(1)
#                 if 0 != len(g_have_use_instance_path_list_set_ip):
#                     _logger.info('set_ip_by_hardwrd_id_list 0 != len(g_have_use_instance_path_list_set_ip) break')
#                     break
#                 else:
#                     _logger.info('set_ip_by_hardwrd_id_list 0 == len(g_have_use_instance_path_list_set_ip) continue')
#                     continue
#             if 0 == len(get_instance_path):
#                 _logger.info('set_ip_by_hardwrd_id_list 0 == len(get_instance_path),hardward_id_list={}'.format(
#                     hardward_id_list))
#                 time.sleep(1)
#                 if 0 != len(g_have_use_instance_path_list_set_ip):
#                     break
#                 else:
#                     continue
#             Driver_key = None
#             Class_key = None
#             Interfaces_key = None
#             while True:
#                 try:
#                     if Driver_key is not None:
#                         win32api.RegCloseKey(Driver_key)
#                     if Class_key is not None:
#                         win32api.RegCloseKey(Class_key)
#                     if Interfaces_key is not None:
#                         win32api.RegCloseKey(Interfaces_key)
#
#                     Driver_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
#                                                      "SYSTEM\\CurrentControlSet\\Enum\\" + get_instance_path, 0,
#                                                      win32con.KEY_READ)
#                     Driver_List = win32api.RegQueryValueEx(Driver_key, 'Driver')
#                     will_open_key_str = "SYSTEM\\CurrentControlSet\\Control\\Class\\" + Driver_List[0]
#                     set_nsi_ip(will_open_key_str, IPAddress_List, SubnetMask_List, DefaultGateway_List)
#                     Class_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, will_open_key_str, 0,
#                                                     win32con.KEY_READ)
#                     start_net_setup_svc()
#                     time.sleep(10)
#                     NetCfgInstanceId_List = win32api.RegQueryValueEx(Class_key, 'NetCfgInstanceId')
#                     bRet = safe_reg_chk_one_value(win32con.HKEY_LOCAL_MACHINE,
#                                                   "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" +
#                                                   NetCfgInstanceId_List[0],
#                                                   "EnableDHCP")
#                     if bRet != True:
#                         _logger.info('set_ip_by_hardwrd_id_list write net info no dhcp,wait!reg={}'.format(
#                             "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" +
#                             NetCfgInstanceId_List[0]))
#                         time.sleep(1)
#                         continue
#                     else:
#                         time.sleep(3)
#                     Interfaces_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
#                                                          "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" +
#                                                          NetCfgInstanceId_List[0],
#                                                          0,
#                                                          win32con.KEY_ALL_ACCESS)
#                     win32api.RegSetValueEx(Interfaces_key, "EnableDHCP", 0, win32con.REG_DWORD, 0)
#                     win32api.RegSetValueEx(Interfaces_key, "NameServer", 0, win32con.REG_SZ, NameServer)
#                     win32api.RegSetValueEx(Interfaces_key, "IPAddress", 0, win32con.REG_MULTI_SZ, IPAddress_List)
#                     win32api.RegSetValueEx(Interfaces_key, "SubnetMask", 0, win32con.REG_MULTI_SZ, SubnetMask_List)
#                     win32api.RegSetValueEx(Interfaces_key, "DefaultGateway", 0, win32con.REG_MULTI_SZ,
#                                            DefaultGateway_List)
#                     DefaultGatewayMetric_List = ["0"]
#                     win32api.RegSetValueEx(Interfaces_key, "DefaultGatewayMetric", 0, win32con.REG_MULTI_SZ,
#                                            DefaultGatewayMetric_List)
#                     _logger.info('set_ip_by_hardwrd_id_list write net info success,reg={}'.format(
#                         "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" +
#                         NetCfgInstanceId_List[0]))
#                     break
#                 except:
#                     _logger.info(
#                         'set_ip_by_hardwrd_id_list write reg err,retry!!! hardward_id_list={}'.format(hardward_id_list))
#                     _logger.error(traceback.format_exc())
#                     time.sleep(1)
#
#             if Driver_key is not None:
#                 win32api.RegCloseKey(Driver_key)
#             if Class_key is not None:
#                 win32api.RegCloseKey(Class_key)
#             if Interfaces_key is not None:
#                 win32api.RegCloseKey(Interfaces_key)
#             return get_instance_path
#     except:
#         _logger.error(traceback.format_exc())
#         return None
#
#
# def real_set_ip(cfg_inst_key, NameServer, DefaultGateway_List, SubnetMask_List, IPAddress_List):
#     try:
#         _logger.info('real_set_ip will RegSetValueEx NameServer={}'.format(NameServer))
#         win32api.RegSetValueEx(cfg_inst_key, "NameServer", 0, win32con.REG_SZ, NameServer)
#         _logger.info(
#             'set_ip_by_hardwrd_id_list_by_local will RegSetValueEx DefaultGateway_List={}'
#                 .format(DefaultGateway_List))
#         win32api.RegSetValueEx(cfg_inst_key, "DefaultGateway", 0, win32con.REG_MULTI_SZ,
#                                DefaultGateway_List)
#         _logger.info(
#             'set_ip_by_hardwrd_id_list_by_local will RegSetValueEx SubnetMask_List={}'
#                 .format(SubnetMask_List))
#         win32api.RegSetValueEx(cfg_inst_key, "SubnetMask", 0, win32con.REG_MULTI_SZ,
#                                SubnetMask_List)
#         _logger.info(
#             'set_ip_by_hardwrd_id_list_by_local will RegSetValueEx IPAddress_List={}'
#                 .format(IPAddress_List))
#         win32api.RegSetValueEx(cfg_inst_key, "IPAddress", 0, win32con.REG_MULTI_SZ,
#                                IPAddress_List)
#     except:
#         pass  # 每一个都有可能异常。
#
#
# def set_ip_by_hardwrd_id_list_by_local(szDeviceInstanceID, NameServer, IPAddress_List, SubnetMask_List,
#                                        DefaultGateway_List):
#     global g_have_use_instance_path_list_set_ip
#     try:
#         _logger.info('set_ip_by_hardwrd_id_list_by_local begin szDeviceInstanceID={} , NameServer = {}'.
#                      format(szDeviceInstanceID, NameServer))
#         _logger.info('set_ip_by_hardwrd_id_list_by_local begin IPAddress_List={} , SubnetMask_List = {}'.
#                      format(IPAddress_List, SubnetMask_List))
#         _logger.info('set_ip_by_hardwrd_id_list_by_local begin DefaultGateway_List={}'.
#                      format(DefaultGateway_List))
#
#         PNP_key = None
#         class_key = None
#         cfg_inst_key = None
#         while True:
#             try:
#                 reg_str_2 = "SYSTEM\\CurrentControlSet\\Enum\\" + szDeviceInstanceID
#                 PNP_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, reg_str_2, 0, win32con.KEY_READ)
#                 _logger.info('set_ip_by_hardwrd_id_list_by_local RegOpenKey end reg_str_2={}'.format(reg_str_2))
#                 driver_value = win32api.RegQueryValueEx(PNP_key, "Driver")
#                 _logger.info('set_ip_by_hardwrd_id_list_by_local RegQueryValueEx Driver end,driver_value={}'
#                              .format(driver_value))
#                 reg_str_3 = "SYSTEM\\CurrentControlSet\\Control\\Class\\" + driver_value[0]
#                 class_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, reg_str_3, 0,
#                                                 win32con.KEY_READ)
#                 _logger.info('set_ip_by_hardwrd_id_list_by_local RegOpenKey end reg_str_3={}'.format(reg_str_3))
#                 cfg_value = win32api.RegQueryValueEx(class_key, "NetCfgInstanceId")
#                 _logger.info(
#                     'set_ip_by_hardwrd_id_list_by_local RegQueryValueEx NetCfgInstanceId end,cfg_value={}'
#                         .format(cfg_value))
#                 reg_str_4 = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" + \
#                             cfg_value[0]
#                 cfg_inst_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, reg_str_4, 0,
#                                                    win32con.KEY_ALL_ACCESS)
#                 _logger.info('set_ip_by_hardwrd_id_list_by_local RegOpenKey end reg_str_4={}'.format(reg_str_4))
#                 try:
#                     value_value = win32api.RegQueryValueEx(cfg_inst_key, "EnableDHCP")
#                     _logger.info(
#                         'set_ip_by_hardwrd_id_list_by_local RegQueryValueEx EnableDHCP end value_value={}'
#                             .format(value_value))
#                     if value_value[0] != 0:
#                         _logger.info(
#                             'set_ip_by_hardwrd_id_list_by_local RegQueryValueEx EnableDHCP and will set 0')
#                         win32api.RegSetValueEx(cfg_inst_key, "EnableDHCP", 0, win32con.REG_DWORD, 0)
#                 except:
#                     # 出现异常，说明没有这个值，强制写入。
#                     _logger.info(
#                         'set_ip_by_hardwrd_id_list_by_local RegQueryValueEx EnableDHCP exception will set 0')
#                     win32api.RegSetValueEx(cfg_inst_key, "EnableDHCP", 0, win32con.REG_DWORD, 0)
#                 value_value = ([], None)
#                 try:
#                     value_value = win32api.RegQueryValueEx(cfg_inst_key, "IPAddress")
#                     _logger.info(
#                         'set_ip_by_hardwrd_id_list_by_local RegQueryValueEx IPAddress end,value_value={}'
#                             .format(value_value))
#                 except:
#                     _logger.info(
#                         'set_ip_by_hardwrd_id_list_by_local RegQueryValueEx IPAddress exception pass,value_value={}'
#                             .format(value_value))
#                     pass  # 每一个都有可能异常。
#                 if value_value[0] is None:
#                     _logger.info('set_ip_by_hardwrd_id_list_by_local if value_value[0] is None')
#                     real_set_ip(cfg_inst_key, NameServer, DefaultGateway_List, SubnetMask_List, IPAddress_List)
#                 elif value_value[0] == ['0.0.0.0']:
#                     _logger.info('set_ip_by_hardwrd_id_list_by_local if value_value[0] == 0.0.0.0')
#                     real_set_ip(cfg_inst_key, NameServer, DefaultGateway_List, SubnetMask_List, IPAddress_List)
#                 elif 0 == len(value_value[0]):
#                     _logger.info('set_ip_by_hardwrd_id_list_by_local if 0 == len(value_value[0])')
#                     real_set_ip(cfg_inst_key, NameServer, DefaultGateway_List, SubnetMask_List, IPAddress_List)
#
#                 if PNP_key is not None:
#                     win32api.RegCloseKey(PNP_key)
#                 if class_key is not None:
#                     win32api.RegCloseKey(class_key)
#                 if cfg_inst_key is not None:
#                     win32api.RegCloseKey(cfg_inst_key)
#                 return
#             except:
#                 _logger.error(traceback.format_exc())
#                 if PNP_key is not None:
#                     win32api.RegCloseKey(PNP_key)
#                     PNP_key = None
#                 if class_key is not None:
#                     win32api.RegCloseKey(class_key)
#                     class_key = None
#                 if cfg_inst_key is not None:
#                     win32api.RegCloseKey(cfg_inst_key)
#                     cfg_inst_key = None
#                 time.sleep(1)
#     except:
#         _logger.error(traceback.format_exc())

def set_ip_by_hardwrd_id_list_v2(UseInstanceID, NameServer, IPAddress_List, SubnetMask_List, DefaultGateway_List, mtu):
    try:
        # clear_all_ip_no_change_dhcp()
        _logger.info('set_ip_by_hardwrd_id_list_v2 UseInstanceID = {}'.format(UseInstanceID))
        Driver_key = None
        Class_key = None
        Interfaces_key = None
        ret_NetCfgInstanceId = None
        while True:
            try:
                if Driver_key is not None:
                    win32api.RegCloseKey(Driver_key)
                if Class_key is not None:
                    win32api.RegCloseKey(Class_key)
                if Interfaces_key is not None:
                    win32api.RegCloseKey(Interfaces_key)

                Driver_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                                 "SYSTEM\\CurrentControlSet\\Enum\\" + UseInstanceID, 0,
                                                 win32con.KEY_READ)
                Driver_List = win32api.RegQueryValueEx(Driver_key, 'Driver')
                will_open_key_str = "SYSTEM\\CurrentControlSet\\Control\\Class\\" + Driver_List[0]
                set_nsi_ip(will_open_key_str, IPAddress_List, SubnetMask_List, DefaultGateway_List)
                Class_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, will_open_key_str, 0,
                                                win32con.KEY_READ)
                start_net_setup_svc()
                time.sleep(10)
                NetCfgInstanceId_List = win32api.RegQueryValueEx(Class_key, 'NetCfgInstanceId')
                bRet = safe_reg_chk_one_value(win32con.HKEY_LOCAL_MACHINE,
                                              "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" +
                                              NetCfgInstanceId_List[0],
                                              "EnableDHCP")
                if bRet != True:
                    _logger.info('set_ip_by_hardwrd_id_list write net info no dhcp,wait!reg={}'.format(
                        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" +
                        NetCfgInstanceId_List[0]))
                    time.sleep(1)
                    continue
                else:
                    time.sleep(3)
                Interfaces_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                                     "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" +
                                                     NetCfgInstanceId_List[0],
                                                     0,
                                                     win32con.KEY_ALL_ACCESS)
                win32api.RegSetValueEx(Interfaces_key, "EnableDHCP", 0, win32con.REG_DWORD, 0)
                win32api.RegSetValueEx(Interfaces_key, "NameServer", 0, win32con.REG_SZ, NameServer)
                win32api.RegSetValueEx(Interfaces_key, "IPAddress", 0, win32con.REG_MULTI_SZ, IPAddress_List)
                win32api.RegSetValueEx(Interfaces_key, "SubnetMask", 0, win32con.REG_MULTI_SZ, SubnetMask_List)
                win32api.RegSetValueEx(Interfaces_key, "DefaultGateway", 0, win32con.REG_MULTI_SZ,
                                       DefaultGateway_List)
                try:
                    if mtu is not None:
                        if mtu != -1:
                            win32api.RegSetValueEx(Interfaces_key, "MTU", 0, win32con.REG_DWORD, mtu)
                except:
                    pass
                DefaultGatewayMetric_List = ["0"]
                win32api.RegSetValueEx(Interfaces_key, "DefaultGatewayMetric", 0, win32con.REG_MULTI_SZ,
                                       DefaultGatewayMetric_List)
                _logger.info('set_ip_by_hardwrd_id_list write net info success,reg={}'.format(
                    "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" +
                    NetCfgInstanceId_List[0]))
                ret_NetCfgInstanceId = NetCfgInstanceId_List[0]
                break
            except:
                _logger.info(
                    'set_ip_by_hardwrd_id_list write reg err,retry!!! UseInstanceID={}'.format(UseInstanceID))
                _logger.error(traceback.format_exc())
                time.sleep(1)

        if Driver_key is not None:
            win32api.RegCloseKey(Driver_key)
        if Class_key is not None:
            win32api.RegCloseKey(Class_key)
        if Interfaces_key is not None:
            win32api.RegCloseKey(Interfaces_key)
        return ret_NetCfgInstanceId
    except:
        _logger.error(traceback.format_exc())
        return None


def safe_RegSetValueEx(key, valueName, reserved, type, value):
    try:
        _logger.info('safe_RegSetValueEx begin\n')
        if valueName is None or value is None:
            return
        if 0 == len(valueName):
            return
        win32api.RegSetValueEx(key, valueName, reserved, type, value)
    except:
        _logger.error(traceback.format_exc())


def save_dev_reg_info(hardward_id_list, one_ip_to_nadrv_list, UseInstanceID, nic_name):
    global g_have_use_instance_path_list_save_reg
    global g_save_reg_num
    sub_key_str = "SYSTEM\\CurrentControlSet\\services\\NAdrvIst\\Parameters\\%03u" % g_save_reg_num
    loop_num = 0
    for one in one_ip_to_nadrv_list:
        while True:
            try:
                if 0 == loop_num:
                    get_instance_path = UseInstanceID
                else:
                    get_instance_path = get_instance_path_by_devcon_by_hardward_id_list(one[2],
                                                                                        g_have_use_instance_path_list_save_reg)
                    if get_instance_path is None:
                        get_instance_path = ''

                save_reg_key = win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE, sub_key_str)
                safe_RegSetValueEx(save_reg_key, "NameGUID", 0, win32con.REG_SZ, one[0])
                safe_RegSetValueEx(save_reg_key, "instancePath", 0, win32con.REG_SZ, get_instance_path)
                safe_RegSetValueEx(save_reg_key, "LocationInformation", 0, win32con.REG_SZ, one[1])
                safe_RegSetValueEx(save_reg_key, "HardwareID", 0, win32con.REG_MULTI_SZ, one[2])
                safe_RegSetValueEx(save_reg_key, "UINumber", 0, win32con.REG_DWORD, one[3])
                safe_RegSetValueEx(save_reg_key, "Address", 0, win32con.REG_DWORD, one[4])
                safe_RegSetValueEx(save_reg_key, "ContainerID", 0, win32con.REG_SZ, one[5])

                win32api.RegCloseKey(save_reg_key)
                break
            except:
                _logger.info('save_dev_reg_info write reg err,retry!!!,HardwareID={}'.format(one[2]))
                _logger.error(traceback.format_exc())
                time.sleep(1)
        sub_key_str = sub_key_str + '\\parent'
        loop_num = loop_num + 1
    g_save_reg_num += 1


def save_dev_reg_info_by_local(hardward_id_list, one_ip_to_nadrv_list, UseInstanceID, nic_name):
    global g_have_use_instance_path_list_save_reg
    global g_save_reg_num
    sub_key_str = "SYSTEM\\CurrentControlSet\\services\\NAdrvIst\\Parameters\\%03u" % g_save_reg_num
    for one in one_ip_to_nadrv_list:
        while True:
            try:
                save_reg_key = win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE, sub_key_str)
                safe_RegSetValueEx(save_reg_key, "NameGUID", 0, win32con.REG_SZ, one[0])
                safe_RegSetValueEx(save_reg_key, "instancePath", 0, win32con.REG_SZ, one[7])
                safe_RegSetValueEx(save_reg_key, "LocationInformation", 0, win32con.REG_SZ, one[1])
                safe_RegSetValueEx(save_reg_key, "HardwareID", 0, win32con.REG_MULTI_SZ, one[2])
                safe_RegSetValueEx(save_reg_key, "UINumber", 0, win32con.REG_DWORD, one[3])
                safe_RegSetValueEx(save_reg_key, "Address", 0, win32con.REG_DWORD, one[4])
                safe_RegSetValueEx(save_reg_key, "ContainerID", 0, win32con.REG_SZ, one[5])

                win32api.RegCloseKey(save_reg_key)
                break
            except:
                _logger.info('save_dev_reg_info write reg err,retry!!!,HardwareID={}'.format(one[2]))
                _logger.error(traceback.format_exc())
                time.sleep(1)
        sub_key_str = sub_key_str + '\\parent'
    g_save_reg_num += 1


def reg_key_exist(szDeviceInstanceID):
    try:
        Driver_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                         "SYSTEM\\CurrentControlSet\\Enum\\" + szDeviceInstanceID, 0, win32con.KEY_READ)
        win32api.RegCloseKey(Driver_key)
        return True
    except:
        _logger.error(traceback.format_exc())
        return False


def get_real_instance_id(old_InstanceID, hardward_id_list):
    global g_have_use_instance_path_list_set_ip
    try:
        # 用UseInstanceID。并且设置IP。
        bIsLocal = True
        if old_InstanceID is None:
            bIsLocal = False
            _logger.info('get_real_instance_id bIsLocal = False 1')
        elif 0 == len(old_InstanceID):
            bIsLocal = False
            _logger.info('get_real_instance_id bIsLocal = False 2')
        if reg_key_exist(old_InstanceID) is False:
            bIsLocal = False
            _logger.info('get_real_instance_id bIsLocal = False 3')
        if bIsLocal:
            _logger.info('get_real_instance_id old_InstanceID = {}, bIsLocal = {}'.format(old_InstanceID, bIsLocal))
            return old_InstanceID, bIsLocal
        else:
            get_instance_path = get_instance_path_by_devcon_by_hardward_id_list(hardward_id_list,
                                                                                g_have_use_instance_path_list_set_ip)
            _logger.info(
                'get_real_instance_id get_instance_path = {}, bIsLocal = {}'.format(get_instance_path, bIsLocal))
            return get_instance_path, bIsLocal
    except:
        _logger.error(traceback.format_exc())
        return '', False


def enum_nic(call_back, p1, p2):
    try:
        _logger.info('enum_nic begin')
        enum_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                       r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}",
                                       0, win32con.KEY_READ)
        size = win32api.RegQueryInfoKey(enum_key)[0]
        _logger.info('enum_nic RegQueryInfoKey size={}'.format(size))
        if 0 == size:
            return
        for i in range(size):
            sub_key_str = win32api.RegEnumKey(enum_key, i)
            _logger.info('enum_nic RegEnumKey sub_key_str={}'.format(sub_key_str))
            try:
                reg_str = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}" \
                          + '\\' + sub_key_str + '\\' + 'Connection'

                one_con_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, reg_str, 0, win32con.KEY_ALL_ACCESS)
                name_value = win32api.RegQueryValueEx(one_con_key, 'Name')
                instance_value = win32api.RegQueryValueEx(one_con_key, 'PnPInstanceId')
                call_back(one_con_key, name_value[0], instance_value[0], p1, p2)
                win32api.RegCloseKey(one_con_key)
            except:
                _logger.error(traceback.format_exc())
        win32api.RegCloseKey(enum_key)
        _logger.info('enum_nic end')
    except:
        _logger.error(traceback.format_exc())


def change_nic_name_by_name_call_back(one_con_key, name_value, instance_value, oldname, newname):
    try:
        _logger.info('change_nic_name_by_name_call_back begin one_con_key = {}, name_value = {},'
                     ' instance_value = {}, oldname = {}, newname = {}'
                     .format(one_con_key, name_value, instance_value, oldname, newname))
        if name_value.upper() == oldname.upper():
            win32api.RegSetValueEx(one_con_key, "Name", 0, win32con.REG_SZ, newname)
            _logger.info('change_nic_name_by_name_call_back find same name = {},change to {}'.format(oldname, newname))
        _logger.info('change_nic_name_by_name_call_back end')
    except:
        _logger.error(traceback.format_exc())


# def set_nic_name_by_instance_call_back(one_con_key, name_value, instance_value, UseInstanceID, nic_name):
#     try:
#         _logger.info('set_nic_name_by_instance_call_back begin one_con_key = {}, name_value = {},'
#                      ' instance_value = {}, UseInstanceID = {}, nic_name = {}'
#                      .format(one_con_key, name_value, instance_value, UseInstanceID, nic_name))
#         if instance_value.upper() == UseInstanceID.upper():
#             # win32api.RegSetValueEx(one_con_key, "Name", 0, win32con.REG_SZ, nic_name)
#             old_name = win32api.RegQueryValueEx(one_con_key, "Name")
#             sys_dir = win32api.GetSystemDirectory()
#             cmd = '{}\\netsh.exe interface set interface name="{}" newname="{}"'.format(sys_dir, old_name[0], nic_name)
#             os.system(cmd)
#             _logger.info('set_nic_name_by_instance_call_back find same UseInstanceID = {},change to {}'
#                          .format(UseInstanceID, nic_name))
#         _logger.info('set_nic_name_by_instance_call_back end')
#     except:
#         _logger.error(traceback.format_exc())


def fix_nic_name_by_InstanceID(UseInstanceID, nic_name, NetCfgInstanceId):
    save_64_value = None
    try:
        _logger.info('fix_nic_name_by_InstanceID begin')
        _logger.info('UseInstanceID = {}'.format(UseInstanceID))
        _logger.info('nic_name = {}'.format(nic_name))
        _logger.info('NetCfgInstanceId = {}'.format(NetCfgInstanceId))
        if nic_name is None:
            _logger.info('nic_name is None')
            return
        if 0 == len(nic_name):
            _logger.info('nic_name len is 0')
            return
        if NetCfgInstanceId is None:
            _logger.info('NetCfgInstanceId is None')
            return
        if 0 == len(NetCfgInstanceId):
            _logger.info('NetCfgInstanceId len is 0')
            return
        if g_bIs64OS:
            save_64_value = win32file.Wow64DisableWow64FsRedirection()
        sys_dir = win32api.GetSystemDirectory()
        # 重命名可能冲突的名字。
        nic_new_name = nic_name + str(uuid.uuid1())
        cmd = '{}\\netsh.exe interface set interface name="{}" newname="{}"'.format(sys_dir, nic_name, nic_new_name)
        _logger.info('cmd = {}'.format(cmd))
        os.system(cmd)
        enum_nic(change_nic_name_by_name_call_back, nic_name, nic_new_name)
        # 开始正式设置 instance 对应的网卡名。
        # enum_nic(set_nic_name_by_instance_call_back, UseInstanceID, nic_name)
        reg_str = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}" \
                  + '\\' + NetCfgInstanceId + '\\' + 'Connection'
        one_con_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, reg_str, 0, win32con.KEY_READ)
        old_nic_name, type = win32api.RegQueryValueEx(one_con_key, 'Name')
        cmd = '{}\\netsh.exe interface set interface name="{}" newname="{}"'.format(sys_dir, old_nic_name, nic_name)
        _logger.info('cmd = {}'.format(cmd))
        os.system(cmd)
        enum_nic(change_nic_name_by_name_call_back, old_nic_name, nic_name)

        if g_bIs64OS:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)
        _logger.info('fix_nic_name_by_InstanceID end')
        win32api.RegCloseKey(reg_str)
    except:
        if save_64_value is not None:
            win32file.Wow64RevertWow64FsRedirection(save_64_value)
        _logger.error(traceback.format_exc())


def uninstall_2003_xp_ms_wlbs_by_InstanceID(UseInstanceID):
    Driver_key = None
    Class_key = None
    try:
        _logger.info(r'uninstall_2003_xp_ms_wlbs_by_InstanceID begin,UseInstanceID = {}'.format(UseInstanceID))
        ver_info = win32api.GetVersionEx()
        _logger.info(r'work_real ver_info = {}'.format(ver_info))
        if ver_info[0] >= 6:
            _logger.info(r'uninstall_2003_xp_ms_wlbs_by_InstanceID ver_info[0] >= 6')
            return
        if g_bIs64OS:
            exec_path = os.path.join(current_dir, r'netcfg.x64.exe')
        else:
            exec_path = os.path.join(current_dir, r'netcfg.x86.exe')
        _logger.info(r'uninstall_2003_xp_ms_wlbs_by_InstanceID exec_path = {}'.format(exec_path))

        param = r' -u ms_wlbs '
        os.system(exec_path + param)

        Driver_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                         "SYSTEM\\CurrentControlSet\\Enum\\" + UseInstanceID, 0,
                                         win32con.KEY_READ)
        Driver_str, type = win32api.RegQueryValueEx(Driver_key, 'Driver')
        splite_str_list = Driver_str.split('\\')
        class_key_str = splite_str_list[0]
        my_main_net_str = splite_str_list[1]
        will_open_key_str = "SYSTEM\\CurrentControlSet\\Control\\Class\\" + class_key_str
        Class_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, will_open_key_str, 0, win32con.KEY_READ)
        key_size, value_size, last_time = win32api.RegQueryInfoKey(Class_key)
        _logger.info('clear_all_ip_no_change_dhcp RegQueryInfoKey key_size={}'.format(key_size))
        if 0 == key_size:
            _logger.info(r'uninstall_2003_xp_ms_wlbs_by_InstanceID key_size == 0')
            return
        get_list = list()
        my_main_net_str = {'num': my_main_net_str, 'RootDevice': None, 'UpperBind': None}
        for i in range(key_size):
            sub_key_str = win32api.RegEnumKey(Class_key, i)
            enum_key = None
            try:
                enum_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                               will_open_key_str + '\\' + sub_key_str + "\\Linkage", 0,
                                               win32con.KEY_READ)
                RootDevice, type = win32api.RegQueryValueEx(enum_key, 'RootDevice')
                UpperBind, type = win32api.RegQueryValueEx(enum_key, 'UpperBind')
                one_enum = {'num': sub_key_str, 'RootDevice': set(RootDevice), 'UpperBind': set(UpperBind)}
                get_list.append(one_enum)
                if sub_key_str == my_main_net_str['num']:
                    my_main_net_str['RootDevice'] = set(RootDevice)
                    my_main_net_str['UpperBind'] = set(UpperBind)
                win32api.RegCloseKey(enum_key)
            except:
                if enum_key:
                    win32api.RegCloseKey(enum_key)
        if my_main_net_str['RootDevice'] is None:
            _logger.info(r'uninstall_2003_xp_ms_wlbs_by_InstanceID my_main_net_str["RootDevice"] is None')
            return
        if my_main_net_str['UpperBind'] is None:
            _logger.info(r'uninstall_2003_xp_ms_wlbs_by_InstanceID my_main_net_str["UpperBind"] is None')
            return
        if 'Tcpip' in my_main_net_str['UpperBind']:
            _logger.info(r'uninstall_2003_xp_ms_wlbs_by_InstanceID bFindTcp = True, end')
            return
        # 白名单：没有 Qos: Psched
        white_set = {'AppleTalk', 'NM', 'NwlnkIpx', 'Ndisuio', 'NdisWan', 'RasPppoe', 'RMCast', 'Tcpip', 'Tcpip6',
                     'Wlbs'}
        for one in get_list:
            if one['num'] == my_main_net_str['num']:
                continue
            if not my_main_net_str['RootDevice'].issubset(one['RootDevice']):
                continue
            if 'Tcpip' not in one['UpperBind']:
                continue
            # 去除 白名单不支持的服务名,求白名单与 UpperBind 的交集
            get_will_fix_set = white_set.intersection(one['UpperBind'])
            print('get_will_fix_set = {}'.format(get_will_fix_set))
            try:
                h_reg_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                                "SYSTEM\\CurrentControlSet\\Control\\Class\\" + Driver_str + '\\Linkage',
                                                0,
                                                win32con.KEY_ALL_ACCESS)
                win32api.RegSetValueEx(h_reg_key, 'UpperBind', 0, win32con.REG_MULTI_SZ, list(get_will_fix_set))
                win32api.RegCloseKey(h_reg_key)
            except:
                _logger.error(traceback.format_exc())
            break
        win32api.RegCloseKey(Class_key)
        win32api.RegCloseKey(Driver_key)
        _logger.info(r'uninstall_2003_xp_ms_wlbs_by_InstanceID end')
    except:
        _logger.error(traceback.format_exc())
        if Class_key is not None:
            win32api.RegCloseKey(Class_key)
        if Driver_key is not None:
            win32api.RegCloseKey(Driver_key)


def add_ip_v2(szDeviceInstanceID, hardward_id_list, NameServer, IPAddress_List, SubnetMask_List, DefaultGateway_List,
              nic_name, context, one_ip_to_nadrv_list):
    try:
        _logger.info('add_ip_v2 begin')
        _logger.info('szDeviceInstanceID = {}'.format(szDeviceInstanceID))
        _logger.info('hardward_id_list = {}'.format(hardward_id_list))
        _logger.info('NameServer = {}'.format(NameServer))
        _logger.info('IPAddress_List = {}'.format(IPAddress_List))
        _logger.info('SubnetMask_List = {}'.format(SubnetMask_List))
        _logger.info('DefaultGateway_List = {}'.format(DefaultGateway_List))
        _logger.info('nic_name = {}'.format(nic_name))
        _logger.info('context = {}'.format(context))
        _logger.info('one_ip_to_nadrv_list = {}'.format(one_ip_to_nadrv_list))

        UseInstanceID = None
        bIsLocal = False
        while True:
            UseInstanceID, bIsLocal = get_real_instance_id(szDeviceInstanceID, hardward_id_list);
            if UseInstanceID is not None:
                if 0 != len(UseInstanceID):
                    break
            else:
                time.sleep(5)
                _logger.error("add_ip_v2 not find instance hardward_id_list = {},retry".format(hardward_id_list))
        NetCfgInstanceId = set_ip_by_hardwrd_id_list_v2(UseInstanceID, NameServer, IPAddress_List, SubnetMask_List,
                                                        DefaultGateway_List, context.get('mtu', -1))
        if bIsLocal:
            save_dev_reg_info_by_local(hardward_id_list, one_ip_to_nadrv_list, UseInstanceID, nic_name)
        else:
            save_dev_reg_info(hardward_id_list, one_ip_to_nadrv_list, UseInstanceID, nic_name)
        fix_nic_name_by_InstanceID(UseInstanceID, nic_name, NetCfgInstanceId)
        uninstall_2003_xp_ms_wlbs_by_InstanceID(UseInstanceID)
        _logger.info('add_ip_v2 end')
    except:
        _logger.error(traceback.format_exc())


def fix_start_reg_info():
    try:
        sub_key_str = "SYSTEM\\CurrentControlSet\\services\\Psched"
        save_reg_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, sub_key_str, 0, win32con.KEY_ALL_ACCESS)
        win32api.RegSetValueEx(save_reg_key, "Start", 0, win32con.REG_DWORD, 0)
        win32api.RegCloseKey(save_reg_key)
    except:
        _logger.error(traceback.format_exc())
    try:
        sub_key_str = "SYSTEM\\CurrentControlSet\\services\\WfpLwf"
        save_reg_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, sub_key_str, 0, win32con.KEY_ALL_ACCESS)
        win32api.RegSetValueEx(save_reg_key, "Start", 0, win32con.REG_DWORD, 0)
        win32api.RegCloseKey(save_reg_key)
    except:
        _logger.error(traceback.format_exc())
    try:
        sub_key_str = "SYSTEM\\CurrentControlSet\\services\\tdx"
        save_reg_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, sub_key_str, 0, win32con.KEY_ALL_ACCESS)
        win32api.RegSetValueEx(save_reg_key, "Start", 0, win32con.REG_DWORD, 0)
        win32api.RegCloseKey(save_reg_key)
    except:
        _logger.error(traceback.format_exc())


def read_bin_file(file_path):
    try:
        _logger.info(file_path)
        # if g_bIs64OS:
        #     save_64_value = win32file.Wow64DisableWow64FsRedirection()
        with open(file_path, 'rb') as file_handle:
            index = 0
            for i in range(0, 16):
                _logger.info("%3s " % (hex(i)), end="")
            _logger.info("")
            for i in range(0, 16):
                _logger.info("%3s " % "#", end="")
            _logger.info("")
            while True:
                temp = file_handle.read(1)
                if len(temp) == 0:
                    break
                else:
                    _logger.info("%s " % temp, end="")
                    index += 1
                if index == 16:
                    index = 0
                    _logger.info("")

                    # if g_bIs64OS:
                    #     win32file.Wow64RevertWow64FsRedirection(save_64_value)
    except:
        _logger.error(traceback.format_exc())
        # win32file.Wow64RevertWow64FsRedirection(save_64_value)


def read_bin_file_no_print_context(file_path):
    try:
        # if g_bIs64OS:
        #     save_64_value = win32file.Wow64DisableWow64FsRedirection()
        with open(file_path, 'rb') as file_handle:
            while True:
                temp = file_handle.read()
                _logger.info("file_path = {},read len = {}".format(file_path, len(temp)))
                if len(temp) == 0:
                    break
    except:
        _logger.error(traceback.format_exc())
        # win32file.Wow64RevertWow64FsRedirection(save_64_value)


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'install_reg', 186)


if __name__ == "__main__":
    global _logger
    r = Runner()
    _logger = r.logger

    cur_file_dir_str = cur_file_dir()
    _logger.info(cur_file_dir_str)
    os.chdir(cur_file_dir_str)

    Check32Or64OS()

    init_reg()
    # fix_start_reg_info()

    # h_id_1 = 'PCI\\VEN_8086&DEV_100F&SUBSYS_075015AD&REV_01'
    # h_id_2 = 'PCI\\VEN_8086&DEV_100F&SUBSYS_075015AD'
    # h_id_3 = 'PCI\\VEN_8086&DEV_100F&CC_020000'
    # h_id_4 = 'PCI\\VEN_8086&DEV_100F&CC_0200'
    # hardward_id_list = h_id_1, h_id_2, h_id_3, h_id_4
    #
    # IPAddress_List = ["172.16.6.78"]
    # SubnetMask_List = ["255.255.255.0"]
    # DefaultGateway_List = ["172.16.1.1"]
    # set_ip_by_hardwrd_id_list(hardward_id_list, "172.16.1.1,8.8.8.8", IPAddress_List, SubnetMask_List,
    #                           DefaultGateway_List)
    # set_ip_by_hardwrd_id_list(hardward_id_list, "172.16.1.1,8.8.8.8", IPAddress_List, SubnetMask_List,
    #                           DefaultGateway_List)
    # print(get_instance_path_by_devcon_by_hardward_id_list(hardward_id_list,g_have_use_instance_path_list_save_reg))
    # print(get_instance_path_by_devcon_by_hardward_id_list(hardward_id_list,g_have_use_instance_path_list_save_reg))

    # NameGUID = "{F5DDC77D-5D11-4418-AA34-E34FF6251726}"
    # LocationInformation = "LocationInformation1"
    # UINumber = 10
    # Address = 10
    # fatherHardwareID = ["fatherHardwareID1", "fatherHardwareID2"]
    # granpaHardwareID = ["granpaHardwareID1", "granpaHardwareID2"]
    # ContainerID = "abcdefg"
    # save_dev_reg_info(NameGUID, LocationInformation, hardward_id_list, UINumber, Address, fatherHardwareID,
    #                   granpaHardwareID,
    #                   ContainerID)
    # save_dev_reg_info(NameGUID, LocationInformation, hardward_id_list, UINumber, Address, fatherHardwareID,
    #                   granpaHardwareID,
    #                   ContainerID)
