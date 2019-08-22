import os
import sys
import win32api

import win32con

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

_logger = None


def generate_reg_path(index):
    return r"SYSTEM\Software\ClerWare\{:04}".format(index)


def is_index_exist(index):
    reg_path = generate_reg_path(index)
    try:
        key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, reg_path)
        win32api.RegCloseKey(key)
        return True
    except Exception as e:
        _logger.info(r'reg path [{}] open failed. {}'.format(reg_path, e))
    return False


def copy_file(file_path, logger, path_in_reg=None):
    global _logger
    _logger = logger
    if path_in_reg is None:
        path_in_reg = file_path
    index = 0
    while is_index_exist(index):
        index += 1
    reg_path = generate_reg_path(index)
    root_key = None
    _logger.info(r'will create {}'.format(reg_path))
    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()
        root_key = win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE, reg_path)
        win32api.RegSetValueEx(root_key, 'Path', 0, win32con.REG_SZ, path_in_reg)
        win32api.RegSetValueEx(root_key, 'Context', 0, win32con.REG_BINARY, file_content)
    except Exception as e:
        _logger.error(r'copy_file_by_reg failed {} | {}'.format(reg_path, e))
        # TODO delete reg which created .
    finally:
        if root_key:
            win32api.RegCloseKey(root_key)
