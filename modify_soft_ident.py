import json
import os
import sys

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging

import win32api

import win32con


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'modify soft ident', 76)

    def work_real(self):
        if self.logger_dir == "None":
            self.logger.warning(r'not logger dir')
            return

        self.logger.info(r'will modify soft ident')
        src_path = os.path.join(current_dir, 'agentServiceCfg.txt')
        self.logger.debug(src_path)
        with open(src_path, 'r') as sp:
            source_content = json.load(sp)

        self.modify_soft_ident(source_content.get('soft_ident', ''))

    def modify_soft_ident(self, soft_ident):
        key = win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE, r'SYSTEM\SOFTWARE\ClerwareSoftIdent')
        self.logger.info(r'RegCreateKey ok')
        win32api.RegSetValueEx(key, 'ClerwareSoftIdent', 0, win32con.REG_SZ, soft_ident)
        self.logger.info(r'RegSetValueEx ok')
        win32api.RegCloseKey(key)


if __name__ == "__main__":
    r = Runner()
    r.work()
