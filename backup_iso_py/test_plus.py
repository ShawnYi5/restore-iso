import os
import traceback
import chardet
import shutil
import sys
import win32api
import win32con

def get_file_charset(file_path):
    try:
        with open(file_path, 'rb') as file_obj:
            data = file_obj.read()
            return chardet.detect(data)['encoding']
    except:
        traceback.print_exc()

def test_win32api():
    try:
        enum_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                       "SYSTEM\\CurrentControlSet\\services")
        return  "open key success"
    except:
        traceback.print_exc()
        return  "open key failed"

if __name__ == "__main__":
    print (get_file_charset("./test_plus.py"))
    print (test_win32api())