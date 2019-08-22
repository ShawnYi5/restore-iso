import os
import sys
import traceback
import shutil
import configparser
import win32api
import win32con
import win32event
import win32process

g_patch_dir = "patch"


def run_patch(cur_file_dir_str):
    try:
        system_dir = win32api.GetSystemDirectory()
        exit_code = 0
        patch_dir = cur_file_dir_str + "\\" + g_patch_dir
        for file in os.listdir(patch_dir):
            cmd_line = " \"" + patch_dir + "\\" + file + "\" /quiet /norestart"
            (proc_handle, thread_handle, proc_id, thread_id) = win32process.CreateProcess(
                system_dir + "\\" + "wusa.exe", cmd_line, None, None, 0, win32process.CREATE_NO_WINDOW, None, None,
                win32process.STARTUPINFO())
            # handle = win32api.ShellExecute(0, "open", file, "", patch_dir, 1)
            win32event.WaitForSingleObject(proc_handle, -1)
            exit_code = win32process.GetExitCodeProcess(proc_handle)
            if exit_code == 3010:  # 需要重新启动
                return exit_code
        return 0
    except:
        traceback.print_exc()
        return 0


def cur_file_dir():
    try:
        # 获取脚本路径
        path = current_dir = os.path.split(os.path.realpath(__file__))[0]
        # 判断为脚本文件还是py2exe编译后的文件，如果是脚本文件，则返回的是脚本的目录，如果是py2exe编译后的文件，则返回的是编译后的文件路径
        if os.path.isdir(path):
            return path
        elif os.path.isfile(path):
            return os.path.dirname(path)
    except:
        traceback.print_exc()


if __name__ == "__main__":
    print("begin run")
    cur_file_dir_str = cur_file_dir()
    print(cur_file_dir_str)
    os.chdir(cur_file_dir_str)
    current_dir = os.path.split(os.path.realpath(__file__))[0]
    sys.path.append(current_dir)

    ret_code = run_patch(cur_file_dir_str)
    exit(ret_code)
