##=====================================================================================================
# 1：初始化 def init_dev(des_dir):
# des_dir：要打包iso的目录
#
##=====================================================================================================
import os
import sys
import traceback
import chardet
import shutil
import win32api
import win32con


def cur_file_dir():
    try:
        # 获取脚本路径
        path = sys.path[0]
        # 判断为脚本文件还是py2exe编译后的文件，如果是脚本文件，则返回的是脚本的目录，如果是py2exe编译后的文件，则返回的是编译后的文件路径
        if os.path.isdir(path):
            return path
        elif os.path.isfile(path):
            return os.path.dirname(path)
    except:
        traceback.print_exc()


disk_inst_dir = "disk_inst"
install_disk_bat = "install_disk.bat"


def copy_inst_disk_drv():
    try:
        # 获取新系统目录
        des_dir = win32api.GetWindowsDirectory()
        des_dir = os.path.dirname(des_dir)
        des_dir = os.path.join(des_dir, disk_inst_dir)

        src_dir = cur_file_dir()

        # 删除目标路径目录,建立空目录
        # os.rmdir(des_dir)
        shutil.rmtree(des_dir, True)
        try:
            os.makedirs(des_dir)
        except:pass

        # 拷贝源目录到目标路径目录。
        shutil.copytree(os.path.join(src_dir,"inf"), os.path.join(des_dir,"inf"))
        shutil.copy(os.path.join(src_dir,install_disk_bat), os.path.join(des_dir,install_disk_bat))
        shutil.copy(os.path.join(src_dir,"devcon.exe"), os.path.join(des_dir,"devcon.exe"))

    except:
        traceback.print_exc()


if __name__ == "__main__":
    print("begin run")
    copy_inst_disk_drv()
    print("end")
