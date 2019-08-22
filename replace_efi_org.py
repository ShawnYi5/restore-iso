import os
import subprocess
import sys
import win32api
import win32file
import shutil
import time
import re
from datetime import datetime

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging


class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'replace_efi', 191)

    def exe_cmd_and_get_ret(self, in_cmd_line):
        try:
            p = subprocess.Popen(in_cmd_line, stdout=subprocess.PIPE)
            out = p.communicate()
            p.stdout.close()
            rc = p.returncode
            return rc, out
        except xlogging.LogicError as e:
            self.logger.warning(r'call {} return error. {}'.format(in_cmd_line, e))
            return -1, ''

    def copytree(self, src, dst, symlinks=False):
        names = os.listdir(src)
        if not os.path.isdir(dst):
            os.makedirs(dst)
        errors = []
        for name in names:
            srcname = os.path.join(src, name)
            dstname = os.path.join(dst, name)
            try:
                if symlinks and os.path.islink(srcname):
                    linkto = os.readlink(srcname)
                    os.symlink(linkto, dstname)
                elif os.path.isdir(srcname):
                    self.copytree(srcname, dstname, symlinks)
                else:
                    if os.path.isdir(dstname):
                        os.rmdir(dstname)
                    elif os.path.isfile(dstname):
                        os.remove(dstname)
                    shutil.copy2(srcname, dstname)
                # XXX What about devices, sockets etc.?
            except (IOError, os.error) as why:
                errors.append((srcname, dstname, str(why)))
            # catch the Error from the recursive copytree so that we can
            # continue with other files
            except OSError as err:
                errors.extend(err.args[0])
        try:
            shutil.copystat(src, dst)
        except WindowsError:
            # can't copy file access times on Windows
            pass
        except OSError as why:
            errors.extend((src, dst, str(why)))
        if errors:
            raise shutil.Error(errors)

    def copy_files(self, drive_name):
        src_dir = '{}\\efi_partition\\EFI'.format(current_dir)
        des_dir = '{}:\\EFI'.format(drive_name)
        self.logger.info('copy_files src_dir={},des_dir={}'.format(src_dir, des_dir))
        st1 = datetime.now()
        while True:
            if os.path.isdir(des_dir):
                break
            else:
                st2 = datetime.now()
                if (st2 - st1).seconds > 30:
                    self.raise_logic_error(r'copy_files des_dir is not find,failed. des_dir={} '.format(des_dir), 1)
                time.sleep(5)
        self.copytree(src_dir, des_dir)

    def mount_efi_partition(self, drive_name):
        cmd = r'mountvol {}: /S'.format(drive_name)
        returned_code, out = self.exe_cmd_and_get_ret(cmd)
        self.logger.info(cmd)
        self.logger.info(out)
        self.logger.info(r'returned_code:{}\n'.format(returned_code))
        if returned_code != 0:
            self.raise_logic_error(r'mount_efi_partition returned_code != 0 : {} '.format(cmd), returned_code)

        return

    def unmount_efi_partition(self, drive_name):
        cmd = r'mountvol {}: /D'.format(drive_name)
        returned_code, out = self.exe_cmd_and_get_ret(cmd)
        self.logger.info(cmd)
        self.logger.info(out)
        self.logger.info(r'returned_code:{}\n'.format(returned_code))
        if returned_code != 0:
            self.raise_logic_error(r'unmount_efi_partition returned_code != 0 : {} '.format(cmd), returned_code)

        return

    def get_all_logic_drive(self):
        _drive_fixed = list()
        drives = win32api.GetLogicalDriveStrings()
        drives = drives.split('\000')[:-1]
        for drive in drives:
            try:
                drv = drive.upper()
                _drive_fixed.append(drv[0:1])
            except:
                pass
        return _drive_fixed

    def get_unused_drive(self):
        _drive_fixed = self.get_all_logic_drive()
        for i in range(ord('Z'), ord('A'), -1):
            if chr(i) not in _drive_fixed:
                return chr(i)
        self.raise_logic_error(r'get_unused_drive Failed. ', 1)

    def execute_cmd(self, cmd, timeout=120, **kwargs):
        with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, **kwargs) as p:
            stdout, stderr = p.communicate(timeout=timeout)
            self.logger.info(
                'execute_cmd cmd={},returncode={},stdout={},stderr={}'.format(cmd, p.returncode, stdout, stderr))
        return p.returncode, stdout, stderr

    def get_mounted_drive(self):
        returned_code, stdout, stderr = self.execute_cmd('mountvol')
        if returned_code != 0:
            self.logger.info('get_mounted_drive mountvol Failed.ignore.returned_code={}'.format(returned_code))
            return None
        pattern = re.compile(r'[\W\w\S\s]*EFI [\W\w\S\s]* ([a-z])+:\\', re.I)
        for line in stdout.split('\n'):
            m = pattern.match(line.strip())
            if m:
                drive_name = m.group(1)
                if drive_name:
                    return drive_name
        return None

    def work_real(self):
        drive_name = self.get_mounted_drive()
        if drive_name is None:
            drive_name = self.get_unused_drive()
            self.mount_efi_partition(drive_name)
        else:
            self.logger.info('work_real exist EFI drive_name={}'.format(drive_name))
        self.copy_files(drive_name)
        self.unmount_efi_partition(drive_name)


if __name__ == "__main__":
    r = Runner()
    # r.work()
