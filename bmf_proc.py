import json
import os
import sys
import win32api
import win32file

import win32con

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging


class CBmfProc(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'bmf_proc', 188)

    def search_need_disk_guid(self):
        ret_num = -1
        flag_string = r'hhekaxxm9idsvW5PdutqgPthyuwuqwq6w5yjfbt9zgTbCtkvebrrknmpzspqhuC2'
        for i in range(26):
            try:
                handle = win32file.CreateFile('\\\\.\\PhysicalDrive' + str(i), win32con.GENERIC_READ,
                                              win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
                                              win32con.OPEN_EXISTING,
                                              win32con.FILE_ATTRIBUTE_NORMAL, 0)
                win32file.SetFilePointer(handle, 1024 * 1024 * 2 - 512, win32con.FILE_BEGIN)
                (ret, ret_str) = win32file.ReadFile(handle, 512, None)
                win32api.CloseHandle(handle)
                if ret != 0:
                    self.logger.info(
                        'win32file.CreateFile error file = {},continue search'.format('\\\\.\\PhysicalDrive' + str(i)))
                    continue
                if -1 != ret_str.find(flag_string.encode('utf-8')):
                    ret_num = i
                    self.logger.info('find flag_string error file ,continue search')
                    break
            except:
                continue
        return ret_num

    def read_bin_file_no_print_context(self, file_path):
        try:
            max_buffer_bytes = 8 * 1024 * 1024
            with open(file_path, 'rb') as file_handle:
                while True:
                    read_bytes = len(file_handle.read(max_buffer_bytes))
                    self.logger.info("file_path = {},read len = {}".format(file_path, read_bytes))
                    if read_bytes < max_buffer_bytes or read_bytes == 0:
                        break
        except Exception as e:
            self.logger.error(r'read_bin_file_no_print_context {} failed. {}'.format(file_path, e), exc_info=True)

    def get_windows_version(self):
        ver_info = win32api.GetVersionEx()
        self.logger.info('ver_info = {}'.format(ver_info))
        return ver_info[0], ver_info[1]

    def write_ext_info(self, disk_handle):
        windows_major_version, windows_minor_version = self.get_windows_version()
        ext_info = {'windows_version': {'major': windows_major_version, 'minor': windows_minor_version}}
        ext_info_data = json.dumps(ext_info).encode().ljust(512, b'\0')
        win32file.SetFilePointer(disk_handle, 1024 * 1024 * 2, win32con.FILE_BEGIN)
        win32file.WriteFile(disk_handle, ext_info_data, None)

    def work_real(self):
        disk_num = self.search_need_disk_guid()
        if -1 == disk_num:
            raise Exception('bmf can not find disk guid')

        windows_dir = win32api.GetWindowsDirectory()
        self.logger.info(windows_dir)
        windows_list = os.listdir(windows_dir)
        self.logger.info(windows_list)
        bmf_list = []

        for i in windows_list:
            if i.endswith('.bmf'):
                bmf_list.append(os.path.join(windows_dir, i))
        self.logger.info(bmf_list)
        bmf_list.sort()
        self.logger.info(bmf_list)

        disk_handle = win32file.CreateFile('\\\\.\\PhysicalDrive' + str(disk_num), win32con.GENERIC_WRITE,
                                           win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
                                           win32con.OPEN_EXISTING,
                                           win32con.FILE_ATTRIBUTE_NORMAL, 0)
        self.logger.info('floppy_handle = {}    {}'.format(disk_handle, disk_num))
        win32file.SetFilePointer(disk_handle, 4 * 1024, win32file.FILE_BEGIN)
        self.logger.info('skip 4k')
        for i in bmf_list:
            # 必须把bmf文件完整的读取，否则在bmf文件跨越 64k 块并且未读取过时，会被还原掉。。。
            self.read_bin_file_no_print_context(i)

            handle = win32file.CreateFile(i, win32con.GENERIC_READ,
                                          win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                                          None, win32con.OPEN_EXISTING, win32con.FILE_ATTRIBUTE_NORMAL, 0)
            self.logger.info('bmf name = {},file handle = {}'.format(i, handle))
            (ret, ret_str) = win32file.ReadFile(handle, 4 * 1024, None)
            if ret != 0 or len(ret_str) != 4 * 1024:
                self.logger.info('ReadFile error,file = {}   len = {}'.format(i, len(ret_str)))
                win32api.CloseHandle(handle)
                continue
            self.logger.info(ret_str)
            ret, _ = win32file.WriteFile(disk_handle, ret_str, None)
            if ret != 0:
                raise Exception('bmf WriteFile err ret = {}'.format(ret))
            else:
                self.logger.info('WriteFile success : {}'.format(i))
            win32api.CloseHandle(handle)

        self.write_ext_info(disk_handle)
        win32api.CloseHandle(disk_handle)


if __name__ == "__main__":
    cbmf_proc = CBmfProc()
    cbmf_proc.work()
