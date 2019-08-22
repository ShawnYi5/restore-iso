import os, hashlib, tempfile, math, struct
import sys
import zipfile
import win32api
import win32con
import win32file
import time
import traceback
from datetime import datetime

import xlogging

_logger = xlogging.getLogger(__name__)

'''
磁盘文件结构
0扇区
flag[32] 6fc3c575b2de4da886f69b126b4d5ffa
syn[32] 多进程同步
reserve[448]
1扇区
head[8] 11111111（在用）或44444444（删除）
next_head_offset[8]
filename[168]
filesize[8]
文件内容
'''


class CMyFileSystem():
    def __init__(self):
        self.logger = _logger
        self.data_offset = 10240
        self.disk_num = self._search_need_disk_guid()

    def _search_need_disk_guid(self):
        ret_num = -1
        flag_string = r'6fc3c575b2de4da886f69b126b4d5ffa'
        for i in range(26):
            try:
                handle = win32file.CreateFile('\\\\.\\PhysicalDrive' + str(i), win32con.GENERIC_READ,
                                              win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
                                              win32con.OPEN_EXISTING,
                                              win32con.FILE_ATTRIBUTE_NORMAL, 0)
                win32file.SetFilePointer(handle, self.data_offset, win32con.FILE_BEGIN)
                (ret, ret_str) = win32file.ReadFile(handle, 512, None)
                win32api.CloseHandle(handle)
                if ret != 0:
                    self.logger.info(
                        'win32file.CreateFile error file = {},continue search'.format('\\\\.\\PhysicalDrive' + str(i)))
                    continue
                if -1 != ret_str.find(flag_string.encode('utf-8')):
                    ret_num = i
                    self.logger.info('find flag_string OK')
                    break
            except Exception as e:
                continue
        return ret_num

    def ReadBuffer(self, offset, length):
        start_sector = math.ceil(length / 512) + 1
        disk_handle = win32file.CreateFile('\\\\.\\PhysicalDrive' + str(self.disk_num), win32con.GENERIC_READ,
                                           win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
                                           win32con.OPEN_EXISTING,
                                           win32con.FILE_ATTRIBUTE_NORMAL, 0)
        win32file.SetFilePointer(disk_handle, offset, win32con.FILE_BEGIN)
        (ret, ret_byte) = win32file.ReadFile(disk_handle, start_sector * 512, None)
        start_offset = offset % 512
        ret_byte = ret_byte[start_offset:start_offset + length]
        win32api.CloseHandle(disk_handle)
        return ret_byte

    def WriteSector(self, offset, buffer):
        disk_handle = win32file.CreateFile('\\\\.\\PhysicalDrive' + str(self.disk_num), win32con.GENERIC_WRITE,
                                           win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
                                           win32con.OPEN_EXISTING,
                                           win32con.FILE_ATTRIBUTE_NORMAL, 0)
        win32file.SetFilePointer(disk_handle, offset, win32con.FILE_BEGIN)
        ret, nWritten = win32file.WriteFile(disk_handle, buffer, None)
        if (ret != 0):
            self.logger.info('WriteSector Failed. ret = {}'.format(ret))
        win32api.CloseHandle(disk_handle)

    def _isSynFlag(self, flag):
        # 如果为时间格式，则时间大于60S，则认为Flag无效
        try:
            flag = flag.decode('utf-8')
        except:
            pass
        return False

    def _addSynFlag(self):
        oldSector = self.ReadBuffer(self.data_offset, 512)
        newSector = oldSector[0:32]
        oldsyn = oldSector[32:64]
        if not self._isSynFlag(oldsyn):
            flag = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            syn = flag.encode(encoding="utf-8")
            syn = syn + bytes([0 for i in range(32 - len(syn))])
            newSector = newSector + syn
            newSector = newSector + oldSector[64:]
            if len(newSector) == 512:
                self.WriteSector(0, newSector)
            else:
                self.logger.info('_addSynFlag Failed.len={},newSector={}'.format(len(newSector), newSector))
                return False
            return True
        return False

    def _delSynFlag(self):
        oldSector = self.ReadBuffer(self.data_offset, 512)
        newSector = oldSector[0:32]
        syn = bytes([0 for i in range(32)])
        newSector = newSector + syn
        newSector = newSector + oldSector[64:]
        if len(newSector) == 512:
            self.WriteSector(0, newSector)
        else:
            self.logger.info('_delSynFlag Failed.len={},newSector={}'.format(len(newSector), newSector))
            return False
        return True

    def _findOffset(self):
        # 查找第一个可写的offset
        i = 0
        offset = self.data_offset + 512
        while True:
            i = i + 1
            if offset > 0x7FFFFE00:
                return -1
            head = self.ReadBuffer(offset, 16)
            if head[0:8] == b'\x01\x01\x01\x01\x01\x01\x01\x01' or head[0:8] == b'\x04\x04\x04\x04\x04\x04\x04\x04':
                offset = struct.unpack('Q', head[8:16])[0]
                continue
            return offset
        return -1

    def _genFileHead(self, offset, filepath):
        '''
        head[8] 11111111（在用）或44444444（删除）
        next_head_offset[8]
        filename[168]
        filesize[8]
        文件内容
        '''
        head = bytes([1 for i in range(8)])  # head
        filename = os.path.basename(filepath).encode('utf-8')[0:168]
        filename = filename + bytes([0 for i in range(168 - len(filename))])
        if len(filename) != 168:
            self.logger.info('_genFileHead Failed.len(filename)={}'.format(len(filename)))
            return None

        filesize = os.path.getsize(filepath)
        next_head_offset = offset + len(head) + 8 + len(filename) + filesize
        filesize = struct.pack('Q', filesize)
        if len(filesize) != 8:
            self.logger.info('_genFileHead Failed.len(filesize)={}'.format(len(filesize)))
            return None

        # 扇区对齐
        next_head_offset += (512 - next_head_offset % 512)
        next_head_offset = struct.pack('Q', next_head_offset)

        fileHead = head
        fileHead += next_head_offset
        fileHead += filename
        fileHead += filesize

        return fileHead

    def addOneFile(self, filepath):
        if self.disk_num == -1:
            self.logger.info('addOneFile Failed.disk_num==-1')
            return False
        self._addSynFlag()
        try:
            offset = self._findOffset()
            if offset == -1:
                self.logger.info('addOneFile Failed.offset==-1')
                return False
            self.logger.info('addOneFile offset=={},filepath={}'.format(hex(offset), filepath))
            head = self._genFileHead(offset, filepath)
            handle = win32file.CreateFile(filepath, win32con.GENERIC_READ,
                                          win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                                          None, win32con.OPEN_EXISTING, win32con.FILE_ATTRIBUTE_NORMAL, 0)

            self.logger.info('addOneFile filepath={},file handle={}'.format(filepath, handle))
            have_write_head = False
            buffer_length = 50 * 1024
            while True:
                if not have_write_head:
                    have_write_head = True
                    (ret, ret_bytes) = win32file.ReadFile(handle, buffer_length - len(head), None)
                    if ret == 0:
                        ret_bytes = head + ret_bytes
                else:
                    (ret, ret_bytes) = win32file.ReadFile(handle, buffer_length, None)
                if ret != 0:
                    break
                if len(ret_bytes) <= 0:
                    break
                if len(ret_bytes) < buffer_length:
                    ret_bytes = ret_bytes + bytes([0 for i in range(buffer_length - len(ret_bytes))])
                elif len(ret_bytes) > buffer_length:
                    self.logger.info('addOneFile filepath={},len(ret_bytes)={}'.format(filepath, len(ret_bytes)))
                    break
                self.WriteSector(offset, ret_bytes)
                offset += buffer_length
            win32api.CloseHandle(handle)
        finally:
            self._delSynFlag()

    def getFileList(self):
        '''
        head[8] 11111111（在用）或44444444（删除）
        next_head_offset[8]
        filename[168]
        filesize[8]
        文件内容
        '''
        filelist = list()
        offset = self.data_offset + 512
        sector = self.ReadBuffer(offset, 512)
        while True:
            if sector[0:8] == b'\x01\x01\x01\x01\x01\x01\x01\x01' or sector[0:8] == b'\x04\x04\x04\x04\x04\x04\x04\x04':
                next_head_offset = struct.unpack('Q', sector[8:16])[0]
                filename = sector[16:184]
                filesize = struct.unpack('Q', sector[184:192])[0]
                onefile = dict()
                onefile['filename'] = filename.decode('utf-8').replace('\x00', '')
                onefile['filesize'] = filesize
                onefile['offset'] = offset
                filelist.append(onefile)
                sector = self.ReadBuffer(next_head_offset, 512)
                offset = next_head_offset
                if len(sector) == 0:
                    self.logger.info('getFileList Failed.len(sector) == 0')
                    break
            else:
                break
        return filelist

    def getOneFile(self, onefile, filePath):
        writesize = 0
        offset = onefile["offset"] + 192
        filesize = onefile["filesize"]
        binfile = open(filePath, 'ab')
        buffersize = 50 * 1024
        while True:
            if filesize > writesize:
                if buffersize + writesize > filesize:
                    buffersize = filesize - writesize
                file_bytes = self.ReadBuffer(offset, buffersize)
                if len(file_bytes) > 0:
                    binfile.write(file_bytes)
                    writesize += buffersize
                    offset += buffersize
                else:
                    break
            else:
                break

        binfile.close()

    def IsFileNameExist(self, filename):
        filelist = self.getFileList()
        for one in filelist:
            if filename == one['filename']:
                return True
        return False


def getRawDiskFiles(flag, destpath):
    if flag != 'htb_disk':
        return 1
    myFileSystem = CMyFileSystem()
    filelist = myFileSystem.getFileList()
    for one in filelist:
        tmppath = os.path.join(destpath, one['filename'])
        while os.path.isfile(tmppath):
            filename = datetime.now().strftime('%Y_%m_%dT%H_%M_%S.f') + one['filename']
            tmppath = os.path.join(path, filename)
        myFileSystem.getOneFile(one, tmppath)
    return 0


if __name__ == "__main__":
    if False:
        myFileSystem = CMyFileSystem()
        myFileSystem.addOneFile(r'D:\test\VMware10.7z')
        myFileSystem.addOneFile(r'D:\test\test.zip')
        myFileSystem.addOneFile(r'D:\test\aaa.zip')
        filelist = myFileSystem.getFileList()
        path = r'D:\test\re'
        for one in filelist:
            tmppath = os.path.join(path, one['filename'])
            while os.path.isfile(tmppath):
                filename = datetime.now().strftime('%Y_%m_%dT%H_%M_%S.f') + one['filename']
                tmppath = os.path.join(path, filename)
            myFileSystem.getOneFile(one, tmppath)
