import os
import subprocess
import sys
import win32api

current_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(current_dir)

import xlogging

filelist = {
    # r'$MFT::$DATA',
    # r'$MFT::$ATTRIBUTE_LIST',
    # r'$MFT::$BITMAP',
    # r'$AttrDef::$DATA',
    # r'$AttrDef::$ATTRIBUTE_LIST',
    # r'$Secure:$SDS:$DATA',
    # r'$Secure::$ATTRIBUTE_LIST',
    # r'$Secure:$SDH:$INDEX_ALLOCATION',
    # r'$Secure:$SDH:$BITMAP',
    # r'$Secure:$SII:$INDEX_ALLOCATION',
    # r'$Secure:$SII:$BITMAP',
    # r'$UpCase::$DATA',
    # r'$UpCase::$ATTRIBUTE_LIST',
    r'$Extend:$I30:$INDEX_ALLOCATION',
    r'$Extend::$ATTRIBUTE_LIST',
    r'$Extend:$I30:$BITMAP',
    r'$Extend\$UsnJrnl:$J:$DATA',
    r'$Extend\$UsnJrnl::$ATTRIBUTE_LIST',
    r'$Extend\$UsnJrnl:$Max:$DATA',
    r'$Extend\$Quota:$Q:$INDEX_ALLOCATION',
    r'$Extend\$Quota::$ATTRIBUTE_LIST',
    r'$Extend\$Quota:$Q:$BITMAP',
    r'$Extend\$Quota:$O:$INDEX_ALLOCATION',
    r'$Extend\$Quota:$O:$BITMAP',
    r'$Extend\$ObjId:$O:$INDEX_ALLOCATION',
    r'$Extend\$ObjId::$ATTRIBUTE_LIST',
    r'$Extend\$ObjId:$O:$BITMAP',
    r'$Extend\$Reparse:$R:$INDEX_ALLOCATION',
    r'$Extend\$Reparse::$ATTRIBUTE_LIST',
    r'$Extend\$Reparse:$R:$BITMAP',
    r'$Extend\$RmMetadata:$I30:$INDEX_ALLOCATION',
    r'$Extend\$RmMetadata:$I30:$BITMAP',
    r'$Extend\$RmMetadata::$ATTRIBUTE_LIST',
    r'$Extend\$RmMetadata\$Repair::$DATA',
    r'$Extend\$RmMetadata\$Repair::$ATTRIBUTE_LIST',
    r'$Extend\$RmMetadata\$Repair:$Config:$DATA',
    r'$Extend\$RmMetadata\$Txf:$I30:$INDEX_ALLOCATION',
    r'$Extend\$RmMetadata\$Txf::$ATTRIBUTE_LIST',
    r'$Extend\$RmMetadata\$Txf:$I30:$BITMAP',
    r'$Extend\$RmMetadata\$Txf:$TXF_DATA:$LOGGED_UTILITY_STREAM',
    r'$Extend\$RmMetadata\$TxfLog:$I30:$INDEX_ALLOCATION',
    r'$Extend\$RmMetadata\$TxfLog::$ATTRIBUTE_LIST',
    r'$Extend\$RmMetadata\$TxfLog:$I30:$BITMAP',
    r'$Extend\$RmMetadata\$TxfLog\$Tops::$DATA',
    r'$Extend\$RmMetadata\$TxfLog\$Tops::$ATTRIBUTE_LIST',
    r'$Extend\$RmMetadata\$TxfLog\$Tops:$T:$DATA',
    r'$Extend\$RmMetadata\$TxfLog\$TxfLog.blf::$DATA',
    r'$Extend\$RmMetadata\$TxfLog\$TxfLog.blf::$ATTRIBUTE_LIST'
}

TxfLogContainer = [
    0x5C, 0x00, 0x24, 0x00, 0x54, 0x00, 0x78, 0x00, 0x66, 0x00, 0x4C, 0x00, 0x6F, 0x00, 0x67, 0x00,
    0x43, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x65, 0x00,
    0x72, 0x00]


# Offset       0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F
# 14D5EBE10         5C 00 24 00 54 00  78 00 66 00 4C 00 6F 00     \ $ T x f L o
# 14D5EBE20   67 00 43 00 6F 00 6E 00  74 00 61 00 69 00 6E 00   g C o n t a i n
# 14D5EBE30   65 00 72 00                                        e r

class Runner(xlogging.WorkWithLogger):
    def __init__(self):
        xlogging.WorkWithLogger.__init__(self, r'file_system_read', 182)

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

    def memicmp(self, srcbin, post, subbin):
        srcsize = len(srcbin)
        dstsize = len(subbin)

        if srcsize < post + dstsize:
            return False  # 已经不可能了。

        for i in range(dstsize):
            aaa = srcbin[post + i]
            bbb = subbin[i]
            # 'a' == 0x61     'z' == 0x7a     'A' == 0x41   'Z' == 0x5a
            if 0x61 <= aaa and aaa <= 0x7a:
                aaa = aaa - 0x20
            if 0x61 <= bbb and bbb <= 0x7a:
                bbb = bbb - 0x20
            if aaa != bbb:
                return False
        return True

    def get_unicode_end_post(self, srcbin, post):
        n = 0
        while True:
            if srcbin[post + n] == 0 and srcbin[post + n + 1] == 0:
                break
            n += 2
        return post + n

    def get_unicode_string(self, srcbin, post):
        endpost = self.get_unicode_end_post(srcbin, post)
        newbytes = srcbin[post:endpost]
        str = newbytes.decode('utf-16')
        return str

    def search_in_bin(self, bindata):
        listfiles = []
        binsize = len(bindata)
        for post in range(binsize):
            if bindata[post] == TxfLogContainer[0]:
                if True == self.memicmp(bindata, post, TxfLogContainer):
                    listfiles.append(self.get_unicode_string(bindata, post))
        return list(set(listfiles))

    def get_txflogfilelist(self, sys_drive):
        ret = {}
        logfile = sys_drive + r':\$Extend\$RmMetadata\$TxfLog\$TxfLog.blf'
        dest_path = os.path.join(self.logger_dir, '$TxfLog.blf')
        cmd = r'filesysapiv2.exe   ' + logfile + r'   "' + dest_path + r'"'
        returned_code, out = self.exe_cmd_and_get_ret(cmd)
        self.logger.info(cmd)
        self.logger.info(out)
        try:
            with open(dest_path, 'rb') as fd:
                bindata = fd.read()
                ret = self.search_in_bin(bindata)
        except:
            pass
        return ret

    def work_real(self):
        if self.logger_dir == "None":
            self.logger.warning(r'not logger dir')
            return

        sys_dir = win32api.GetSystemDirectory()

        sys_drive = sys_dir[0:1]

        txflog_list = []
        txflog_list = self.get_txflogfilelist(sys_drive)
        for onefile in txflog_list:
            full_path = sys_drive + r':\$Extend\$RmMetadata\$TxfLog' + onefile
            cmd = "filesysapiv2.exe  \"" + full_path + "\""
            returned_code, out = self.exe_cmd_and_get_ret(cmd)
            self.logger.info(cmd)
            self.logger.info(out)

        for file in filelist:
            cmd = "filesysapiv2.exe  \"" + sys_drive + ":\\" + file + "\""
            returned_code, out = self.exe_cmd_and_get_ret(cmd)
            self.logger.info(cmd)
            self.logger.info(out)
            self.logger.info(r'returned_code:{}\n'.format(returned_code))

        for index in range(99):
            cmd = "filesysapiv2.exe  \"" + sys_drive + ":\\" + r'$Extend\$RmMetadata\$TxfLog\$TxfLogContainer000000000000000000' + "{:02d}".format(
                index) + "\""
            returned_code, out = self.exe_cmd_and_get_ret(cmd)
            self.logger.info(cmd)
            self.logger.info(out)

        # 这个代码没有必要，是识判加入的。
        # cmd = r'{} "{}" 6'.format("filesysapi.exe", sys_dir)
        # returned_code, out = self.exe_cmd_and_get_ret(cmd)
        # self.logger.info(cmd)
        # self.logger.info(out)
        # self.logger.info(r'returned_code:{}\n'.format(returned_code))
        # if (returned_code != 0) and ((returned_code & 0xffff) != 0x301):
        #     self.raise_logic_error(r'returned_code != 0 : {} '.format(cmd), returned_code)

        cmd = r'{} "{}" 2'.format("filesysapi.exe", sys_dir)
        returned_code, out = self.exe_cmd_and_get_ret(cmd)
        self.logger.info(cmd)
        self.logger.info(out)
        self.logger.info(r'returned_code:{}\n'.format(returned_code))
        if (returned_code != 0) and ((returned_code & 0xffff) != 0x301):
            self.raise_logic_error(r'returned_code != 0 : {} '.format(cmd), returned_code)


if __name__ == "__main__":
    r = Runner()
    r.work()
