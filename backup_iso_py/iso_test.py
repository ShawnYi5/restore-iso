##=====================================================================================================
# 1：初始化 def init_dev(des_dir):
# des_dir：要打包iso的目录
#
# 2：拷贝驱动 inf 到目标
# def search_id(type, vid, hardward_id_list, compatible_id_list, src_path, des_dir):
# type：网络:net ; 磁盘 ;disk 注意大小写
# vid：厂商ID 十六进制：无 0x
# hardward_id_list :硬件ID list
# compatible_id_list : 兼容ID list
# src_path : inf 搜索库根目录，下面依次为 type ,再下面为 vid
# des_dir：要打包iso的目录
#
# 3：*****************此功能暂停*****************
# 拷贝磁盘驱动到目标
# def gen_install_disk_bat(vid, hardward_id_list, compatible_id_list, src_path, des_dir):
# vid：厂商ID 十六进制：无 0x
# hardward_id_list :硬件ID list
# compatible_id_list : 兼容ID list
# src_path : inf 搜索库根目录，下面依次为 type ,再下面为 vid
# des_dir：要打包iso的目录
#
# 4：设置网卡 IP 地址
# def set_ip_by_hardwrd_id_list_by_fix_py(hardward_id_list, NameServer, IPAddress_List, SubnetMask_List,
#                                        DefaultGateway_List, des_dir):
# hardward_id_list :硬件ID list
# NameServer ：DNS 服务器名字，字符串，多个名字用逗号间隔。
# IPAddress_List : IP地址，字符串 list
# SubnetMask_List：子网 字符串 list
# DefaultGateway_List : 网关  字符串 list
# des_dir：要打包iso的目录
#
# 5：保存一些信息到注册表。
# def save_dev_reg_info_by_fix_py(NameGUID, LocationInformation, HardwareID, UINumber, Address, fatherHardwareID,
#                                granpaHardwareID, ContainerID, des_dir):
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NAdrvIst\Parameters\000\
# 000，001,十进制3位数依次递增
# NameGUID		REG_SZ		//george 定义的GUID .. {2C6C5F28-B590-4D8E-8D29-4490F654FD71}
# instancePath	REG_SZ		//当前安装好的设备的instancePath
# LocationInformation REG_SZ	//设备的LocationInformation，从George传来。不是当前的。
# HardwareID	REG_MULTI_SZ	//设备的HardwareID，从George传来。不是当前的。
# UINumber	REG_DWORD		//设备的UINumber，从George传来。不是当前的。
# Address 	REG_DWORD		//设备的Address，从George传来。不是当前的。
# fatherHardwareID	REG_MULTI_SZ; //本设备上一级设备的硬件ID。
# granpaHardwareID	REG_MULTI_SZ; //本设备上上一级设备的硬件ID。
# ContainerID			REG_SZ	//本设备的Container ID.
#
# 6:打包ISO
# def packet_iso(src_iso_dir,des_iso_path):
# src_iso_dir: 要打包的ISO 目录。
# des_iso_path: ISO 目的地址。
##=====================================================================================================
import os
import traceback
import chardet
import shutil
import configparser

# dir (os)
# help (os)
install_drv_org = "install_drv_org.py"
install_drv = "install_drv.py"
install_reg_org = "install_reg_org.py"
install_reg = "install_reg.py"
install_disk_bat = "install_disk.bat"

g_inf_list_list = []


def get_file_charset(file_path):
    try:
        with open(file_path, 'rb') as file_obj:
            data = file_obj.read()
            return chardet.detect(data)['encoding']
    except:
        traceback.print_exc()


def copy_inf_dir_and_gen_install_drv_str_and_time(src_path, des_path, des_dir,list_line):
    global g_inf_list_list
    try:
        # config = configparser.ConfigParser()
        # 获取src_path的源目录。
        base_dir_name = os.path.basename(os.path.dirname(src_path))
        new_des_path = os.path.join(des_path, base_dir_name)
        # print(new_des_path)
        # 删除目标路径目录。
        # os.rmdir(new_des_path)
        shutil.rmtree(new_des_path, True)
        # 拷贝源目录到目标路径目录。
        try:
            shutil.copytree(os.path.dirname(src_path), new_des_path)
        except:
            pass
        # 建立配置文件。
        ini_des_path_str_1 = des_path[len(des_dir):len(des_path)]
        # ini_des_path_str_2 = src_path[src_path.find(ini_des_path_str_1) + len(ini_des_path_str_1):len(src_path)]
        ini_des_path = "." + ini_des_path_str_1 + "/" + os.path.basename(
            os.path.dirname(src_path)) + "/" + os.path.basename(src_path)
        # out_put_one_line_str = "    devcon_install_dev(r\'" + ini_des_path + "\')\n"
        # with open(os.path.join(des_dir, install_drv), 'a+') as out_put:
        #     out_put.write(out_put_one_line_str)
        print(ini_des_path)
        # 读取inf 内部版本号结中的时间。
        # config.read_file(file_obj)
        # config.sections()
        # str_inf_of_time = config.get("version", "DriverVer")
        for one_line in list_line:
            if 0 != one_line.find("DriverVer"):
                continue
            start_num=one_line.find("=")
            end_num=one_line.find(",")
            if -1 == start_num:
                continue
            if -1== end_num:
                continue
            if start_num >= end_num:
                continue
            str_inf_of_time = one_line[start_num+1:end_num]
            # str_inf_of_time = str_inf_of_time[0:str_inf_of_time.find(",")]
            mon = int(str_inf_of_time[0:str_inf_of_time.find("/")])
            str_inf_of_time = str_inf_of_time[str_inf_of_time.find("/") + 1:]
            day = int(str_inf_of_time[0:str_inf_of_time.find("/")])
            year = int(str_inf_of_time[str_inf_of_time.find("/") + 1:])
            all_day = year * 365 + mon * 30 + day
            inf_list = []
            inf_list.append(ini_des_path)
            inf_list.append(all_day)
            g_inf_list_list.append(inf_list)
            break
    except:
        traceback.print_exc()


def str_to_one_str(str):
    out_str = "r\"" + str + "\""
    return out_str


def str_list_to_one_str(list):
    out_str = "["
    try:
        for i in list:
            out_str = out_str + str_to_one_str(i) + ","
        if out_str[-1] == ',':
            out_str = out_str[0:len(out_str) - 1]
        out_str = out_str + "]"
        return out_str
    except:
        traceback.print_exc()
        return out_str


def set_ip_by_hardwrd_id_list_by_fix_py(hardward_id_list, NameServer, IPAddress_List, SubnetMask_List,
                                        DefaultGateway_List, des_dir):
    try:
        with open(os.path.join(des_dir, install_reg), 'a+') as out_put:
            write_str = "    set_ip_by_hardwrd_id_list("
            write_str = write_str + str_list_to_one_str(hardward_id_list) + ","
            write_str = write_str + str_to_one_str(NameServer) + ","
            write_str = write_str + str_list_to_one_str(IPAddress_List) + ","
            write_str = write_str + str_list_to_one_str(SubnetMask_List) + ","
            write_str = write_str + str_list_to_one_str(DefaultGateway_List) + ")\n"
            out_put.write(write_str)
    except:
        traceback.print_exc()


def save_dev_reg_info_by_fix_py(NameGUID, LocationInformation, HardwareID, UINumber, Address, fatherHardwareID,
                                granpaHardwareID, ContainerID, des_dir):
    try:
        with open(os.path.join(des_dir, install_reg), 'a+') as out_put:
            write_str = "    save_dev_reg_info("
            write_str = write_str + str_to_one_str(NameGUID) + ","
            write_str = write_str + str_to_one_str(LocationInformation) + ","
            write_str = write_str + str_list_to_one_str(HardwareID) + ","
            write_str = write_str + str(UINumber) + ","
            write_str = write_str + str(Address) + ","
            write_str = write_str + str_list_to_one_str(fatherHardwareID) + ","
            write_str = write_str + str_list_to_one_str(granpaHardwareID) + ","
            write_str = write_str + str_to_one_str(ContainerID) + ")\n"
            out_put.write(write_str)
    except:
        traceback.print_exc()


def bool_get_clean_sub_str_by_line(one_line, one_id):
    try:
        find_start = one_line.find(one_id)
        find_end = find_start + len(one_id)
        if -1 == find_start:
            return False
        # 判断头部，头部除空格，字符串起始，不能有其他字符。
        if 0 != find_start:
            if one_line[find_start - 1] != ' ':
                return False
        # 判断尾部，尾部除空格，字符串结束，'\r','\n'之外不能有其他字符。
        one_line_len = len(one_line)
        if find_end == len(one_line):
            return False
        if one_line[find_end] == '\r':
            return True
        if one_line[find_end] == '\n':
            return True
        if one_line[find_end] == ' ':
            return True
        return False
    except:
        traceback.print_exc()
        return False


def search_id_by_charset_name(hardward_id_list, compatible_id_list, charset_name, src_path, des_path, des_dir):
    try:
        with open(src_path, 'r', 1, charset_name) as file_obj:
            list_line = file_obj.readlines()
            for one_line in list_line:
                # if 'UTF-16LE' == charset_name:
                #     u_one_line = one_line
                #     print(one_line)
                # elif 'ascii' == charset_name:
                #     u_one_line = one_line.encode('utf-8')
                #     print (one_line)
                for one_id in hardward_id_list:
                    if bool_get_clean_sub_str_by_line(one_line, one_id):
                        # print(src_path)
                        # print(one_line)
                        copy_inf_dir_and_gen_install_drv_str_and_time(src_path, des_path, des_dir,list_line)
                        break

                for one_id in compatible_id_list:
                    if bool_get_clean_sub_str_by_line(one_line, one_id):
                        # print(src_path)
                        # print(one_line)
                        copy_inf_dir_and_gen_install_drv_str_and_time(src_path, des_path, des_dir,list_line)
                        break
                else:
                    continue
                break
    except:
        traceback.print_exc()


def search_id_in_not_know_charset_file(hardward_id_list, compatible_id_list, src_path, des_path, des_dir):
    try:
        charset_name = get_file_charset(src_path)
        if 'UTF-16LE' == charset_name:
            search_id_by_charset_name(hardward_id_list, compatible_id_list, charset_name, src_path, des_path, des_dir)
        elif 'ascii' == charset_name:
            search_id_by_charset_name(hardward_id_list, compatible_id_list, charset_name, src_path, des_path, des_dir)

    except:
        traceback.print_exc()


def get_inf_sort_key(x):
    return x[1]


def search_id(type, vid, hardward_id_list, compatible_id_list, src_path, des_dir):
    global g_inf_list_list
    vid = vid.upper()
    suffix = ['inf']
    if src_path[-1] == '/':
        src_path = src_path[0:-1]
    if des_dir[-1] == '/':
        des_dir = des_dir[0:-1]
    new_src_path = src_path + "/" + type + "/" + vid
    new_des_path = des_dir + "/inf/" + type + "/" + vid
    os.makedirs(new_des_path, 0o777, True)
    try:
        g_inf_list_list.clear()
        for root, dirs, files in os.walk(new_src_path):
            for file in files:
                file_suffix = file[file.find('.') + 1:len(file)]
                if file_suffix in suffix:
                    search_id_in_not_know_charset_file(hardward_id_list, compatible_id_list, os.path.join(root, file),
                                                       new_des_path, des_dir)
        # g_inf_list_list.sort(key=get_inf_sort_key,reverse = True)
        g_inf_list_list.sort(key=get_inf_sort_key)
        with open(os.path.join(des_dir, install_drv), 'a+') as out_put:
            for i in g_inf_list_list:
                out_put_one_line_str = "    devcon_install_dev(r\'" + hardward_id_list[0] + "\',r\'" + i[0] + "\')\r\n"
                out_put.write(out_put_one_line_str)
            # out_put_one_line_str = "    os.system('devcon rescan')\r\n"
            # out_put.write(out_put_one_line_str)
    except:
        traceback.print_exc()


def gen_install_disk_bat(vid, hardward_id_list, compatible_id_list, src_path, des_dir):
    global g_inf_list_list
    vid = vid.upper()
    type = "disk"
    suffix = ['inf']
    if src_path[-1] == '/':
        src_path = src_path[0:-1]
    if des_dir[-1] == '/':
        des_dir = des_dir[0:-1]
    new_src_path = src_path + "/" + type + "/" + vid
    new_des_path = des_dir + "/inf/" + type + "/" + vid
    os.makedirs(new_des_path, 0o777, True)
    try:
        g_inf_list_list.clear()
        for root, dirs, files in os.walk(new_src_path):
            for file in files:
                file_suffix = file[file.find('.') + 1:len(file)]
                if file_suffix in suffix:
                    search_id_in_not_know_charset_file(hardward_id_list, compatible_id_list, os.path.join(root, file),
                                                       new_des_path, des_dir)
        # g_inf_list_list.sort(key=get_inf_sort_key,reverse = True)
        g_inf_list_list.sort(key=get_inf_sort_key)
        with open(os.path.join(des_dir, install_disk_bat), 'a+') as out_put:
            for i in g_inf_list_list:
                out_put_one_line_str = "dism /Image:\"%1\" /Add-Driver /Driver:\"" + i[0] + "\" /ForceUnsigned\n"
                out_put.write(out_put_one_line_str)
    except:
        traceback.print_exc()


def init_dev(des_dir):
    try:
        if des_dir[-1] == '/':
            des_dir = des_dir[0:-1]
        try:
            try:
                os.remove(os.path.join(des_dir, install_disk_bat))
            except:
                pass
            try:
                os.remove(os.path.join(des_dir, install_drv))
            except:
                pass
            try:
                os.remove(os.path.join(des_dir, install_reg))
            except:
                pass
            shutil.copy(os.path.join(des_dir, install_drv_org), os.path.join(des_dir, install_drv))
            shutil.copy(os.path.join(des_dir, install_reg_org), os.path.join(des_dir, install_reg))
        except:
            traceback.print_exc()

    except:
        traceback.print_exc()


def packet_iso(src_iso_dir, des_iso_path):
    try:
        os.system("mkisofs -o " + des_iso_path + " -J -R -A -V -v " + src_iso_dir)
    except:
        traceback.print_exc()


if __name__ == "__main__":
    print("begin run")
    init_dev(r"D:\AIO\restore-iso")

    c_id_1 = r'PCI\VEN_15AD&DEV_07B0&REV_01'
    c_id_2 = r'PCI\VEN_15AD&DEV_07B0'
    c_id_3 = r'PCI\VEN_15AD&CC_020000'
    c_id_4 = r'PCI\VEN_15AD&CC_0200'
    c_id_5 = r'PCI\VEN_15AD'
    c_id_6 = r'PCI\CC_020000&DT_0'
    c_id_7 = r'PCI\CC_020000'
    c_id_8 = r'PCI\CC_0200&DT_0'
    c_id_9 = r'PCI\CC_0200'
    compatible_id_list = c_id_1, c_id_2, c_id_3, c_id_4, c_id_5, c_id_6, c_id_7, c_id_8, c_id_9

    h_id_1 = r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01'
    h_id_2 = r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD'
    h_id_3 = r'PCI\VEN_15AD&DEV_07B0&CC_020000'
    h_id_4 = r'PCI\VEN_15AD&DEV_07B0&CC_0200'
    hardward_id_list = h_id_1, h_id_2, h_id_3, h_id_4

    search_id("net", "8086", hardward_id_list, compatible_id_list, "D:/inf",r"D:\AIO\restore-iso")
    # gen_install_disk_bat("8086", hardward_id_list, compatible_id_list, "D:/inf",r"D:\AIO\restore-iso")

    # IPAddress_List = ["172.16.6.78"]
    # SubnetMask_List = ["255.255.255.0"]
    # DefaultGateway_List = ["172.16.1.1"]
    # set_ip_by_hardwrd_id_list_by_fix_py(hardward_id_list, "172.16.1.1,8.8.8.8", IPAddress_List, SubnetMask_List,
    #                                     DefaultGateway_List,r"D:\AIO\restore-iso")
    #
    # NameGUID = "{F5DDC77D-5D11-4418-AA34-E34FF6251726}"
    # LocationInformation = "LocationInformation1"
    # UINumber = 10
    # Address = 10
    # fatherHardwareID = ["fatherHardwareID1", "fatherHardwareID2"]
    # granpaHardwareID = ["granpaHardwareID1", "granpaHardwareID2"]
    # ContainerID = "abcdefg"
    # save_dev_reg_info_by_fix_py(NameGUID, LocationInformation, hardward_id_list, UINumber, Address, fatherHardwareID,
    #                             granpaHardwareID, ContainerID, "D:\AIO\restore-iso")
    #
    # packet_iso(r"D:\AIO\restore-iso", "d:/test.iso")
    print("end")
