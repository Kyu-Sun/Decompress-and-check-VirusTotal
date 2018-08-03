# -*- coding:utf8 -*-
# author : Kyusun Shim
# ----Base code info----
# Original Script Author: Adam Meyers
# Rewritten & Modified: Chris Clark
# ------------------------

from __future__ import division
import json, urllib, urllib2, hashlib, re
from pprint import pprint
import zipfile
import os
import patoolib
import pandas as pd
from time import sleep
import requests
import sys
import string

reload(sys)
sys.setdefaultencoding('utf-8')

commpress_file_ext_list = ['.zip', '.rar', '.tar', '.egg']


class UNZip():
    def __init__(self):
        self.decompress_file_list = list()

    def getDecompressFileList(self):
        return self.decompress_file_list

    def decompressFile(self, path_name):
        for file in self.search(path_name):
            target_path = path_name + file
            if os.path.isdir(target_path):
                self.decompressFile(target_path + "\\")
            else:
                fname, ext = os.path.splitext(target_path)
                # If file is binary, add to the list
                if self.isbinaryfile(target_path):
                    self.decompress_file_list.append(target_path)

                if ext in commpress_file_ext_list:
                    dir_name = path_name + os.path.splitext(file)[0] + "_unzip"
                    os.makedirs(dir_name)

                    if commpress_file_ext_list.index(ext) == 0:
                        self.deCompressZip(target_path, dir_name)
                    elif commpress_file_ext_list.index(ext) == 1:
                        self.deCompressRAR(target_path, dir_name)

    def deCompressZip(self, _target_path, _dir_name):
        zipfile.is_zipfile(_target_path)
        unzip_file = zipfile.ZipFile(_target_path)
        unzip_file.extractall(_dir_name)
        self.decompressFile(_dir_name + "\\")

    def deCompressRAR(self, _target_path, _dir_name):
        patoolib.extract_archive(_target_path, outdir=_dir_name)
        self.decompressFile(_dir_name + "\\")

    def search(self, path_name):
        filename_list = os.listdir(path_name)
        return filename_list

    def allSearch(self, path_name):
        filenames = os.listdir(path_name)
        for filename in filenames:
            full_filename = os.path.join(path_name, filename)
            if os.path.isdir(full_filename):
                self.allSearch(full_filename)
            else:
                # If file is binary, add to the list
                if self.isbinaryfile(full_filename):
                    self.decompress_file_list.append(full_filename)

    def isbinaryfile(self, filename):
        s = open(filename, 'r').read(512)
        text_characters = "".join(map(chr, range(32,127)) + list("\n\r\t\b"))
        _null_trans = string.maketrans("","")
        if not s:
            #Empty files are considered text
            return False
        if "\0" in s:
            #Files with null bytes are likely binary
            return True
        # Get the non-text characters (map a character to itself then
        # use the 'remove' option to get rid of the text characters.)
        t = s.translate(_null_trans, text_characters)
        # If more than 30% non-text characters, then
        # this is considered a binary file
        if float(len(t))/float(len(s)) > 0.30:
            return True
        return False


class vtAPI():

    def __init__(self, key_file_name):
        self.api = '<--------------PRIVATE-API-KEY-GOES-HERE----->'
        self.base = 'https://www.virustotal.com/vtapi/v2/'
        f = open(key_file_name, 'r')
        self.api = f.readline()

    def getReport(self, md5):
        try:
            param = {'resource': md5, 'apikey': self.api, 'allinfo': '1'}
            url = self.base + "file/report"
            data = urllib.urlencode(param)
            result = urllib2.urlopen(url, data)
            jdata = json.loads(result.read())
            #print jdata
            return jdata
        except:
            e = sys.exc_info()[0]
            print e
            return 0


    def scan(self, _files):
        try:
            param = {'apikey': self.api}
            files = {'file':(_files, open(_files), 'rb')}
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params = param)
            result = response.json()
        except:
            e = sys.exc_info()[0]
            print e
            pass

    def rescan(self, _md5):
        try:
            param = {'resource':_md5, 'apikey': self.api}
            url = self.base + "file/rescan"
            data = urllib.urlencode(param)
            result = urllib2.urlopen(url, data)
            jdata = json.loads(result.read())
            return jdata['response_code']
        except:
            e = sys.exc_info()[0]
            print e
            return -1
# Md5 Function

def checkMD5(checkval):
    if re.match(r"([a-fA-F\d]{32})", checkval) == None:
        md5 = md5sum(checkval)
        return md5.upper()
    else:
        return checkval.upper()


def md5sum(filename):
    fh = open(filename, 'rb')
    m = hashlib.md5()
    while True:
        data = fh.read(8192)
        if not data:
            break
        m.update(data)
    return m.hexdigest()


def parse(it, md5, file_name):
    antiVirus_rows = list()
    detected_rows = list()
    Result_rows = list()
    Version_rows = list()
    update_rows = list()
    if it == 0:
        print "JSON is null"
        return 0
    if int(it['response_code']) == 0:
        print md5 + " -- Not Found in VT"
        return 0
    elif int(it['response_code']) == -2:
        print md5 + " -- Queuing in VT"
        return -2
    elif int(it['positives']) > 0:
        print "Checked Virus File: ", it['positives'],  ' / ', it['total']
        virus_result = it['positives'],  ' / ', it['total']
        rows = [file_name, md5, it['permalink'], virus_result]
        pd_frame = pd.DataFrame(rows)
        pd_frame.to_csv("result.csv", mode='a')

        for x in it['scans']:
            #   print '\t', x, '\t' if len(x) < 7 else '', '\t' if len(x) < 14 else '', '\t', it['scans'][x][
            #       'detected'], '\t', it['scans'][x]['result'], '\t', it['scans'][x]['version'], '\t', it['scans'][x]['update']
            antiVirus_rows.append(x)
            detected_rows.append(it['scans'][x]['detected'])
            Result_rows.append(it['scans'][x]['result'])
            Version_rows.append(it['scans'][x]['version'])
            update_rows.append(it['scans'][x]['update'])


        dic = {'AntiVirus': antiVirus_rows,
               'Detected': detected_rows,
               'Result': Result_rows,
               'Update': update_rows,
               'Version': Version_rows}
        frame = pd.DataFrame(dic)
        frame.to_csv("result.csv", mode="a")
        return 1
    else:
        print "Not Virus File"

def GetFileList(path, is_compressed):
    uzip = UNZip()
    if is_compressed:
        uzip.decompressFile(path)
    else:
        uzip.allSearch(path)
    file_list = uzip.getDecompressFileList()
    return file_list


def main():
    file_list = GetFileList("C:\\Users\\test32\\Desktop\\test\\", False)
    md5_list = list()
    queing_list = list()
    cnt = 0
    check_count = 0
    tot_cnt = len(file_list)
    vt = vtAPI("publicKey.txt")
    for file_name in file_list:
        file_info = os.stat(file_name)
        check_count = check_count + 1
        print "Processed : ", check_count, "/", tot_cnt
        if file_info.st_size < 31457280:
            md5 = checkMD5(file_name)
            print file_name, md5
            if md5 not in md5_list:
                md5_list.append(md5)
                ret_code = vt.rescan(md5)
                if int(ret_code) == 0:
                    vt.scan(file_name)
                    queing_list.append([md5, file_name])
                    print "Recheck Again"
                elif int(ret_code) == -1:
                    print "Exception Error"
                else:
                    parse(vt.getReport(md5), md5, file_name)
                cnt = cnt + 1
                if cnt % 2 == 0:
                    sleep(60)
        else:
            print file_name + " : Size is greater than 30MB(Limit VT API)"



    for recheck_md5, file_name in queing_list:
        vt.rescan(recheck_md5)
        parse(vt.getReport(recheck_md5), recheck_md5, file_name)
    print "Total Checked Files : ", len(file_list)
    print "Total Sending Files : ",len(md5_list)
    print "Total ReChecked Files : ", len(queing_list)

#Module Test
    # file_name = "Cases.dll"
    # md5 = checkMD5(file_name)
    # vt=vtAPI("publicKey.txt")
    # vt.scan(file_name)
    # parse(vt.getReport(md5), md5, file_name)

     # vt=vtAPI("publicKey.txt")
     # vt.rescan("20F36363556DDD8FB22903E5FCB922F0")
     # parse(vt.getReport("20F36363556DDD8FB22903E5FCB922F0"), "20F36363556DDD8FB22903E5FCB922F0", "AAAA")



if __name__ == '__main__':
    main()
