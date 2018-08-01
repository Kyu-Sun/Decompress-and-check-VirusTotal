# -*- coding:utf8 -*-
# author : Kyusun Shim
# ----Base code info----
# Original Script Author: Adam Meyers
# Rewritten & Modified: Chris Clark
# ------------------------


import json, urllib, urllib2, hashlib, re
from pprint import pprint
import csv
import zipfile
import os
import patoolib
import pandas as pd
from time import sleep

commpress_file_ext_list = ['.zip', '.rar', '.tar', '.egg']


class UNZip():
    def __init__(self):
        self.decompress_file_list = list()

    def getDecompressFileList(self):
        return self.decompress_file_list

    def decompressFile(self, path_name):
        for file in self.search(path_name):
            target_path = path_name + file
            #    print target_path
            if os.path.isdir(target_path):
                self.decompressFile(target_path + "\\")
            else:
                fname, ext = os.path.splitext(target_path)
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


class vtAPI():

    def __init__(self, key_file_name):
        self.api = '<--------------PRIVATE-API-KEY-GOES-HERE----->'
        self.base = 'https://www.virustotal.com/vtapi/v2/'
        f = open(key_file_name, 'r')
        self.api = f.readline()

    def getReport(self, md5):
        param = {'resource': md5, 'apikey': self.api, 'allinfo': '1'}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url, data)
        jdata = json.loads(result.read())
        print jdata
        return jdata

    def rescan(self, md5):
        param = {'resource': md5, 'apikey': self.api}
        url = self.base + "file/rescan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url, data)
        print "\n\tVirus Total Rescan Initiated for -- " + md5 + " (Requery in 10 Mins)"
        jdata = json.loads(result.read())
        return jdata


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

    if it['positives'] > 0:
        if it['response_code'] == 0:
            print md5 + " -- Not Found in VT"
            return 0

        print '\tScanned on:', it['scan_date']
        print '\n\tResult Link:', it['permalink']
       # print '\n\tVerbose VirusTotal Information Output:\n'

      #  print "\n\tResults for MD5: ", it['md5'], "\n\n\tDetected by: ", it['positives'], '/', it['total'], '\n'

        #print '\n\tAntiVirus\tDetected\tResult\tVersion\tUpdate date'
        # writeCSV(["AntiVirus", "Detected", "Result", "Version", "Update date"])
        for x in it['scans']:
            #   print '\t', x, '\t' if len(x) < 7 else '', '\t' if len(x) < 14 else '', '\t', it['scans'][x][
            #       'detected'], '\t', it['scans'][x]['result'], '\t', it['scans'][x]['version'], '\t', it['scans'][x]['update']
            antiVirus_rows.append(x)
            detected_rows.append(it['scans'][x]['detected'])
            Result_rows.append(it['scans'][x]['result'])
            Version_rows.append(it['scans'][x]['version'])
            update_rows.append(it['scans'][x]['update'])

        rows = [file_name, md5, it['permalink']]
        pd_frame = pd.DataFrame(rows)
        pd_frame.to_csv("result.csv", mode='a')

        dic = {'AntiVirus': antiVirus_rows,
               'Detected': detected_rows,
               'Result': Result_rows,
               'Update': update_rows,
               'Version': Version_rows}
        frame = pd.DataFrame(dic)
        frame.to_csv("result.csv", mode="a")


def reUnzip(path):
    uzip = UNZip()
    uzip.decompressFile(path)
    file_list = uzip.getDecompressFileList()
    return file_list


def main():
    file_list = reUnzip("C:\\Users\\NFS\\Desktop\\test\\test2\\test3\\")
    md5_list = list()
    cnt = 0;
    for file_name in file_list:
        #   HashorPath = "myfile.dll"

        md5 = checkMD5(file_name)
        print file_name, md5
        if md5 not in md5_list:
            md5_list.append(md5)

            vt = vtAPI("publicKey.txt")
            vt.rescan(md5)
            parse(vt.getReport(md5), md5, file_name)
            cnt = cnt + 1;
            print cnt
            if cnt % 2 == 0:
                sleep(60)

    print len(file_list)
    print len(md5_list)


if __name__ == '__main__':
    main()
