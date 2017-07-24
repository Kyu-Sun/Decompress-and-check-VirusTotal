# -*- coding:utf8 -*-
# author : Kyusun Shim

import json, urllib, urllib2, hashlib, re
from pprint import pprint


class vtAPI():

    def __init__(self):
        self.api = '<--------------PRIVATE-API-KEY-GOES-HERE----->'
        self.base = 'https://www.virustotal.com/vtapi/v2/'

    def setApiKey(self, key):
        self.api = key

    def getReport(self, md5):
        param = {'resource': md5, 'apikey': self.api, 'allinfo': '1'}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url, data)
        jdata = json.loads(result.read())
        return jdata

    def rescan(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/rescan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        print "\n\tVirus Total Rescan Initiated for -- " + md5 + " (Requery in 10 Mins)"
        jdata = json.loads(result.read())
        return jdata
aaa

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

def parse(it, md5):
    if it['response_code'] == 0:
        print md5 + " -- Not Found in VT"
        return 0
    print "\n\tResults for MD5: ", it['md5'], "\n\n\tDetected by: ", it['positives'], '/', it['total'], '\n'
    if 'Sophos' in it['scans']:
        print '\tSophos Detection:', it['scans']['Sophos']['result'], '\n'
    if 'Kaspersky' in it['scans']:
        print '\tKaspersky Detection:', it['scans']['Kaspersky']['result'], '\n'
    if 'ESET-NOD32' in it['scans']:
        print '\tESET Detection:', it['scans']['ESET-NOD32']['result'], '\n'

    print '\tScanned on:', it['scan_date']

    print '\n\tVerbose VirusTotal Information Output:\n'
    for x in it['scans']:
        print '\t', x, '\t' if len(x) < 7 else '', '\t' if len(x) < 14 else '', '\t', it['scans'][x][
            'detected'], '\t', it['scans'][x]['result']

def main():
    f = open("publicKey.txt",'r')
    key = f.readline()
    HashorPath = "myfile.dll"
    vt = vtAPI()
    vt.setApiKey(key)
    md5 = checkMD5(HashorPath)
    vt.rescan(md5)
    parse(vt.getReport(md5), md5)

if __name__ == '__main__':
    main()