import re
import sys
import requests
import subprocess
from multiprocessing.dummy import Pool as ThreadPool

class maSscan(object):
    def __init__(self, ip, port, thread='10000'):
        self.ip = ip
        self.port = port
        self.thread = thread
        self.sd = []
        self.ad = {}

    def porTscan(self):
        return subprocess.check_output(['masscan', '--open', '{}'.format(self.ip), '-p {}'.format(self.port), '--rate={}'.format(self.thread)])

    def outPut(self, ip, port):
        if ip in self.ad:
            self.ad[ip].append(port)
        else:
            self.ad.update({ip:[port]})

    def cleaNing(self, data):
        lineList = data
        for line in lineList:
            ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            findIP = re.findall(ipPattern, line)
            portPattern = re.compile('(\d+)/tcp')
            findPort = re.findall(portPattern, line)
            if len(findIP) != 0 and len(findPort) != 0:
                self.outPut(findIP[0],findPort[0])
                self.sd.append('{}:{}'.format(findIP[0],findPort[0]))
        print("------------------------------")
        print("----------prot scan-----------\n")
        for key in self.ad:
            print("IP: {}".format(key))
            print("PORT: {}".format(self.ad[key]))
            print()
        return self.sd

    def run(self):
        return self.cleaNing(self.porTscan().decode(encoding='utf-8').split('\n'))

def run(url):
    try:
        r = requests.get("http://{}/".format(url),timeout=10)
        if r.status_code == 400:
            r = requests.get("https://{}/".format(url),timeout=10)
        title = titlePattern.findall(r.text)
        if title:
            return r.url,title[0]
        else:
            return r.url,'Null'
    except:
        pass

masscan = maSscan(sys.argv[1],sys.argv[2],'1000').run()
titlePattern = re.compile('<title>(.*)</title>')
Pool = ThreadPool(int(1));results = Pool.map(run, masscan);Pool.close();Pool.join()
print("------------------------------")
print("----------title scan----------\n")
for line in results:
    if line != None:
        print("{0[0]}       {0[1]}".format(line))