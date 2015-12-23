#coding: utf-8

'''
tcpdumpformat是一个格式化tcpdump输出的工具。

在使用tcpdump查看传输数据的时候有两种方法，一种是使用tcpdump -w把分组数据写到一个文件，然后用wireshark之类的gui工具直接查看，另外一种是使用tcpdump -X来查看输出。

一般我们开发应用的时候有时候只需要关注tcp包的内容部分，ip头和tcp头一般用得不多，然后tcpdump并没有提供工具过滤这两个头。所以就写了这个脚本来处理。

这个工具的使用方法主要是吧tcpdump的16进制输出结果解析，通过解析ip协议的头长度和报文长度，还有tcp协议的头部长度，计算出具体的tcp起始位置，并重新格式化输出。

使用方法：

tcpdump -x ..... | python tcpdumpformat.py

注意，-x参数是必须的，省略号是一个抓取规则，按需输入。
'''
__author__ = 'liangguanhui'

import sys

HEX = "0123456789abcdef"
SKIP_EMPTY = True
LINE_COUNT = 32

def hex2byte(hexstr):
    assert len(hexstr) == 2
    return HEX.find(hexstr[0]) * 16 +  HEX.find(hexstr[1])

def byte2hex(b):
    return HEX[b / 16] + HEX[b % 16]

def printhex(data):
    ss = []
    for d in data:
        if d >= 32 and d <= 127:
            ss.append(chr(d))
        else:
            ss.append('.')
    return "".join(ss)

class Conf:
    def __init__(self, title):
        self.title = title
        self.iplen = -1
        self.tcplen = -1
        self.totallen = -1
        self.bodylen = -1
        self.data = []
        self.done = False

    def appendhex(self, line):
        hs = line.split()[:8]
        for h in hs:
            h1 = h[:2]
            self.data.append(hex2byte(h1))
            h2 = h[2:4]
            if h2:
                self.data.append(hex2byte(h2))

        if self.iplen < 0:
            if not self.data:
                raise Exception("error ip length")
            v = self.data[0] / 16
            if v != 4:
                raise Exception("Only support IPv4! %s" % v)
            iplen = (self.data[0] % 16) * 4
            if iplen < 20:
                raise Exception("Invalid ip len %s" % iplen)
            self.iplen = iplen
            #print "iplen:", iplen
        if self.totallen < 0:
            if len(self.data) > 4:
                self.totallen = self.data[2] * 256 + self.data[3]
                #print "totallen:", self.totallen
        if self.tcplen < 0:
            r = self.iplen + 12
            if r < len(self.data):
                tcplen = (self.data[r] / 16) * 4
                if tcplen < 20:
                    raise Exception("Invalid tcp len %s" % tcplen)
                self.tcplen = tcplen
                self.bodylen = self.totallen - self.iplen - self.tcplen
                #print "tcplen:", tcplen
                #print "bodylen:", self.bodylen
                #print "len(self.data):", len(self.data)

        if not self.done and len(self.data) >= self.totallen:
            #print "finish"
            headlen = self.iplen+self.tcplen
            body = self.data[headlen:self.totallen]
            n = 0
            if body or not SKIP_EMPTY:
                print self.title

            fmt = "  0x%04x: %-" + str(LINE_COUNT * 3 + 2) + "s %s"
            for idx in range(0, len(body), LINE_COUNT):
                sec = body[idx:idx+LINE_COUNT]
                left = " ".join([byte2hex(i) for i in sec])
                right = printhex(sec)
                print fmt % (n * LINE_COUNT, left, right)
                n += 1

            if body or not SKIP_EMPTY:
                print
            self.done = True

if len(sys.argv) > 1:
    if sys.argv[1] == "-h":
        print "usage: tcpdump -x ... | python %s" % sys.argv[0]
        sys.exit(0)
    if sys.argv[1] == "-e":
        SKIP_EMPTY = False

conf = None
#for line in open("input.txt"):
for line in sys.stdin:
    line = line.rstrip()
    if not line:
        continue
    if line.startswith(" 0x") or line.startswith("\t0x"):
        idx = line.find(":")
        if idx < 0:
            print "ERROR Format >>>>", line
            continue

        s = line[idx+1:].strip()
        if s:
            conf.appendhex(s)
    else:
        if conf and not conf.done:
            print "[ERROR] >>>>>>>>>>>>>>> it seems some section not done!!!!!"
        conf = Conf(line)









