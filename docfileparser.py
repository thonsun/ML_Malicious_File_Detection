#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2014-2017 Yuhei Otsubo
Released under the MIT license
http://opensource.org/licenses/mit-license.php
"""
import sys
import argparse
import re
# write csv
import csv

def chWord(line):
    ret = ord(chr(line[0]))+ord(chr(line[1]))*256
    return ret

def chDword(line):
    ret = ord(chr(line[0]))+(ord(chr(line[1]))<<8)+(ord(chr(line[2]))<<16)+(ord(chr(line[3]))<<24)
    return ret

def chInt(line):
    ret = ord(chr(line[0]))+(ord(chr(line[1]))<<8)+(ord(chr(line[2]))<<16)+(ord(chr(line[3]))<<24)
    if ret>0x80000000:
        ret -= 0x100000000
    return int(ret)

def sec_pos(SecID,sec_size):
    return 512+SecID*sec_size

def ssec_pos(SecID,sec_size):
    return SecID*sec_size

def readSAT(line,MSAT,sec_size):
    ret = []
    for SecID in MSAT:
        pos = sec_pos(SecID,sec_size)
        buf = line[pos:pos+sec_size]
        for i in range(int(sec_size/4)):
            var = chInt(buf[i*4:i*4+4])
            ret.append(var)
    return ret

def SATtoStream(line,sat,sec_size):
    ret = []
    for ary in sat:
        txt = ""
        for var in ary:
            txt += line[sec_pos(var,sec_size):sec_pos(var,sec_size)+sec_size]
        ret.append(txt)
    return ret

def SSATtoStream(line,sat,sec_size):
    ret = []
    for ary in sat:
        txt = ""
        for var in ary:
            txt += line[ssec_pos(var,sec_size):ssec_pos(var,sec_size)+sec_size]
        ret.append(txt)
    return ret

def deUni(uniline):
    ret = ""
    for i in range(int(len(uniline)/2)):
        ret += chr(chWord(uniline[i*2:i*2+2]))
    try:
        return str(ret)
    except:
        return "encode error"
# start
def start_cfb_extact(filename):
    with open(filename,'rb') as f:
        allLines = f.read()
        f.close()
        # print(allLines)
    # file format judge
    if allLines[0:8] ==b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
        print("This is DocFile")
    else:
        print("This file is not DocFile")
        sys.exit()

    row_list = []
    sec_size = 1<<chWord(allLines[30:32])
    ssec_size = 1<<chWord(allLines[32:34])
    num_sec = chDword(allLines[44:48])
    row_list.append(num_sec) # add #1
    DictSecID = chInt(allLines[48:52])
    mini_size = chDword(allLines[56:60])
    num_ssec = chDword(allLines[64:68])
    if chInt(allLines[60:64]) == 0:
        num_ssec = 0
    row_list.append(num_ssec) # add #2

    # file finished?
    unfinished_ms_file = 0
    if len(allLines) < 512 + 512 * ( 512 / 4 ) * (num_sec -1 ):
        unfinished_ms_file = 1
    row_list.append(unfinished_ms_file) # add #3

    #Sector Table
    msat = []
    next_sec = chInt(allLines[68:72])
    for i in range(109):
        var = chInt(allLines[76+i*4:80+i*4])
        if var != -1:
            msat.append(var)
    while next_sec >=0:#!= -2:
        for i in range((sec_size-4)/4):
            var = chInt(allLines[sec_pos(next_sec,sec_size)+i*4:sec_pos(next_sec,sec_size)+i*4+4])
            if var != -1:
                msat.append(var)
        next_sec = chInt(allLines[sec_pos(next_sec,sec_size)+sec_size-4:sec_pos(next_sec,sec_size)+sec_size])
    #print "MSAT:",msat
    #Sector Allocation Tableの読み込み
    sat = readSAT(allLines,msat,sec_size)
    #print "SAT:",sat

    #Short-Sector Allocation Tableの読み込み
    ssat = []
    next_sec = chInt(allLines[60:64])
    while next_sec >0:#!= -2:
        for i in range(int(sec_size/4)):
            var = chInt(allLines[sec_pos(next_sec,sec_size)+i*4:sec_pos(next_sec,sec_size)+i*4+4])
            ssat.append(var)
        next_sec = sat[next_sec]
    #print "SSAT:",ssat

    #Dictionary Streamの解析
    DirID = 0
    SSCS = ""
    next_sec = DictSecID
    DictSize = 0
    total_c_size = 0
    while next_sec >=0:#!= -2:
        DictSecPos = sec_pos(next_sec,sec_size)
        for i in range(4):
            Dict = allLines[DictSecPos:DictSecPos+128]
            #print i,
            #Directry Name
            name = deUni(Dict[:chWord(Dict[64:66])])
            f_empty = False
            if Dict[66] == '\x01':
                f_empty = True
                name = 'D:' + name
            elif Dict[66] == '\x00':
                f_empty = True
                name = 'Empty'
            elif Dict[66] == '\x02':
                name = 'U:' + name
            #Type of the entry:
            #print ord(Dict[66])
            f_id = chInt(Dict[116:120])
            #print "SecID of first sector or short-sector:",f_id,
            f_size = chDword(Dict[120:124])
            if f_empty:
                f_size = 0
            if f_size < mini_size:
                c_size = (f_size + ssec_size -1)/ssec_size*ssec_size
            else:
                c_size = (f_size + sec_size-1)/sec_size*sec_size
            if Dict[66] == '\x05':
                c_size = (f_size + sec_size-1)/sec_size*sec_size
            if f_size >= mini_size or Dict[66] == '\x05':#DirID != 0:
                #Root Entryの場合は足さない
                total_c_size += c_size

            DictSecPos += 128
            DirID += 1
        DictSize += 512
        if next_sec == sat[next_sec]:
            break
        next_sec = sat[next_sec]


    #未使用セクタの表示
    suspicious_file_size = 0
    l = len(allLines)
    if num_sec*sec_size*sec_size/4+512 < l:
        l = num_sec * sec_size*sec_size /4 + 512
        suspicious_file_size = 1
    row_list.append(suspicious_file_size)

    num_unused_block = 0
    unused_block =0
    for i in range(int(l/sec_size-1)):
        if sat[i] == -1:
            num_unused_block += 1
            unused_block = 1
    row_list.append(unused_block)

    suspisous_sector = 0
    if sat[int(l/sec_size)-1-1] == -1:
        suspisous_sector = 1
    row_list.append(suspisous_sector)

    #null blockの判定
    null_block = 0
    l = len(allLines)/sec_size
    num_null_block = 0
    for i in range(int(l)):
        f = True
        for j in range(sec_size):
            if allLines[i*sec_size+j] != '\x00':
                f = False
                break
        if f:
            num_null_block += 1
            null_block = 1
    row_list.append(null_block)

    #判定 unkowndoata
    # if len(allLines)-(num_sec+num_ssec+1)*sec_size-total_c_size-DictSize:
    #     row_list.append(1)
    # else:
    #     row_list.append(0)
    return row_list



