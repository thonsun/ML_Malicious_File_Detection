#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import argparse
import time
import docfileparser
import numpy as np
import pickle


# args details
parser = argparse.ArgumentParser(description='MS File Analysis Tool')
parser.add_argument('FileName', metavar='FileName', type=str,
                   help='PDF FileName')

args = parser.parse_args()
t1 = time.time()

mal = False

feature = docfileparser.start_cfb_extact(args.FileName)
print(feature) # 返回的特征向量
feature = np.array(feature)
with open("knn.pkl",'rb') as f:
    rf = pickle.load(f)
    res = rf.predict(feature.reshape(1,-1))[0]
    if res == 1:
        mal = True

# output file malicious
if mal:
    print('Malicious!')
else:
    print('None!')

t2 = time.time()
print('run time:', t2 - t1, 'sec')
sys.exit()
