#coding:utf-8


import random

file = open('db_data', 'w')

list = range(0, 2048)

for key in list:
    value = random.randint(0, 1000000)
    file.write("%d, %d\n"% (key, value))

file.close()
