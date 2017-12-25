# -*- coding:utf-8 -*-

# 对字符串进行按长度分割
def split_string(string,width):
    if isinstance(string,str):
        string=string
    else:
        string=str(int(string))
    return '\n'.join([string[i:i+width] for i in range(0,len(string),width)])