# -*- coding:utf-8 -*-
from Crypto.Cipher import DES,DES3,AES
from Crypto.Util import Counter
from binascii import b2a_hex, a2b_hex
from base64 import b64encode,b64decode

def encrypt(text,cipher_flag,key,mode,iv,out_mode):
    try:
        if cipher_flag == 'AES':
            if mode == 'ECB':
                cryptor = AES.new(key,AES.MODE_ECB)
            elif mode == 'CBC':
                cryptor = AES.new(key,AES.MODE_CBC,iv)
            elif mode == 'CFB':
                cryptor = AES.new(key,AES.MODE_CFB,iv)
            elif mode == 'OFB':
                cryptor = AES.new(key,AES.MODE_OFB,iv)
            elif mode == 'CTR':
                cryptor = AES.new(key,AES.MODE_CTR,counter=Counter.new(AES.block_size*8))
            else:
                return {'error':False,'msg':u'未知模式！'}
    except Exception,e:
        print e
        return {'error':False,'msg':u'key或iv长度错误！'}
    try:
        if cipher_flag == 'DES':
            if mode == 'ECB':
                cryptor = DES.new(key,DES.MODE_ECB)
            elif mode == 'CBC':
                cryptor = DES.new(key,DES.MODE_CBC,iv)
            elif mode == 'CFB':
                cryptor = DES.new(key,DES.MODE_CFB,iv)
            elif mode == 'OFB':
                cryptor = DES.new(key,DES.MODE_OFB,iv)
            elif mode == 'CTR':
                cryptor = DES.new(key,DES.MODE_CTR,counter=Counter.new(DES.block_size*8))
            else:
                return {'error':False,'msg':u'未知模式！'}
    except Exception,e:
        print e
        return {'error':False,'msg':u'key或iv长度错误！'}
    try:
        if cipher_flag == '3DES':
            if mode == 'ECB':
                cryptor = DES3.new(key,DES3.MODE_ECB)
            elif mode == 'CBC':
                cryptor = DES3.new(key,DES3.MODE_CBC,iv)
            elif mode == 'CFB':
                cryptor = DES3.new(key,DES3.MODE_CFB,iv)
            elif mode == 'OFB':
                cryptor = DES3.new(key,DES3.MODE_OFB,iv)
            elif mode == 'CTR':
                cryptor = DES3.new(key,DES3.MODE_CTR,counter=Counter.new(DES3.block_size*8))
            else:
                return {'error':False,'msg':u'未知模式！'}
    except Exception,e:
        print e
        return {'error':False,'msg':u'key或iv长度错误！'}
    #这里密钥key 长度必须为16（AES-128）,
    #24（AES-192）,或者32 （AES-256）Bytes 长度
    #目前AES-128 足够目前使用
    length = 16
    count = len(text)
    if count < length:
        add = (length-count)
        #\0 backspace
        text = text + ('\0' * add)
    elif count > length:
        add = (length-(count % length))
        text = text + ('\0' * add)
    try:
        ciphertext = cryptor.encrypt(text)
    except Exception,e:
        return {'error':False,'msg':u'加密失败！'}
    #因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
    #所以这里统一把加密后的字符串转化为16进制字符串
    if out_mode =='base64':
        return {'error':True,'msg':b64encode(ciphertext)}
    elif out_mode =='hex':
        return {'error':True,'msg':b2a_hex(ciphertext)}
    else:
        return {'error':True,'msg':b2a_hex(ciphertext)}

def decrypt(text,cipher_flag,key,mode,iv,out_mode):
    try:
        if cipher_flag == 'AES':
            if mode == 'ECB':
                cryptor = AES.new(key,AES.MODE_ECB)
            elif mode == 'CBC':
                cryptor = AES.new(key,AES.MODE_CBC,iv)
            elif mode == 'CFB':
                cryptor = AES.new(key,AES.MODE_CFB,iv)
            elif mode == 'OFB':
                cryptor = AES.new(key,AES.MODE_OFB,iv)
            elif mode == 'CTR':
                cryptor = AES.new(key,AES.MODE_CTR,counter=Counter.new(AES.block_size*8))
            else:
                return {'error':False,'msg':u'未知模式！'}
    except Exception,e:
        return {'error':False,'msg':u'key或iv长度错误！'}
    try:
        if cipher_flag == 'DES':
            if mode == 'ECB':
                cryptor = DES.new(key,DES.MODE_ECB)
            elif mode == 'CBC':
                cryptor = DES.new(key,DES.MODE_CBC,iv)
            elif mode == 'CFB':
                cryptor = DES.new(key,DES.MODE_CFB,iv)
            elif mode == 'OFB':
                cryptor = DES.new(key,DES.MODE_OFB,iv)
            elif mode == 'CTR':
                cryptor = DES.new(key,DES.MODE_CTR,counter=Counter.new(DES.block_size*8))
            else:
                return {'error':False,'msg':u'未知模式！'}
    except Exception,e:
        print e
        return {'error':False,'msg':u'key或iv长度错误！'}
    try:
        if cipher_flag == '3DES':
            if mode == 'ECB':
                cryptor = DES3.new(key,DES3.MODE_ECB)
            elif mode == 'CBC':
                cryptor = DES3.new(key,DES3.MODE_CBC,iv)
            elif mode == 'CFB':
                cryptor = DES3.new(key,DES3.MODE_CFB,iv)
            elif mode == 'OFB':
                cryptor = DES3.new(key,DES3.MODE_OFB,iv)
            elif mode == 'CTR':
                cryptor = DES3.new(key,DES3.MODE_CTR,counter=Counter.new(DES3.block_size*8))
            else:
                return {'error':False,'msg':u'未知模式！'}
    except Exception,e:
        return {'error':False,'msg':u'key或iv长度错误！'}
    try:
        if out_mode =='base64':
            return {'error':True,'msg':cryptor.decrypt(b64decode(text)).rstrip('\0').decode('utf-8')}
        elif out_mode =='hex':
            return {'error':True,'msg':cryptor.decrypt(a2b_hex(text)).rstrip('\0').decode('utf-8')}
        else:
            return {'error':True,'msg':cryptor.decrypt(a2b_hex(text)).rstrip('\0').decode('utf-8')}
    except Exception,e:
        print e
        return {'error':False,'msg':u'解密失败！'}

if __name__=='__main__':
    print encrypt(b'xxxx','DES','zzzzxyz2zzz3wwww','CTR','00000000','base64')