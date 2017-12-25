# -*- coding:utf-8 -*-
from Crypto.Hash import HMAC,MD2,MD4,MD5,SHA1,SHA224,SHA256,SHA384,SHA512,RIPEMD,RIPEMD160

def md_sha_hash(flag,text):
    hash_text=None
    if flag == 'MD2':
        h=MD2.new()
        h.update(text)
        hash_text=h.hexdigest()
    elif flag == 'MD4':
        h=MD4.new()
        h.update(text)
        hash_text=h.hexdigest()
    elif flag == 'MD5':
        h=MD5.new()
        h.update(text)
        hash_text=h.hexdigest()
    elif flag == 'SHA1':
        h=SHA1.new()
        h.update(text)
        hash_text=h.hexdigest()
    elif flag == 'SHA224':
        h=SHA224.new()
        h.update(text)
        hash_text=h.hexdigest()
    elif flag == 'SHA256':
        h=SHA256.new()
        h.update(text)
        hash_text=h.hexdigest()
    elif flag == 'SHA384':
        h=SHA384.new()
        h.update(text)
        hash_text=h.hexdigest()
    elif flag == 'SHA512':
        h=SHA512.new()
        h.update(text)
        hash_text=h.hexdigest()
    elif flag == 'RIPEMD':
        h=RIPEMD.new()
        h.update(text)
        hash_text=h.hexdigest()
    elif flag == 'RIPEMD160':
        h=RIPEMD160.new()
        h.update(text)
        hash_text=h.hexdigest()
    else:
        return {'error':False,'msg':u'未知hash算法！'}
    return {'error':True,'msg':hash_text}

def hmac_hash(text,key):
    h=HMAC.new(key)
    h.update(text)
    return {'error':True,'msg':h.hexdigest()}
