# -*- coding:utf-8 -*-
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa,dsa,ec
from binascii import b2a_hex

# 对字符串进行按长度分割
def split_string(string,width):
    if isinstance(string,str):
        string=string
    else:
        string=str(int(string))
    return '\n'.join([string[i:i+width] for i in range(0,len(string),width)])

# 公钥提取
def pubkey_tiqu(key_pem_data,key_passwd=None):
    try:
        key=serialization.load_pem_private_key(key_pem_data,password=key_passwd,backend=default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'私钥解析失败！'}
    public_key_pem=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    public_key_der=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    return {'error':True,'public_key_pem':public_key_pem,'public_key_der':b2a_hex(public_key_der)}

# 公钥解析
def pubkey_asysi(public_pem_data):
    public_key=None
    rep_reuslt={}
    try:
        public_key=serialization.load_pem_public_key(public_pem_data,backend=default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'公钥解析失败！'}
    # 密钥类型
    if isinstance(public_key,rsa.RSAPublicKey):
        rep_reuslt['public_key']="RSA"
        rep_reuslt['public_key_n']=split_string(public_key.public_numbers().n,64)
        rep_reuslt['public_key_e']=public_key.public_numbers().e
    elif isinstance(public_key,dsa.DSAPublicKey):
        rep_reuslt['public_key']="DSA"
        rep_reuslt['public_key_y']=split_string(public_key.public_numbers().y,64)
    elif isinstance(public_key,ec.EllipticCurvePublicKey):
        rep_reuslt['public_key']="ECDSA"
        rep_reuslt['public_key_x']=split_string(public_key.public_numbers().x,64)
        rep_reuslt['public_key_y']=split_string(public_key.public_numbers().y,64)
    else:
        return {'error':False,'msg':u'无法识别密钥类型！'}
    rep_reuslt['public_key_size']=public_key.key_size
    rep_reuslt['public_key_der']=b2a_hex(public_key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
    return {'error':True,'msg':rep_reuslt}
