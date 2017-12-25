# -*- coding:utf-8 -*-
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def cer_csr(cer_pem_data,csr_pem_data):
    cer=None
    csr=None
    try:
        cer=x509.load_pem_x509_certificate(cer_pem_data,default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'证书内容错误！'}

    try:
        csr=x509.load_pem_x509_csr(csr_pem_data,default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'CSR内容错误！'}

    if isinstance(cer,x509.Certificate) and isinstance(csr,x509.CertificateSigningRequest):
        # 公钥明文
        cer_public_key=cer.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        csr_public_key=csr.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        if cer_public_key == csr_public_key:
            return {'error':True,'msg':u'匹配成功！'}
        else:
            return {'error':False,'msg':u'匹配失败！'}
    else:
        return {'error':False,'msg':u'证书/CSR内容错误！'}

def csr_key(csr_pem_data,key_pem_data,key_passwd=None):
    csr=None
    key=None

    try:
        csr=x509.load_pem_x509_csr(csr_pem_data,default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'CSR内容错误！'}

    try:
        key=serialization.load_pem_private_key(key_pem_data,password=key_passwd,backend=default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'私钥内容错误！'}
    if isinstance(csr,x509.CertificateSigningRequest):
        csr_public_key=csr.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        key_public_key=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        if csr_public_key == key_public_key:
            return {'error':True,'msg':u'匹配成功！'}
        else:
            return {'error':False,'msg':u'匹配失败！'}
    else:
        return {'error':False,'msg':u'CSR/私钥内容错误！'}

def cer_key(cer_pem_data,key_pem_data,key_passwd=None):
    cer=None
    key=None
    try:
        cer=x509.load_pem_x509_certificate(cer_pem_data,default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'证书内容错误！'}
    try:
        key=serialization.load_pem_private_key(key_pem_data,password=key_passwd,backend=default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'私钥内容错误！'}
    if isinstance(cer,x509.Certificate):
        # 公钥明文
        cer_public_key=cer.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        key_public_key=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        if csr_public_key == key_public_key:
            return {'error':True,'msg':u'匹配成功！'}
        else:
            return {'error':False,'msg':u'匹配失败！'}
    else:
        return {'error':False,'msg':u'证书/私钥内容错误！'}

def jjm_1(key_pem_data,pass_key):
    try:
        key=serialization.load_pem_private_key(key_pem_data,password=None,backend=default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'私钥内容/密码错误！'}
    result={}
    try:
        result['key_string']=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(pass_key)
        )
    except Exception,e:
        print e
        return {'error':False,'msg':u'密码错误！'}
    result['key']=pass_key
    return {'error':True,'msg':result}

def jjm_2(key_pem_data,pass_key):
    try:
        key=serialization.load_pem_private_key(key_pem_data,password=pass_key,backend=default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'私钥内容/密码错误！'}
    result={}
    try:
        result['key_string']=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    except Exception,e:
        print e
        return {'error':False,'msg':u'密码错误！'}
    result['key']=pass_key
    return {'error':True,'msg':result}    

if __name__=='__main__':
    cer_pem_data=b''
    try:
        with open('./key.pem','rb') as f:
            cer_pem_data=f.read()
    except Exception as e:
        print(e)
    
    print jjm_2(cer_pem_data,'123456')
