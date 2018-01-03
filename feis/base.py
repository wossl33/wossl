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

# 公私钥校验
def pub_priv_checker(pub_pem_data,key_pem_data,pass_key=None):
    try:
        pub_key=serialization.load_pem_public_key(pub_pem_data,backend=default_backend())
    except Exception,e:
        return {'error':False,'msg':u'公钥内容错误！'}

    try:
        priv_key=serialization.load_pem_private_key(key_pem_data,password=pass_key,backend=default_backend())
    except Exception,e:
        return {'error':False,'msg':u'私钥内容或KEY错误！'}
    public_key=pub_key.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    key_public_key=priv_key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    if public_key == key_public_key:
        return {'error':True,'msg':u'匹配成功！'}
    else:
        return {'error':False,'msg':u'匹配失败！'}

# 公私钥对生成
def pub_priv_creater(mysf,myqd,key_pass):
    if mysf == 'RSA':
        private_key=rsa.generate_private_key(
            public_exponent=65537,
            key_size=int(myqd),
            backend=default_backend()
        )
        if key_pass:
            key=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(key_pass),
            )
        else:
            key=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        public_key=private_key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        return {'error':True,'pub_key':public_key,'priv_key':key}
    elif mysf == 'DSA':
        private_key=dsa.generate_private_key(
            key_size=int(myqd),
            backend=default_backend()
        )
        if key_pass:
            key=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(key_pass),
            )
        else:
            key=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        public_key=private_key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        return {'error':True,'pub_key':public_key,'priv_key':key}
    elif mysf =='ECDSA':
        if myqd == 'P192':
            private_key=ec.generate_private_key(
                curve=ec.SECP192R1(),
                backend=default_backend()
            )
        elif myqd == 'P224':
            private_key=ec.generate_private_key(
                curve=ec.SECP224R1(),
                backend=default_backend()
            )
        elif myqd == 'P256':
            private_key=ec.generate_private_key(
                curve=ec.SECP256R1(),
                backend=default_backend()
            )
        elif myqd == 'P384':
            private_key=ec.generate_private_key(
                curve=ec.SECP384R1(),
                backend=default_backend()
            )
        elif myqd == 'P521':
            private_key=ec.generate_private_key(
                curve=ec.SECP521R1(),
                backend=default_backend()
            )
        else:
            private_key=ec.generate_private_key(
                curve=ec.SECP256R1(),
                backend=default_backend()
            )

        if key_pass:
            key=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(key_pass),
            )
        else:
            key=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        public_key=private_key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        return {'error':True,'pub_key':public_key,'priv_key':key}
    else:
        return {'error':False,'pub_key':u'选择加密算法错误！'}

# 私钥密码修改
def private_xiugai(key_pem_data,old_key,new_key):
    try:
        priv_key=serialization.load_pem_private_key(key_pem_data,password=old_key,backend=default_backend())
    except Exception,e:
        return {'error':False,'msg':u'私钥内容或原密码错误！'}

    try:
        new_priv_key=priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(new_key),
        )
    except Exception,e:
        return {'error':False,'msg':u'新密码格式错误！'}
    return {'error':True,'new_key':new_priv_key,'new_pass':new_key}