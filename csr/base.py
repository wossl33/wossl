# -*- coding:utf-8 -*-
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,dsa,ec
import datetime
import binascii

# 对字符串进行按长度分割
def split_string(string,width):
    if isinstance(string,str):
        string=string
    else:
        string=str(int(string))
    return '\n'.join([string[i:i+width] for i in range(0,len(string),width)])

# 读取CSR内容
def readCSR(pem_req_data):
    csr=None
    try:
        csr=x509.load_pem_x509_csr(pem_req_data,default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'CSR内容错误！'}
    # csr句柄获取
    if isinstance(csr,x509.CertificateSigningRequest):
        rep_reuslt={}
        # 获取subject基本信息
        subject_check=['commonName','countryName','stateOrProvinceName','localityName','organizationName','organizationalUnitName']
        for attr in csr.subject:
            if attr.oid._name in subject_check:
                rep_reuslt[attr.oid._name]=attr.value
                subject_check.remove(attr.oid._name)
            
        for i in subject_check:
            rep_reuslt[i]=""
        # csr扩展信息
        public_extensions=[]
        if csr.extensions:
            try:
                for extension in csr.extensions:
                    for value in extension.value:
                        if isinstance(value,x509.DNSName):
                            public_extensions.append(value.value)
                rep_reuslt['extension']=','.join(public_extensions)
            except Exception,e:
                print e
                return {'error':False,'msg':u'CSR扩展错误！'}
        else:
            rep_reuslt['extension']=''
        # 获取密钥强度
        try:
            rep_reuslt['public_key_size']=str(csr.public_key().key_size)
        except Exception,e:
            return {'error':False,'msg':u'无法识别：未知加密算法！'}
        # 密钥类型
        if isinstance(csr.public_key(),rsa.RSAPublicKey):
            rep_reuslt['public_key']="RSA"
            rep_reuslt['public_key_n']=split_string(csr.public_key().public_numbers().n,64)
            rep_reuslt['public_key_e']=csr.public_key().public_numbers().e
        elif isinstance(csr.public_key(),dsa.DSAPublicKey):
            rep_reuslt['public_key']="DSA"
            rep_reuslt['public_key_y']=split_string(csr.public_key().public_numbers().y,64)
        elif isinstance(csr.public_key(),ec.EllipticCurvePublicKey):
            rep_reuslt['public_key']="ECDSA"
            rep_reuslt['public_key_x']=split_string(csr.public_key().public_numbers().x,64)
            rep_reuslt['public_key_y']=split_string(csr.public_key().public_numbers().y,64)
        else:
            rep_reuslt['public_key']=""
        # 签名算法
        if isinstance(csr.signature_hash_algorithm,hashes.MD5):
            rep_reuslt['sign_with']="MD5"
        elif isinstance(csr.signature_hash_algorithm,hashes.SHA1):
            rep_reuslt['sign_with']="SHA1"
        elif isinstance(csr.signature_hash_algorithm,hashes.SHA224):
            rep_reuslt['sign_with']="SHA224"
        elif isinstance(csr.signature_hash_algorithm,hashes.SHA256):
            rep_reuslt['sign_with']="SHA256"
        elif isinstance(csr.signature_hash_algorithm,hashes.SHA384):
            rep_reuslt['sign_with']="SHA384"
        elif isinstance(csr.signature_hash_algorithm,hashes.SHA512):
            rep_reuslt['sign_with']="SHA512"
        elif isinstance(csr.signature_hash_algorithm,hashes.BLAKE2b):
            rep_reuslt['sign_with']="BLAKE2b"
        elif isinstance(csr.signature_hash_algorithm,hashes.BLAKE2s):
            rep_reuslt['sign_with']="BLAKE2s"
        else:
            rep_reuslt['sign_with']=""
        # 签名信息及是否有效
        rep_reuslt['csr_signture']=split_string(binascii.hexlify(csr.signature),64)
        if csr.is_signature_valid:
            rep_reuslt['csr_sign_valid']=u"是"
        else:
            rep_reuslt['csr_sign_valid']=u"否"
        # 公钥明文
        rep_reuslt['public_key_string']=csr.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        return {'error':True,'msg':rep_reuslt}
    else:
        return {'error':False,'msg':u'对象类型错误！'}

# CSR创建    
def create_csr(com_name,bumen_name,zuzhi_name,city_name,shengfen_name,guojia_name,mysf,beiyong_name,myqd,qmsf,key_pass):
    private_key=None
    csr=None
    key=None
    try:
        if bumen_name:
            csr_subject_name=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                # Provide various details about who we are.
                x509.NameAttribute(NameOID.COUNTRY_NAME, guojia_name),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, shengfen_name),
                x509.NameAttribute(NameOID.LOCALITY_NAME, city_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, zuzhi_name),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, bumen_name),
                x509.NameAttribute(NameOID.COMMON_NAME, com_name),
                ]))
        else:
            csr_subject_name=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                # Provide various details about who we are.
                x509.NameAttribute(NameOID.COUNTRY_NAME, guojia_name),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, shengfen_name),
                x509.NameAttribute(NameOID.LOCALITY_NAME, city_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, zuzhi_name),
                x509.NameAttribute(NameOID.COMMON_NAME, com_name),
                ]))
    except Exception,e:
        print e
        return {'error':False,'msg':u'提交内容错误！'}
    try:
        dns_name=[x509.DNSName(i) for i in beiyong_name.split(',')]
    except Exception,e:
        print e
        return {'error':False,'msg':u'备用名请用逗号隔开！'}
    csr_add_extension=csr_subject_name.add_extension(x509.SubjectAlternativeName(dns_name),critical=False,)
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
        if qmsf == 'MD5':
            csr=csr_add_extension.sign(private_key,hashes.MD5(),default_backend())
        elif qmsf == 'SHA1':
            csr=csr_add_extension.sign(private_key,hashes.SHA1(),default_backend())
        elif qmsf == 'SHA224':
            csr=csr_add_extension.sign(private_key,hashes.SHA224(),default_backend())
        elif qmsf == 'SHA256':
            csr=csr_add_extension.sign(private_key,hashes.SHA256(),default_backend())
        elif qmsf == 'SHA384':
            csr=csr_add_extension.sign(private_key,hashes.SHA384(),default_backend())
        elif qmsf == 'SHA512':
            csr=csr_add_extension.sign(private_key,hashes.SHA512(),default_backend())
        else:
            csr=csr_add_extension.sign(private_key,hashes.SHA1(),default_backend())
        return {'error':True,'csr':csr.public_bytes(serialization.Encoding.PEM),'priv_key':key}
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
        if qmsf == 'SHA1':
            csr=csr_add_extension.sign(private_key,hashes.SHA1(),default_backend())
        elif qmsf == 'SHA224':
            csr=csr_add_extension.sign(private_key,hashes.SHA224(),default_backend())
        elif qmsf == 'SHA256':
            csr=csr_add_extension.sign(private_key,hashes.SHA256(),default_backend())
        else:
            csr=csr_add_extension.sign(private_key,hashes.SHA1(),default_backend())
        return {'error':True,'csr':csr.public_bytes(serialization.Encoding.PEM),'priv_key':key}
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
        if qmsf == 'SHA1':
            csr=csr_add_extension.sign(private_key,hashes.SHA1(),default_backend())
        elif qmsf == 'SHA224':
            csr=csr_add_extension.sign(private_key,hashes.SHA224(),default_backend())
        elif qmsf == 'SHA256':
            csr=csr_add_extension.sign(private_key,hashes.SHA256(),default_backend())
        elif qmsf == 'SHA384':
            csr=csr_add_extension.sign(private_key,hashes.SHA384(),default_backend())
        elif qmsf == 'SHA512':
            csr=csr_add_extension.sign(private_key,hashes.SHA512(),default_backend())
        else:
            csr=csr_add_extension.sign(private_key,hashes.SHA1(),default_backend())
        return {'error':True,'csr':csr.public_bytes(serialization.Encoding.PEM),'priv_key':key}

# 自签名证书创建
def create_cert(subject_com_name,subject_bumen_name,subject_zuzhi_name,subject_city_name,subject_shengfen_name,subject_guojia_name,issuer_com_name,issuer_zuzhi_name,issuer_guojia_name,root_flag,before_time,after_time,mysf,beiyong_name,myqd,qmsf,key_pass):
    key=None
    builder=None
    certificate=None
    try:
        if subject_bumen_name:
            builder=x509.CertificateBuilder().subject_name(x509.Name([
                # Provide various details about who we are.
                x509.NameAttribute(NameOID.COUNTRY_NAME, subject_guojia_name),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_shengfen_name),
                x509.NameAttribute(NameOID.LOCALITY_NAME, subject_city_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_zuzhi_name),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_bumen_name),
                x509.NameAttribute(NameOID.COMMON_NAME, subject_com_name),
                ]))
        else:
            builder=x509.CertificateBuilder().subject_name(x509.Name([
                # Provide various details about who we are.
                x509.NameAttribute(NameOID.COUNTRY_NAME, subject_guojia_name),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_shengfen_name),
                x509.NameAttribute(NameOID.LOCALITY_NAME, subject_city_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_zuzhi_name),
                x509.NameAttribute(NameOID.COMMON_NAME, subject_com_name),
                ]))
    except Exception,e:
        print e
        return {'error':False,'msg':u'提交内容错误！'}
    # 添加issuer信息
    builder=builder.issuer_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,issuer_com_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,issuer_zuzhi_name),
            x509.NameAttribute(NameOID.COUNTRY_NAME,issuer_guojia_name),
        ])
    )
    # 其他杂项    
    ##############
    try:
        builder=builder.not_valid_before(datetime.datetime.strptime(before_time,'%Y-%m-%d %H:%M:%S'))
        builder=builder.not_valid_after(datetime.datetime.strptime(after_time,'%Y-%m-%d %H:%M:%S'))
    except Exception,e:
        return {'error':False,'msg':u'过期时间小于颁发时间！'}
    builder=builder.serial_number(x509.random_serial_number())
    ##################
    try:
        dns_name=[x509.DNSName(i) for i in beiyong_name.split(',')]
    except Exception,e:
        print e
        return {'error':False,'msg':u'备用名请用逗号隔开！'}
    builder=builder.add_extension(x509.SubjectAlternativeName(dns_name),critical=False)

    builder=builder.add_extension(x509.BasicConstraints(ca=root_flag, path_length=None), critical=True,)

    #########################   
    
    #########################
    if mysf == 'RSA':
        private_key=rsa.generate_private_key(
            public_exponent=65537,
            key_size=int(myqd),
            backend=default_backend()
        )
        builder=builder.public_key(private_key.public_key())
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
        if qmsf == 'MD5':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.MD5(),backend=default_backend())
        elif qmsf == 'SHA1':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA1(),backend=default_backend())
        elif qmsf == 'SHA224':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA224(),backend=default_backend())
        elif qmsf == 'SHA256':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA256(),backend=default_backend())
        elif qmsf == 'SHA384':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA384(),backend=default_backend())
        elif qmsf == 'SHA512':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA512(),backend=default_backend())
        else:
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA1(),backend=default_backend())
        return {'error':True,'cert':certificate.public_bytes(serialization.Encoding.PEM),'priv_key':key}
    elif mysf == 'DSA':
        private_key=dsa.generate_private_key(
            key_size=int(myqd),
            backend=default_backend()
        )
        builder=builder.public_key(private_key.public_key())
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
        if qmsf == 'SHA1':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA1(),backend=default_backend())
        elif qmsf == 'SHA224':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA224(),backend=default_backend())
        elif qmsf == 'SHA256':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA256(),backend=default_backend())
        else:
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA1(),backend=default_backend())
        return {'error':True,'cert':certificate.public_bytes(serialization.Encoding.PEM),'priv_key':key}
    elif mysf =='ECDSA':
        if myqd == 'P192':
            private_key=ec.generate_private_key(
                curve=ec.SECP192R1(),
                backend=default_backend()
            )
            builder=builder.public_key(private_key.public_key())
        elif myqd == 'P224':
            private_key=ec.generate_private_key(
                curve=ec.SECP224R1(),
                backend=default_backend()
            )
            builder=builder.public_key(private_key.public_key())
        elif myqd == 'P256':
            private_key=ec.generate_private_key(
                curve=ec.SECP256R1(),
                backend=default_backend()
            )
            builder=builder.public_key(private_key.public_key())
        elif myqd == 'P384':
            private_key=ec.generate_private_key(
                curve=ec.SECP384R1(),
                backend=default_backend()
            )
            builder=builder.public_key(private_key.public_key())
        elif myqd == 'P521':
            private_key=ec.generate_private_key(
                curve=ec.SECP521R1(),
                backend=default_backend()
            )
            builder=builder.public_key(private_key.public_key())
        else:
            private_key=ec.generate_private_key(
                curve=ec.SECP256R1(),
                backend=default_backend()
            )
            builder=builder.public_key(private_key.public_key())

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
        if qmsf == 'SHA1':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA1(),backend=default_backend())
        elif qmsf == 'SHA224':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA224(),backend=default_backend())
        elif qmsf == 'SHA256':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA256(),backend=default_backend())
        elif qmsf == 'SHA384':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA384(),backend=default_backend())
        elif qmsf == 'SHA512':
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA512(),backend=default_backend())
        else:
            certificate=builder.sign(private_key=private_key,algorithm=hashes.SHA1(),backend=default_backend())
        return {'error':True,'cert':certificate.public_bytes(serialization.Encoding.PEM),'priv_key':key}