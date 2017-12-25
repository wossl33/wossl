# -*- coding:utf-8 -*-
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa,dsa,ec

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

if __name__=='__main__':
    print create_csr('US'.decode('utf-8'),''.decode('utf-8'),'US'.decode('utf-8'),'中国'.decode('utf-8'),'US'.decode('utf-8'),'US'.decode('utf-8'),'RSA',u'a,b',1024,'SHA512','11111')