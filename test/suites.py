from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from create_key import key,default_backend,serialization
#create a csr
csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    # Provide various details about who we are.
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
])).add_extension(x509.SubjectAlternativeName([
    # Describe what sites we want this certificate for.
    x509.DNSName(u"mysite.com"),
    x509.DNSName(u"www.mysite.com"),
    x509.DNSName(u"subdomain.mysite.com"),
]),
critical=False,
# Sign the CSR with our private key.
).sign(key,hashes.SHA256(),default_backend())

def create_csr(com_name,bumen_name,zuzhi_name,city_name,shengfen_name,guojia_name,mysf,beiyong_name,myqd,qmsf,key_pass):
    private_key=None
    if mysf == 'RSA':
        csr_subject_name=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, guojia_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, shengfen_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, zuzhi_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, bumen_name),
        x509.NameAttribute(NameOID.COMMON_NAME, com_name),
        ]))
        csr.add_extension()
    #create a csr
    csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, guojia_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, shengfen_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, zuzhi_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, bumen_name),
        x509.NameAttribute(NameOID.COMMON_NAME, com_name),
    ])).add_extension(x509.SubjectAlternativeName([
        # Describe what sites we want this certificate for.
        x509.DNSName(u"mysite.com"),
        x509.DNSName(u"www.mysite.com"),
        x509.DNSName(u"subdomain.mysite.com"),
    ]),
    critical=False,
    # Sign the CSR with our private key.
    ).sign(key,hashes.SHA256(),default_backend())
    return None
if __name__ == '__main__':
    try:
        with open("./csr.pem","wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
            print("csr create is ok")
    except Exception as e:
        print(e)
    
    try:
        with open('./key.pem','wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
            print('private key is ok')
    except Exception as e:
        print(e)
    