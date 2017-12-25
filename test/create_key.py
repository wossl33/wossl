from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa,dsa,ec

key=ec.generate_private_key(
    curve=ec.SECP192R1(),
    backend=default_backend()
)

if __name__ == '__main__':
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