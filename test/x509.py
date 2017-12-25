x=u'中国,日本'
print x.split(',')


'''
subject_check=['commonName','countryName','stateOrProvinceName','localityName','organizationName','organizationalUnitName']
for i in cert.subject:
    if isinstance(i,x509.NameAttribute):
        print i.oid._name
'''
'commonName','countryName','stateOrProvinceName','localityName','organizationName','organizationalUnitName'
'''
def extensions_type(exten):
    if isinstance(exten,x509.extensions.SubjectAlternativeName):
        pass
    elif isinstance(exten,x509.extensions.BasicConstraints):
        pass
    elif isinstance(exten,x509.extensions.KeyUsage):
        pass
    elif isinstance(exten,x509.extensions.CRLDistributionPoints):
        pass
    elif isinstance(exten,x509.extensions.CertificatePolicies):
        pass
    elif isinstance(exten,x509.extensions.ExtendedKeyUsage):
        pass
    elif isinstance(exten,x509.extensions.AuthorityKeyIdentifier):
        pass
    elif isinstance(exten,x509.extensions.AuthorityInformationAccess):
        pass
    elif isinstance(exten,x509.extensions.UnrecognizedExtension):
        pass
    elif isinstance(exten,x509.extensions.AuthorityKeyIdentifier):
        pass
    elif isinstance(exten,x509.extensions.AuthorityKeyIdentifier):
        pass
print cert.serial_number
print binascii.hexlify(cert.fingerprint(hashes.SHA256()))
print cert.not_valid_before
print cert.not_valid_before
print cert.version
for i in cert.extensions:
    print type(i)

x509.AccessDescription
x509.AuthorityInformationAccess
x509.AuthorityInformationAccessOID
x509.AuthorityKeyIdentifier
x509.BasicConstraints
x509.CRLDistributionPoints
x509.CRLEntryExtensionOID
x509.CRLNumber
x509.CRLReason
x509.DirectoryName
x509.DistributionPoint
x509.DuplicateExtension
x509.DNSName
x509.ExtendedKeyUsage

x509.ExtendedKeyUsageOID
x509.ExtensionNotFound
x509.GeneralName
x509.GeneralNames
x509.InhibitAnyPolicy
x509.InvalidityDate
x509.InvalidVersion
x509.IPAddress
x509.IssuerAlternativeName
x509.KeyUsage
x509.Name
x509.NameAttribute
x509.NameConstraints
x509.NoticeReference

x509.ObjectIdentifier
x509.OCSPNoCheck
x509.UserNotice
x509.UnsupportedGeneralNameType
x509.UnsupportedExtension
x509.UnrecognizedExtension
x509.UniformResourceIdentifier
x509.SubjectKeyIdentifier
x509.SubjectAlternativeName
x509.SignatureAlgorithmOID
x509.RFC822Name
x509.RelativeDistinguishedName
x509.ReasonFlags
x509.PolicyInformation
x509.PolicyConstraints
x509.OtherName
'''