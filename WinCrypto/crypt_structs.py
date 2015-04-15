from WinCrypto.crypt_flags import *
from WinCrypto.crypt_utils import *
from WinCrypto.crypt_blobs import *

from ctypes import *
from struct import unpack, pack
import binascii

class GUID(Structure):
    _fields_ = [
                    ('Data1', DWORD ),
                    ('Data2', SHORT ),
                    ('Data3', SHORT ),
                    ('Data4', BYTE * 4)
                ]
    

class SPC_SERIALIZED_OBJECT(Structure):
    _fields_ = [
                    ('ClassId', BYTE * 16 ),
                    ('SerializedData', CRYPT_DATA_BLOB)
                ]
class SPC_LINK_U(Union):
    _fields_ = [("pwszUrl", LPWSTR),
                ("Moniker", SPC_SERIALIZED_OBJECT),
                ("pwszFile", LPWSTR)]
class SPC_LINK(Structure):
    _anonymous_ = ('u',)
    _fields_ = [
                    ('dwLinkChoice', DWORD),
                    ('u', SPC_LINK_U )
                    ]
    def __str__(self):
        if self.dwLinkChoice == SpcLinkChoice['SPC_URL_LINK_CHOICE']:
            return "pwszUrl:%s" % self.pwszUrl
        elif self.dwLinkChoice == SpcLinkChoice['SPC_MONIKER_LINK_CHOICE']:
            return "Moniker:%s" % self.Moniker
        elif self.dwLinkChoice == SpcLinkChoice['SPC_FILE_LINK_CHOICE']:
            return "pwszFile:%s" % self.pwszFile
        return ""
class SPC_SP_OPUS_INFO(Structure):
    _fields_ = [
                    ('pwszProgramName', LPWSTR),
                    ('pMoreInfo', POINTER(SPC_LINK)),
                    ('pPublisherInfo', POINTER(SPC_LINK))                    
                    ]
class SPC_STATEMENT_TYPE(Structure):
    _fields_ = [
                    ('cKeyPurposeId', DWORD),
                    ('rgpszKeyPurposeId', PVOID),
                    ]
    
    def KeyPurposeIds( self ):
        if not self.cKeyPurposeId:
            return []
        return cast(self.rgpszKeyPurposeId, POINTER(LPCSTR * self.cKeyPurposeId)).contents
        
class CRYPT_ALGORITHM_IDENTIFIER(Structure):
    _fields_ = [
                    ('pszObjId', LPCSTR),
                    ('Parameters', CRYPT_OBJID_BLOB)
                    ]
    ObjId = property(lambda self: self.pszObjId, None, None, "ObjId property.")
                    
    def __str__( self ):
        return "%s:%s" % ( self.pszObjId, self.Parameters )
class CRYPT_ATTRIBUTE(Structure):
    _fields_ = [
                    ('pszObjId', LPCSTR),
                    ('cValue', DWORD),
                    ('rgAttr', PVOID)
                    ]
    ObjId = property(lambda self: self.pszObjId, None, None, "ObjId property.")
    
    def attributes( self ):
        if not self.cValue:
            return []
        return cast(self.rgAttr, POINTER(CRYPT_OBJID_BLOB * self.cValue)).contents
        
    def __str__( self ):
        if not self.pszObjId:
            return ""
        return "%s:%s" % ( Reverse(OID,self.pszObjId,True), "\n".join( str(x.cbData) for x in self.attributes()) )
class CRYPT_ATTRIBUTES(Structure):
    _fields_ = [
                    ('cAttr', DWORD),
                    ('rgAttr', PVOID)
                    ]
    def attributes( self ):
        if not self.cAttr:
            return []
        return cast(self.rgAttr, POINTER(CRYPT_ATTRIBUTE * self.cAttr)).contents
class CMSG_SIGNER_INFO(Structure):
    _fields_ = [
                    ('dwVersion', DWORD),
                    ('Issuer', CERT_NAME_BLOB),
                    ('SerialNumber', CRYPT_INTEGER_BLOB),
                    ('HashAlgorithm', CRYPT_ALGORITHM_IDENTIFIER),
                    ('HashEncryptionAlgorithm', CRYPT_ALGORITHM_IDENTIFIER),
                    ('EncryptedHash', CRYPT_DATA_BLOB),
                    ('AuthAttrs', CRYPT_ATTRIBUTES),
                    ('UnauthAttrs', CRYPT_ATTRIBUTES),
                    ]
    def __str__( self ):
        _s = ["Signer Info:"]
        _s.append( "  Version: %d" % self.dwVersion )
        _s.append( "  Issuer: %s" % self.Issuer )
        _s.append( "  SerialNumber: %s" % binascii.hexlify(str(self.SerialNumber)) )
        _s.append( "  HashAlgorithm: %s" % Reverse(OID, self.HashAlgorithm.ObjId, True) )
        _s.append( "  HashEncryptionAlgorithm: %s" % Reverse(OID, self.HashEncryptionAlgorithm.ObjId, True) )
        _s.append( "  EncryptedHash: %s" % self.EncryptedHash )
        _s.append( "  Authenticated Attributes:\n\t%s" % "\n\t".join( [str(x) for x in self.AuthAttrs.attributes()] ))
        _s.append( "  Unauthenticated Attributes:\n\t%s" % "\n\t".join( [str(x) for x in self.UnauthAttrs.attributes()] ))
        return "\n".join(_s)
        
class FILETIME(Structure):
    _fields_ = [
                    ('dwLowDateTime', DWORD),
                    ('dwHighDateTime', DWORD)
                ]
                
    def time( self ):
        lft = FILETIME()
        windll.kernel32.FileTimeToLocalFileTime.argtypes = [POINTER(FILETIME),POINTER(FILETIME)]
        windll.kernel32.FileTimeToLocalFileTime.restype = c_bool
        if windll.kernel32.FileTimeToLocalFileTime(byref(self), byref(lft)):            
            #Int32x32To64
            ft_dec, = unpack('@Q', pack('@LL', lft.dwLowDateTime, lft.dwHighDateTime))

            from datetime import datetime
            EPOCH_AS_FILETIME = 116444736000000000;  HUNDREDS_OF_NANOSECONDS = 10000000
            print ((ft_dec - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
            dt = datetime.fromtimestamp((ft_dec - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
            return dt.date()
        return None
        
    def __str__( self ):
        t = self.time()
        return str(t) if t else "<unknown>"
class CERT_PUBLIC_KEY_INFO(Structure):
    _fields_ = [
                    ('Algorithm', CRYPT_ALGORITHM_IDENTIFIER ),
                    ('PublicKey', CRYPT_BIT_BLOB)
                ]
class CERT_EXTENSION(Structure):
    _fields_ = [
                    ('pszObjId', LPCSTR),
                    ('fCritical', BOOL),
                    ('Value', CRYPT_OBJID_BLOB),
                ]
    def __str__( self ):
        oid = Reverse(OID, self.pszObjId)
        oid = oid[0] if len(oid) == 1 else oid
        return "%s: %s %s" % ( oid, self.fCritical != 0, self.Value )
PCERT_EXTENSION = POINTER(CERT_EXTENSION)

class CERT_EXTENSIONS(Structure):
    _fields_ = [
                    ('cExtension', DWORD),
                    ('rgExtension', PVOID),
                ]
    def extensions( self ):
        if not self.cExtension:
            return []
        return cast(self.rgExtension, POINTER(CERT_EXTENSION * self.cExtension)).contents

class CERT_INFO(Structure):
    _fields_ = [
                    ('dwVersion', DWORD),
                    ('SerialNumber', CRYPT_INTEGER_BLOB),
                    ('SignatureAlgorithm', CRYPT_ALGORITHM_IDENTIFIER),
                    ('Issuer', CERT_NAME_BLOB),
                    ('NotBefore', FILETIME),
                    ('NotAfter', FILETIME),
                    ('Subject', CERT_NAME_BLOB),
                    ('SubjectPublicKeyInfo', CERT_PUBLIC_KEY_INFO),
                    ('IssuerUniqueId', CRYPT_BIT_BLOB),
                    ('SubjectUniqueId', CRYPT_BIT_BLOB),
                    ('cExtension', DWORD),
                    ('rgExtension', PVOID),
                ]
    def extensions( self ):
        if not self.cExtension:
            return []
        return cast(self.rgExtension, POINTER(CERT_EXTENSION * self.cExtension)).contents
    
    def __str__( self, show_extensions = True ):
        _s = ["Certificate Info:"]
        _s.append( "  Version: %d" % self.dwVersion )
        _s.append( "  SerialNumber: %s" % binascii.hexlify(str(self.SerialNumber)) )
        _s.append( "  Digest type: %s" % Reverse(OID, self.SignatureAlgorithm.ObjId, True) )
        _s.append( "  Issuer: %s" % self.Issuer )
        _s.append( "  Valid: %s - %s" % (self.NotBefore, self.NotAfter) )
        _s.append( "  Subject: %s" % self.Subject )
        if show_extensions:
            _s.append( "  Extensions:\n\t%s" % "\n\t".join( [str(x) for x in self.extensions()] ))
        return "\n".join(_s)
        
class CERT_CONTEXT(Structure):
    _fields_ = [
                    ('dwCertEncodingType', DWORD),
                    ('pbCertEncoded', POINTER(BYTE) ),
                    ('cbCertEncoded', DWORD),
                    ('pCertInfo', POINTER(CERT_INFO)),
                    ('hCertStore', HCERTSTORE)
                ]
    CertInfo = property(lambda self: self.pCertInfo.contents if self.pCertInfo else None, None, None, "CertInfo property.")

class CTL_USAGE(Structure):
    _fields_ = [
                    ('cUsageIdentifier', DWORD),
                    ('rgpszUsageIdentifier', PVOID)
                ]
    def UsageIdentifiers( self ):
        if not self.cUsageIdentifier:
            return []
        return cast(self.rgpszUsageIdentifier, POINTER(LPCSTR * self.cUsageIdentifier)).contents
        
class CTL_ENTRY(Structure):
    _fields_ = [
                    ('SubjectIdentifier', CRYPT_DATA_BLOB),
                    ('cAttribute', DWORD),
                    ('rgAttribute', PVOID)
                ]
    def attributes( self ):
        if not self.cAttribute:
            return []
        return cast(self.rgAttribute, POINTER(CRYPT_ATTRIBUTE * self.cAttribute)).contents
PCTL_ENTRY = POINTER(CTL_ENTRY)
                
class CTL_INFO(Structure):
    _fields_ = [
                    ('dwVersion', DWORD),
                    ('SubjectUsage', CTL_USAGE),
                    ('ListIdentifier', CRYPT_DATA_BLOB),     # OPTIONAL
                    ('SequenceNumber', CRYPT_INTEGER_BLOB),     # OPTIONAL
                    ('ThisUpdate', FILETIME),
                    ('NextUpdate', FILETIME),         # OPTIONAL
                    ('SubjectAlgorithm', CRYPT_ALGORITHM_IDENTIFIER),
                    ('cCTLEntry', DWORD),
                    ('rgCTLEntry', PCTL_ENTRY),         # OPTIONAL
                    ('cExtension', DWORD),
                    ('rgExtension', PCERT_EXTENSION),        # OPTIONAL
                ]
PCTL_INFO = POINTER(CTL_INFO)
    
class CTL_CONTEXT(Structure):
    _fields_ = [
                    ('dwMsgAndCertEncodingType', DWORD),
                    ('pbCtlEncoded', PBYTE),
                    ('cbCtlEncoded', DWORD),
                    ('pCtlInfo', PCTL_INFO),
                    ('hCertStore', HCERTSTORE),
                    ('hCryptMsg', HCRYPTMSG),
                    ('pbCtlContent', PBYTE),
                    ('cbCtlContent', DWORD)
                ]
PCTL_CONTEXT = POINTER(CTL_CONTEXT)
PCCTL_CONTEXT = POINTER(CTL_CONTEXT)

class WINTRUST_FILE_INFO(Structure):
    _fields_ = [
                    ('cbStruct', DWORD),
                    ('pcwszFilePath', LPWSTR),
                    ('hFile', HANDLE),
                    ('pgKnownSubject', POINTER(GUID))
                    ]
class WINTRUST_CATALOG_INFO(Structure):
    _fields_ = [
                    ('cbStruct', DWORD),                # = sizeof(WINTRUST_CATALOG_INFO)
                    ('dwCatalogVersion', DWORD),        # optional: Catalog version number
                    ('pcwszCatalogFilePath', LPWSTR),   # required: path/name to Catalog file
                    ('pcwszMemberTag', LPWSTR),         # optional: tag to member in Catalog
                    ('pcwszMemberFilePath', LPWSTR),    # required: path/name to member file
                    ('hMemberFile', HANDLE),            # optional: open handle to pcwszMemberFilePath
                    ('pbCalculatedFileHash', PBYTE),    # optional: pass in the calculated hash
                    ('cbCalculatedFileHash', DWORD),    # optional: pass in the count bytes of the calc hash
                    ('pcCatalogContext', PCCTL_CONTEXT),# optional: pass in to use instead of CatalogFilePath.
                    ('hCatAdmin', HCATADMIN)            # optional for SHA-1 hashes, required for all other hash types.
                ]

class WinTrustData(Structure):
    _fields_ = [
                    ('PolicyCallbackData', c_void_p),
                    ('SIPClientData', c_void_p),
                    ('UIChoice', c_void_p),         # WinTrustDataUIChoice
                    ('RevocationChecks', c_void_p), # WinTrustDataRevocationChecks
                    ('UnionChoice', c_void_p), # WinTrustDataChoice
                    ('FileInfoPtr', c_void_p),
                    ('StateAction', c_void_p), # WinTrustDataStateAction
                    ('StateData', c_void_p),
                    
                    ]
    def __init__( self, _filePath ):
        self.pszFilePath = c_char_p( _filePath )
        self.hFile = None
        self.pgKnownSubject = None
        
class WINTRUST_BLOB_INFO(Structure):
    __fields__ =    [
                        ('cbStruct', DWORD),
                        ('gSubject', GUID),
                        ('pcwszDisplayName', LPWSTR),
                        ('cbMemObject', DWORD),
                        ('pbMemObject', POINTER(BYTE)),
                        ('cbMemSignedMsg', DWORD),
                        ('pbMemSignedMsg', POINTER(BYTE)),
                        
                    ]