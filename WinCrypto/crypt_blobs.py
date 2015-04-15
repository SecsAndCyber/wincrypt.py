from WinCrypto.crypt_flags import *
from WinCrypto.crypt_utils import *

from ctypes import *
from struct import unpack, pack
import binascii

def str_to_PBYTE( _str ):
    _bytes = _str.encode('ascii')
    return (BYTE * len(_bytes))(* unpack("=" + "B"*len(_bytes), _bytes))
    
    
class BLOBHEADER(Structure):
    _pack_ = 1
    _fields_ = [
                    ('bType', BYTE),
                    ('bVersion', BYTE),
                    ('reserved', WORD),
                    ('aiKeyAlg', ALG_ID)
                ]
class AES128HEADER(Structure):
    _pack_ = 1
    _fields_ = [
                    ('header', BLOBHEADER),
                    ('keySize', DWORD),
                    ('keyBytes', BYTE*16)
                ]
class AES192HEADER(Structure):
    _pack_ = 1
    _fields_ = [
                    ('header', BLOBHEADER),
                    ('keySize', DWORD),
                    ('keyBytes', BYTE*24)
                ]
class AES256HEADER(Structure):
    _pack_ = 1
    _fields_ = [
                    ('header', BLOBHEADER),
                    ('keySize', DWORD),
                    ('keyBytes', BYTE*32)
                ]
    
class _CRYPTOAPI_BLOB(Structure):
    _pack_ = 1
    _fields_ = [
                    ('cbData', DWORD),
                    ('pbData', POINTER(BYTE))
                ]
    def __str__( self ):
        if not self.cbData:
            return ""
        # print self.cbData, len(cast(self.pbData, POINTER(BYTE * self.cbData)).contents)
        return binascii.hexlify(cast(self.pbData, POINTER(BYTE * self.cbData)).contents)
        
class CRYPT_INTEGER_BLOB(_CRYPTOAPI_BLOB):
    def __str__(self):
        if not self.cbData:
            return ""
        # print self.cbData, len(cast(self.pbData, POINTER(BYTE * self.cbData)).contents)
        return buffer(cast(self.pbData, POINTER(BYTE * self.cbData)).contents)[::-1]
        
PCRYPT_INTEGER_BLOB = POINTER(CRYPT_INTEGER_BLOB)

class CERT_NAME_BLOB(_CRYPTOAPI_BLOB):
    CertNameToStr = crypt32_dll.CertNameToStrA
    CertNameToStr.res_type = DWORD
    
    def __init__(self):
        super(C, self).__init__()
        
    def __str__(self, name_type = 'CERT_X500_NAME_STR'):
        self.CertNameToStr.argtypes = [ DWORD, POINTER(_CRYPTOAPI_BLOB), DWORD, LPCSTR, DWORD ]
        if not self.cbData:
            return ""
            
        str_size = self.CertNameToStr( ENCODING,
                            self,
                            CertNameStr[name_type],
                            NULL,
                            0 )
        if str_size:
            StringBuffer = cast(malloc(str_size * sizeof(c_char)), c_char_p)
            str_size = self.CertNameToStr( ENCODING,
                                self,
                                CertNameStr[name_type],
                                StringBuffer,
                                str_size )
            r_string = StringBuffer.value
            free( StringBuffer)
            return r_string            
            
        return ""
    
PCERT_NAME_BLOB = POINTER(CERT_NAME_BLOB)

CERT_RDN_VALUE_BLOB, PCERT_RDN_VALUE_BLOB = _CRYPTOAPI_BLOB, POINTER(_CRYPTOAPI_BLOB)
CERT_BLOB, PCERT_BLOB = _CRYPTOAPI_BLOB, POINTER(_CRYPTOAPI_BLOB)
CRL_BLOB, PCRL_BLOB = _CRYPTOAPI_BLOB, POINTER(_CRYPTOAPI_BLOB)
DATA_BLOB, PDATA_BLOB = _CRYPTOAPI_BLOB, POINTER(_CRYPTOAPI_BLOB)
CRYPT_DATA_BLOB, PCRYPT_DATA_BLOB = _CRYPTOAPI_BLOB, POINTER(_CRYPTOAPI_BLOB)
CRYPT_HASH_BLOB, PCRYPT_HASH_BLOB = _CRYPTOAPI_BLOB, POINTER(_CRYPTOAPI_BLOB)
CRYPT_DIGEST_BLOB, PCRYPT_DIGEST_BLOB = _CRYPTOAPI_BLOB, POINTER(_CRYPTOAPI_BLOB)
CRYPT_DER_BLOB, PCRYPT_DER_BLOB = _CRYPTOAPI_BLOB, POINTER(_CRYPTOAPI_BLOB)
CRYPT_ATTR_BLOB, PCRYPT_ATTR_BLOB = _CRYPTOAPI_BLOB, POINTER(_CRYPTOAPI_BLOB)
CRYPT_UINT_BLOB, PCRYPT_UINT_BLOB = _CRYPTOAPI_BLOB, POINTER(_CRYPTOAPI_BLOB)

class CRYPT_OBJID_BLOB(_CRYPTOAPI_BLOB):
    def __str__(self):
        if not self.cbData:
            return ""
        return BinPrint(cast(self.pbData, POINTER(BYTE * self.cbData)).contents)
    
PCRYPT_OBJID_BLOB = POINTER(CRYPT_OBJID_BLOB)

class CRYPT_BIT_BLOB(Structure):
    _fields_ = [
                    ('cbData', DWORD),
                    ('pbData', POINTER(BYTE)),
                    ('cUnusedBits', DWORD),
                    ]
    def __str__( self ):
        if not self.cbData:
            return ""
        # print self.cbData, len(cast(self.pbData, POINTER(BYTE * self.cbData)).contents)
        return buffer(cast(self.pbData, POINTER(BYTE * self.cbData)).contents)[:]
PCRYPT_BIT_BLOB = POINTER(CRYPT_BIT_BLOB)
        