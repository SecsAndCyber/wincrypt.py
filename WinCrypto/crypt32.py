from WinCrypto.crypt_structs import *
from ctypes import *
from struct import unpack, pack
import binascii

"""
WINCRYPT32API
BOOL
WINAPI
CryptQueryObject(
    _In_ DWORD                    dwObjectType,
    _In_ const void               *pvObject,
    _In_ DWORD                    dwExpectedContentTypeFlags,
    _In_ DWORD                    dwExpectedFormatTypeFlags,
    _In_ DWORD                    dwFlags,
    _Out_opt_ DWORD               *pdwMsgAndCertEncodingType,
    _Out_opt_ DWORD               *pdwContentType,
    _Out_opt_ DWORD               *pdwFormatType,
    _Out_opt_ HCERTSTORE          *phCertStore,
    _Out_opt_ HCRYPTMSG           *phMsg,
    _Outptr_opt_result_maybenull_ const void **ppvContext
    );
"""
CryptQueryObject = crypt32_dll.CryptQueryObject
CryptQueryObject.res_type = c_bool
CryptQueryObject.argtypes = [DWORD, PVOID, DWORD, DWORD, DWORD, POINTER(DWORD), POINTER(DWORD), POINTER(DWORD), POINTER(HCERTSTORE), POINTER(HCRYPTMSG), POINTER(POINTER(PVOID)) ]
    
"""
WINCRYPT32API
BOOL
WINAPI
CryptMsgGetParam(
    _In_ HCRYPTMSG hCryptMsg,
    _In_ DWORD dwParamType,
    _In_ DWORD dwIndex,
    _Out_writes_bytes_to_opt_(*pcbData, *pcbData) void *pvData,
    _Inout_ DWORD *pcbData
    );
"""
CryptMsgGetParam = crypt32_dll.CryptMsgGetParam
CryptMsgGetParam.res_type = c_bool
CryptMsgGetParam.argtypes = [ HCRYPTMSG, DWORD, DWORD, POINTER(BYTE), POINTER(DWORD) ]
    
"""
WINCRYPT32API
BOOL
WINAPI
CryptDecodeObject(
    _In_ DWORD dwCertEncodingType,
    _In_ LPCSTR lpszStructType,
    _In_reads_bytes_(cbEncoded) const BYTE *pbEncoded,
    _In_ DWORD cbEncoded,
    _In_ DWORD dwFlags,
    _Out_writes_bytes_to_opt_(*pcbStructInfo, *pcbStructInfo) void *pvStructInfo,
    _Inout_ DWORD *pcbStructInfo
    );
"""
CryptDecodeObject = crypt32_dll.CryptDecodeObject
CryptDecodeObject.res_type = c_bool
CryptDecodeObject.argtypes = [ DWORD, LPCSTR, PVOID, DWORD, DWORD,  POINTER(BYTE), POINTER(DWORD) ]

"""
WINCRYPT32API
PCCERT_CONTEXT
WINAPI
CertFindCertificateInStore(
    _In_ HCERTSTORE hCertStore,
    _In_ DWORD dwCertEncodingType,
    _In_ DWORD dwFindFlags,
    _In_ DWORD dwFindType,
    _In_opt_ const void *pvFindPara,
    _In_opt_ PCCERT_CONTEXT pPrevCertContext
    );
"""
CertFindCertificateInStore = crypt32_dll.CertFindCertificateInStore
CertFindCertificateInStore.res_type = POINTER(CERT_CONTEXT)
CertFindCertificateInStore.argtypes = [ HCERTSTORE, DWORD, DWORD, DWORD, PVOID,  POINTER(CERT_CONTEXT) ]

"""
WINCRYPT32API
DWORD
WINAPI
CertNameToStrW(
    _In_ DWORD dwCertEncodingType,
    _In_ PCERT_NAME_BLOB pName,
    _In_ DWORD dwStrType,
    _Out_writes_to_opt_(csz, return) LPWSTR psz,
    _In_ DWORD csz
    );
"""
CertNameToStr = crypt32_dll.CertNameToStrW
CertNameToStr.res_type = DWORD
CertNameToStr.argtypes = [ DWORD, PCERT_NAME_BLOB, DWORD, LPWSTR, DWORD ]

"""
WINCRYPT32API
DWORD
WINAPI
CertGetNameStringW(
    _In_ PCCERT_CONTEXT pCertContext,
    _In_ DWORD dwType,
    _In_ DWORD dwFlags,
    _In_opt_ void *pvTypePara,
    _Out_writes_to_opt_(cchNameString, return) LPWSTR pszNameString,
    _In_ DWORD cchNameString
    );
"""
CertGetNameString = crypt32_dll.CertGetNameStringW
CertGetNameString.res_type = DWORD
CertGetNameString.argtypes = [ POINTER(CERT_CONTEXT), DWORD, DWORD, PVOID, LPWSTR, DWORD ]

