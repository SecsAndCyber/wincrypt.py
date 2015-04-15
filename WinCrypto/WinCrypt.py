from ctypes import *
from ctypes.wintypes import *
from crypt_flags import *
from crypt_blobs import str_to_PBYTE, BLOBHEADER, AES128HEADER, AES192HEADER, AES256HEADER
from platform import win32_ver
import binascii, hashlib
# Advapi32.dll
"""
BOOL WINAPI CryptAcquireContext(
  _Out_  HCRYPTPROV *phProv,
  _In_   LPCTSTR pszContainer,
  _In_   LPCTSTR pszProvider,
  _In_   DWORD dwProvType,
  _In_   DWORD dwFlags
);
BOOL WINAPI CryptImportKey(
  _In_   HCRYPTPROV hProv,
  _In_   BYTE *pbData,
  _In_   DWORD dwDataLen,
  _In_   HCRYPTKEY hPubKey,
  _In_   DWORD dwFlags,
  _Out_  HCRYPTKEY *phKey
);
BOOL WINAPI CryptGenKey(
  _In_   HCRYPTPROV hProv,
  _In_   ALG_ID Algid,
  _In_   DWORD dwFlags,
  _Out_  HCRYPTKEY *phKey
);
BOOL WINAPI CryptEncrypt(
  _In_     HCRYPTKEY hKey,
  _In_     HCRYPTHASH hHash,
  _In_     BOOL Final,
  _In_     DWORD dwFlags,
  _Inout_  BYTE *pbData,
  _Inout_  DWORD *pdwDataLen,
  _In_     DWORD dwBufLen
);
BOOL WINAPI CryptSetKeyParam(
  _In_  HCRYPTKEY hKey,
  _In_  DWORD dwParam,
  _In_  const BYTE *pbData,
  _In_  DWORD dwFlags
);
"""

AdvApi32 = windll.LoadLibrary("advapi32")

AcquireContext = AdvApi32.CryptAcquireContextW
AcquireContext.argtypes = [ POINTER(HCRYPTPROV), PWCHAR, PWCHAR, DWORD, DWORD ]
AcquireContext.restype = c_bool

GenKey = AdvApi32.CryptGenKey
GenKey.argtypes = [ HCRYPTPROV, ALG_ID, DWORD, POINTER(HCRYPTKEY) ]
GenKey.restype = c_bool

ImportKey = AdvApi32.CryptImportKey
ImportKey.argtypes = [ HCRYPTPROV, PBYTE, DWORD, HCRYPTKEY, DWORD, POINTER(HCRYPTKEY) ]
ImportKey.restype = c_bool

Encrypt = AdvApi32.CryptEncrypt
Encrypt.argtypes = [ HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, PBYTE, POINTER(DWORD), DWORD ]
Encrypt.restype = c_bool

Decrypt = AdvApi32.CryptDecrypt
Decrypt.argtypes = [ HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, PBYTE, POINTER(DWORD) ]
Decrypt.restype = c_bool

SetKeyParam = AdvApi32.CryptSetKeyParam
SetKeyParam.argtypes = [ HCRYPTKEY, DWORD, PBYTE, DWORD ]
SetKeyParam.restype = c_bool

key_size = (16, 24, 32)
block_size = 16
MODE_CBC    =   0x0002
MODE_CFB    =   0x0003
MODE_CTR    =   0x0006
MODE_ECB    =   0x0001
MODE_OFB    =   0x0005
MODE_OPENPGP=   0x0007
MODE_PGP    =   0x0004

MS_ENH_RSA_AES_PROV = "Microsoft Enhanced RSA and AES Cryptographic Provider" if not win32_ver()[0] == 'XP' else "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)"
    
PLAINTEXTKEYBLOB = 0x8
CUR_BLOB_VERSION = 2

CALG_AES_128=            (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_128)
CALG_AES_192=            (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_192)
CALG_AES_256=            (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_256)