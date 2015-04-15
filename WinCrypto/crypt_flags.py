from ctypes import *
from ctypes.wintypes import *
from struct import unpack, pack
import binascii

BYTE = c_ubyte
PBYTE = POINTER(BYTE)
BOOL = c_uint
DWORD = c_uint
SHORT = c_ushort
LPCSTR = c_char_p
LPWSTR = c_wchar_p
WCHAR = c_wchar
PVOID = c_void_p
HANDLE = PVOID
HCERTSTORE = PVOID
HCRYPTMSG =  PVOID
HCATADMIN = PVOID
HCRYPTPROV = c_void_p
HCRYPTKEY = c_void_p
HCRYPTHASH = c_void_p
ALG_ID = c_ulong
PWCHAR = c_wchar_p
NULL = None
 
# Algorithm classes
# certenrolld_begin -- ALG_CLASS_*
ALG_CLASS_ANY = (0)
ALG_CLASS_SIGNATURE = (1 << 13)
ALG_CLASS_MSG_ENCRYPT = (2 << 13)
ALG_CLASS_DATA_ENCRYPT = (3 << 13)
ALG_CLASS_HASH = (4 << 13)
ALG_CLASS_KEY_EXCHANGE = (5 << 13)
ALG_CLASS_ALL = (7 << 13)
# certenrolld_end

# Algorithm types
ALG_TYPE_ANY = (0)
ALG_TYPE_DSS = (1 << 9)
ALG_TYPE_RSA = (2 << 9)
ALG_TYPE_BLOCK = (3 << 9)
ALG_TYPE_STREAM = (4 << 9)
ALG_TYPE_DH = (5 << 9)
ALG_TYPE_SECURECHANNEL = (6 << 9)

# Block cipher sub ids
ALG_SID_DES	= 1
ALG_SID_3DES	= 3
ALG_SID_DESX	= 4
ALG_SID_IDEA	= 5
ALG_SID_CAST	= 6
ALG_SID_SAFERSK64	= 7
ALG_SID_SAFERSK128	= 8
ALG_SID_3DES_112	= 9
ALG_SID_CYLINK_MEK	= 12
ALG_SID_RC5	= 13
ALG_SID_AES_128	= 14
ALG_SID_AES_192	= 15
ALG_SID_AES_256	= 16
ALG_SID_AES	= 17


KP_IV = 1       # Initialization vector
KP_SALT = 2       # Salt value
KP_PADDING = 3       # Padding values
KP_MODE = 4       # Mode of the cipher
KP_MODE_BITS = 5       # Number of bits to feedback
KP_PERMISSIONS = 6       # Key permissions DWORD
KP_ALGID = 7       # Key algorithm
KP_BLOCKLEN = 8       # Block size of the cipher
KP_KEYLEN = 9       # Length of key in bits
KP_SALT_EX = 10      # Length of salt in bytes
KP_P = 11      # DSS/Diffie-Hellman P value
KP_G = 12      # DSS/Diffie-Hellman G value
KP_Q = 13      # DSS Q value
KP_X = 14      # Diffie-Hellman X value
KP_Y = 15      # Y value
KP_RA = 16      # Fortezza RA value
KP_RB = 17      # Fortezza RB value
KP_INFO = 18      # for putting information into an RSA envelope
KP_EFFECTIVE_KEYLEN = 19      # setting and getting RC2 effective key length
KP_SCHANNEL_ALG = 20      # for setting the Secure Channel algorithms
KP_CLIENT_RANDOM = 21      # for setting the Secure Channel client random data
KP_SERVER_RANDOM = 22      # for setting the Secure Channel server random data
KP_RP = 23
KP_PRECOMP_MD5 = 24
KP_PRECOMP_SHA = 25
KP_CERTIFICATE = 26      # for setting Secure Channel certificate data (PCT1)
KP_CLEAR_KEY = 27      # for setting Secure Channel clear key data (PCT1)
KP_PUB_EX_LEN = 28
KP_PUB_EX_VAL = 29
KP_KEYVAL = 30
KP_ADMIN_PIN = 31
KP_KEYEXCHANGE_PIN = 32
KP_SIGNATURE_PIN = 33
KP_PREHASH = 34

# KP_MODE
CRYPT_MODE_CBC = 1       # Cipher block chaining
CRYPT_MODE_ECB = 2       # Electronic code book
CRYPT_MODE_OFB = 3       # Output feedback mode
CRYPT_MODE_CFB = 4       # Cipher feedback mode
CRYPT_MODE_CTS = 5       # Ciphertext stealing mode

# KP_PERMISSIONS
CRYPT_ENCRYPT = 0x0001  # Allow encryption
CRYPT_DECRYPT = 0x0002  # Allow decryption
CRYPT_EXPORT = 0x0004  # Allow key to be exported
CRYPT_READ = 0x0008  # Allow parameters to be read
CRYPT_WRITE = 0x0010  # Allow parameters to be set
CRYPT_MAC = 0x0020  # Allow MACs to be used with key
CRYPT_EXPORT_KEY = 0x0040  # Allow key to be used for exporting keys
CRYPT_IMPORT_KEY = 0x0080  # Allow key to be used for importing keys
 
CertInformationFlags = {
        #+-------------------------------------------------------------------------
        #  Certificate Information Flags
        #--------------------------------------------------------------------------
        'CERT_INFO_VERSION_FLAG' : 1,
        'CERT_INFO_SERIAL_NUMBER_FLAG' : 2,
        'CERT_INFO_SIGNATURE_ALGORITHM_FLAG' : 3,
        'CERT_INFO_ISSUER_FLAG' : 4,
        'CERT_INFO_NOT_BEFORE_FLAG' : 5,
        'CERT_INFO_NOT_AFTER_FLAG' : 6,
        'CERT_INFO_SUBJECT_FLAG' : 7,
        'CERT_INFO_SUBJECT_PUBLIC_KEY_INFO_FLAG' : 8,
        'CERT_INFO_ISSUER_UNIQUE_ID_FLAG' : 9,
        'CERT_INFO_SUBJECT_UNIQUE_ID_FLAG' : 10,
        'CERT_INFO_EXTENSION_FLAG' : 11,
    }
CertCompare = {
        #+-------------------------------------------------------------------------
        # Certificate comparison functions
        #--------------------------------------------------------------------------
        'CERT_COMPARE_MASK' : 0xFFFF,
        'CERT_COMPARE_SHIFT' : 16,
        'CERT_COMPARE_ANY' : 0,
        'CERT_COMPARE_SHA1_HASH' : 1,
        'CERT_COMPARE_NAME' : 2,
        'CERT_COMPARE_ATTR' : 3,
        'CERT_COMPARE_MD5_HASH' : 4,
        'CERT_COMPARE_PROPERTY' : 5,
        'CERT_COMPARE_PUBLIC_KEY' : 6,
        'CERT_COMPARE_HASH' : 1, #CERT_COMPARE_SHA1_HASH
        'CERT_COMPARE_NAME_STR_A' : 7,
        'CERT_COMPARE_NAME_STR_W' : 8,
        'CERT_COMPARE_KEY_SPEC' : 9,
        'CERT_COMPARE_ENHKEY_USAGE' : 10,
        'CERT_COMPARE_CTL_USAGE' : 10, #CERT_COMPARE_ENHKEY_USAGE
        'CERT_COMPARE_SUBJECT_CERT' : 11,
        'CERT_COMPARE_ISSUER_OF' : 12,
        'CERT_COMPARE_EXISTING' : 13,
        'CERT_COMPARE_SIGNATURE_HASH' : 14,
        'CERT_COMPARE_KEY_IDENTIFIER' : 15,
        'CERT_COMPARE_CERT_ID' : 16,
        'CERT_COMPARE_CROSS_CERT_DIST_POINTS' : 17,

        'CERT_COMPARE_PUBKEY_MD5_HASH' : 18,

        'CERT_COMPARE_SUBJECT_INFO_ACCESS' : 19,
        'CERT_COMPARE_HASH_STR' : 20,
        'CERT_COMPARE_HAS_PRIVATE_KEY' : 21
        }
CertCompare.update( {
        #+-------------------------------------------------------------------------
        #  dwFindType
        #
        #  The dwFindType definition consists of two components:
        #   - comparison function
        #   - certificate information flag
        #--------------------------------------------------------------------------
        'CERT_FIND_ANY'		        : (CertCompare['CERT_COMPARE_ANY'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_SHA1_HASH'		: (CertCompare['CERT_COMPARE_SHA1_HASH'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_MD5_HASH'		: (CertCompare['CERT_COMPARE_MD5_HASH'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_SIGNATURE_HASH'	: (CertCompare['CERT_COMPARE_SIGNATURE_HASH'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_KEY_IDENTIFIER'	: (CertCompare['CERT_COMPARE_KEY_IDENTIFIER'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_HASH'            : (CertCompare['CERT_COMPARE_SHA1_HASH'] << CertCompare['CERT_COMPARE_SHIFT']), # CERT_FIND_SHA1_HASH
        'CERT_FIND_PROPERTY'		: (CertCompare['CERT_COMPARE_PROPERTY'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_PUBLIC_KEY'		: (CertCompare['CERT_COMPARE_PUBLIC_KEY'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_SUBJECT_NAME'	: (CertCompare['CERT_COMPARE_NAME'] << CertCompare['CERT_COMPARE_SHIFT'] | CertInformationFlags['CERT_INFO_SUBJECT_FLAG']),
        'CERT_FIND_SUBJECT_ATTR'		: (CertCompare['CERT_COMPARE_ATTR'] << CertCompare['CERT_COMPARE_SHIFT'] |  CertInformationFlags['CERT_INFO_SUBJECT_FLAG']),
        'CERT_FIND_ISSUER_NAME'		: (CertCompare['CERT_COMPARE_NAME'] << CertCompare['CERT_COMPARE_SHIFT'] |  CertInformationFlags['CERT_INFO_ISSUER_FLAG']),
        'CERT_FIND_ISSUER_ATTR'		: (CertCompare['CERT_COMPARE_ATTR'] << CertCompare['CERT_COMPARE_SHIFT'] |  CertInformationFlags['CERT_INFO_ISSUER_FLAG']),
        'CERT_FIND_SUBJECT_STR_A'		: (CertCompare['CERT_COMPARE_NAME_STR_A'] << CertCompare['CERT_COMPARE_SHIFT'] | CertInformationFlags['CERT_INFO_SUBJECT_FLAG']),
        'CERT_FIND_SUBJECT_STR_W'		: (CertCompare['CERT_COMPARE_NAME_STR_W'] << CertCompare['CERT_COMPARE_SHIFT'] | CertInformationFlags['CERT_INFO_SUBJECT_FLAG']),
        'CERT_FIND_ISSUER_STR_A'		: (CertCompare['CERT_COMPARE_NAME_STR_A'] << CertCompare['CERT_COMPARE_SHIFT'] | CertInformationFlags['CERT_INFO_ISSUER_FLAG']),
        'CERT_FIND_ISSUER_STR_W'		: (CertCompare['CERT_COMPARE_NAME_STR_W'] << CertCompare['CERT_COMPARE_SHIFT'] | CertInformationFlags['CERT_INFO_ISSUER_FLAG']),
        'CERT_FIND_KEY_SPEC'		    : (CertCompare['CERT_COMPARE_KEY_SPEC'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_ENHKEY_USAGE'		: (CertCompare['CERT_COMPARE_ENHKEY_USAGE'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_CTL_USAGE'           : (CertCompare['CERT_COMPARE_ENHKEY_USAGE'] << CertCompare['CERT_COMPARE_SHIFT']), # CERT_FIND_ENHKEY_USAGE
        'CERT_FIND_SUBJECT_CERT'		: (CertCompare['CERT_COMPARE_SUBJECT_CERT'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_ISSUER_OF'		    : (CertCompare['CERT_COMPARE_ISSUER_OF'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_EXISTING'		    : (CertCompare['CERT_COMPARE_EXISTING'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_CERT_ID'		        : (CertCompare['CERT_COMPARE_CERT_ID'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_CROSS_CERT_DIST_POINTS' : (CertCompare['CERT_COMPARE_CROSS_CERT_DIST_POINTS'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_PUBKEY_MD5_HASH'     : (CertCompare['CERT_COMPARE_PUBKEY_MD5_HASH'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_SUBJECT_INFO_ACCESS' : (CertCompare['CERT_COMPARE_SUBJECT_INFO_ACCESS'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_HASH_STR'		    : (CertCompare['CERT_COMPARE_HASH_STR'] << CertCompare['CERT_COMPARE_SHIFT']),
        'CERT_FIND_HAS_PRIVATE_KEY'		: (CertCompare['CERT_COMPARE_HAS_PRIVATE_KEY'] << CertCompare['CERT_COMPARE_SHIFT'])
    })
OID = {
        #+-------------------------------------------------------------------------
        #  Predefined X509 certificate data structures that can be encoded / decoded.
        #--------------------------------------------------------------------------
        'CRYPT_ENCODE_DECODE_NONE'           : cast(PVOID(0), LPCSTR),
        'X509_CERT'                          : cast(PVOID(1), LPCSTR),
        'X509_CERT_TO_BE_SIGNED'             : cast(PVOID(2), LPCSTR),
        'X509_CERT_CRL_TO_BE_SIGNED'         : cast(PVOID(3), LPCSTR),
        'X509_CERT_REQUEST_TO_BE_SIGNED'     : cast(PVOID(4), LPCSTR),
        'X509_EXTENSIONS'                    : cast(PVOID(5), LPCSTR),
        'X509_NAME_VALUE'                    : cast(PVOID(6), LPCSTR),
        'X509_NAME'                          : cast(PVOID(7), LPCSTR),
        'X509_PUBLIC_KEY_INFO'               : cast(PVOID(8), LPCSTR),

        #+-------------------------------------------------------------------------
        #  Predefined X509 certificate extension data structures that can be
        #  encoded / decoded.
        #--------------------------------------------------------------------------
        'X509_AUTHORITY_KEY_ID'              : cast(PVOID(9), LPCSTR),
        'X509_KEY_ATTRIBUTES'                : cast(PVOID(10), LPCSTR),
        'X509_KEY_USAGE_RESTRICTION'         : cast(PVOID(11), LPCSTR),
        'X509_ALTERNATE_NAME'                : cast(PVOID(12), LPCSTR),
        'X509_BASIC_CONSTRAINTS'             : cast(PVOID(13), LPCSTR),
        'X509_KEY_USAGE'                     : cast(PVOID(14), LPCSTR),
        'X509_BASIC_CONSTRAINTS2'            : cast(PVOID(15), LPCSTR),
        'X509_CERT_POLICIES'                 : cast(PVOID(16), LPCSTR),

        #+-------------------------------------------------------------------------
        #  Additional predefined data structures that can be encoded / decoded.
        #--------------------------------------------------------------------------
        'PKCS_UTC_TIME'                      : cast(PVOID(17), LPCSTR),
        'PKCS_TIME_REQUEST'                  : cast(PVOID(18), LPCSTR),
        'RSA_CSP_PUBLICKEYBLOB'              : cast(PVOID(19), LPCSTR),
        'X509_UNICODE_NAME'                  : cast(PVOID(20), LPCSTR),

        'X509_KEYGEN_REQUEST_TO_BE_SIGNED'   : cast(PVOID(21), LPCSTR),
        'PKCS_ATTRIBUTE'                     : cast(PVOID(22), LPCSTR),
        'PKCS_CONTENT_INFO_SEQUENCE_OF_ANY'  : cast(PVOID(23), LPCSTR),

        #+-------------------------------------------------------------------------
        #  Predefined primitive data structures that can be encoded / decoded.
        #--------------------------------------------------------------------------
        'X509_UNICODE_NAME_VALUE'            : cast(PVOID(24), LPCSTR),
        'X509_ANY_STRING'                    : cast(PVOID(24), LPCSTR), # X509_NAME_VALUE
        'X509_UNICODE_ANY_STRING'            : cast(PVOID(24), LPCSTR), # X509_UNICODE_NAME_VALUE
        'X509_OCTET_STRING'                  : cast(PVOID(25), LPCSTR),
        'X509_BITS'                          : cast(PVOID(26), LPCSTR),
        'X509_INTEGER'                       : cast(PVOID(27), LPCSTR),
        'X509_MULTI_BYTE_INTEGER'            : cast(PVOID(28), LPCSTR),
        'X509_ENUMERATED'                    : cast(PVOID(29), LPCSTR),
        'X509_CHOICE_OF_TIME'                : cast(PVOID(30), LPCSTR),

        #+-------------------------------------------------------------------------
        #  More predefined X509 certificate extension data structures that can be
        #  encoded / decoded.
        #--------------------------------------------------------------------------
        'X509_AUTHORITY_KEY_ID2'             : cast(PVOID(31), LPCSTR),
        'X509_AUTHORITY_INFO_ACCESS'         : cast(PVOID(32), LPCSTR),
        'X509_SUBJECT_INFO_ACCESS'           : cast(PVOID(32), LPCSTR), # X509_AUTHORITY_INFO_ACCESS
        'X509_CRL_REASON_CODE'               : cast(PVOID(29), LPCSTR), # X509_ENUMERATED
        'PKCS_CONTENT_INFO'                  : cast(PVOID(33), LPCSTR),
        'X509_SEQUENCE_OF_ANY'               : cast(PVOID(34), LPCSTR),
        'X509_CRL_DIST_POINTS'               : cast(PVOID(35), LPCSTR),
        'X509_ENHANCED_KEY_USAGE'            : cast(PVOID(36), LPCSTR),
        'PKCS_CTL'                           : cast(PVOID(37), LPCSTR),

        'X509_MULTI_BYTE_UINT'               : cast(PVOID(38), LPCSTR),
        'X509_DSS_PUBLICKEY'                 : cast(PVOID(38), LPCSTR), # X509_MULTI_BYTE_UINT
        'X509_DSS_PARAMETERS'                : cast(PVOID(39), LPCSTR),
        'X509_DSS_SIGNATURE'                 : cast(PVOID(40), LPCSTR),
        'PKCS_RC2_CBC_PARAMETERS'            : cast(PVOID(41), LPCSTR),
        'PKCS_SMIME_CAPABILITIES'            : cast(PVOID(42), LPCSTR),

        # Qualified Certificate Statements Extension uses the same encode/decode
        # function as PKCS_SMIME_CAPABILITIES. Its data structures are identical
        # except for the names of the fields.
        'X509_QC_STATEMENTS_EXT'             : cast(PVOID(42), LPCSTR),

        #+-------------------------------------------------------------------------
        #  data structures for private keys
        #--------------------------------------------------------------------------
        'PKCS_RSA_PRIVATE_KEY'               : cast(PVOID(43), LPCSTR),
        'PKCS_PRIVATE_KEY_INFO'              : cast(PVOID(44), LPCSTR),
        'PKCS_ENCRYPTED_PRIVATE_KEY_INFO'    : cast(PVOID(45), LPCSTR),

        #+-------------------------------------------------------------------------
        #  certificate policy qualifier
        #--------------------------------------------------------------------------
        'X509_PKIX_POLICY_QUALIFIER_USERNOTICE' : cast(PVOID(46), LPCSTR),

        #+-------------------------------------------------------------------------
        #  Diffie-Hellman Key Exchange
        #--------------------------------------------------------------------------
        'X509_DH_PUBLICKEY'                  : cast(PVOID(38), LPCSTR), # X509_MULTI_BYTE_UINT
        'X509_DH_PARAMETERS'                 : cast(PVOID(47), LPCSTR),
        'PKCS_ATTRIBUTES'                    : cast(PVOID(48), LPCSTR),
        'PKCS_SORTED_CTL'                    : cast(PVOID(49), LPCSTR),

        #+-------------------------------------------------------------------------
        #  ECC Signature
        #--------------------------------------------------------------------------
        # Uses the same encode/decode function as X509_DH_PARAMETERS. Its data
        # structure is identical except for the names of the fields.
        'X509_ECC_SIGNATURE'                 : cast(PVOID(47), LPCSTR),

        #+-------------------------------------------------------------------------
        #  X942 Diffie-Hellman
        #--------------------------------------------------------------------------
        'X942_DH_PARAMETERS'                 : cast(PVOID(50), LPCSTR),

        #+-------------------------------------------------------------------------
        #  The following is the same as X509_BITS, except before encoding,
        #  the bit length is decremented to exclude trailing zero bits.
        #--------------------------------------------------------------------------
        'X509_BITS_WITHOUT_TRAILING_ZEROES'  : cast(PVOID(51), LPCSTR),

        #+-------------------------------------------------------------------------
        #  X942 Diffie-Hellman Other Info
        #--------------------------------------------------------------------------
        'X942_OTHER_INFO'                    : cast(PVOID(52), LPCSTR),

        'X509_CERT_PAIR'                     : cast(PVOID(53), LPCSTR),
        'X509_ISSUING_DIST_POINT'            : cast(PVOID(54), LPCSTR),
        'X509_NAME_CONSTRAINTS'              : cast(PVOID(55), LPCSTR),
        'X509_POLICY_MAPPINGS'               : cast(PVOID(56), LPCSTR),
        'X509_POLICY_CONSTRAINTS'            : cast(PVOID(57), LPCSTR),
        'X509_CROSS_CERT_DIST_POINTS'        : cast(PVOID(58), LPCSTR),

        #+-------------------------------------------------------------------------
        #  Certificate Management Messages over CMS (CMC) Data Structures
        #--------------------------------------------------------------------------
        'CMC_DATA'                           : cast(PVOID(59), LPCSTR),
        'CMC_RESPONSE'                       : cast(PVOID(60), LPCSTR),
        'CMC_STATUS'                         : cast(PVOID(61), LPCSTR),
        'CMC_ADD_EXTENSIONS'                 : cast(PVOID(62), LPCSTR),
        'CMC_ADD_ATTRIBUTES'                 : cast(PVOID(63), LPCSTR),

        #+-------------------------------------------------------------------------
        #  Certificate Template
        #--------------------------------------------------------------------------
        'X509_CERTIFICATE_TEMPLATE'          : cast(PVOID(64), LPCSTR),

        #+-------------------------------------------------------------------------
        #  Online Certificate Status Protocol (OCSP) Data Structures
        #--------------------------------------------------------------------------
        'OCSP_SIGNED_REQUEST'                : cast(PVOID(65), LPCSTR),
        'OCSP_REQUEST'                       : cast(PVOID(66), LPCSTR),
        'OCSP_RESPONSE'                      : cast(PVOID(67), LPCSTR),
        'OCSP_BASIC_SIGNED_RESPONSE'         : cast(PVOID(68), LPCSTR),
        'OCSP_BASIC_RESPONSE'                : cast(PVOID(69), LPCSTR),

        #+-------------------------------------------------------------------------
        #  Logotype and Biometric Extensions
        #--------------------------------------------------------------------------
        'X509_LOGOTYPE_EXT'                  : cast(PVOID(70), LPCSTR),
        'X509_BIOMETRIC_EXT'                 : cast(PVOID(71), LPCSTR),

        'CNG_RSA_PUBLIC_KEY_BLOB'            : cast(PVOID(72), LPCSTR),
        'X509_OBJECT_IDENTIFIER'             : cast(PVOID(73), LPCSTR),
        'X509_ALGORITHM_IDENTIFIER'          : cast(PVOID(74), LPCSTR),
        'PKCS_RSA_SSA_PSS_PARAMETERS'        : cast(PVOID(75), LPCSTR),
        'PKCS_RSAES_OAEP_PARAMETERS'         : cast(PVOID(76), LPCSTR),

        'ECC_CMS_SHARED_INFO'                : cast(PVOID(77), LPCSTR),

        #+-------------------------------------------------------------------------
        #  TIMESTAMP
        #--------------------------------------------------------------------------
        'TIMESTAMP_REQUEST'                  : cast(PVOID(78), LPCSTR),
        'TIMESTAMP_RESPONSE'                 : cast(PVOID(79), LPCSTR),
        'TIMESTAMP_INFO'                     : cast(PVOID(80), LPCSTR),

        #+-------------------------------------------------------------------------
        #  CertificateBundle
        #--------------------------------------------------------------------------
        'X509_CERT_BUNDLE'                   : cast(PVOID(81), LPCSTR),

        #+-------------------------------------------------------------------------
        #  ECC Keys
        #--------------------------------------------------------------------------
        'X509_ECC_PRIVATE_KEY'               : cast(PVOID(82), LPCSTR),   # CRYPT_ECC_PRIVATE_KEY_INFO

        'CNG_RSA_PRIVATE_KEY_BLOB'           : cast(PVOID(83), LPCSTR),   # BCRYPT_RSAKEY_BLOB

        #+-------------------------------------------------------------------------
        #  Subject Directory Attributes extension
        #--------------------------------------------------------------------------
        'X509_SUBJECT_DIR_ATTRS'             : cast(PVOID(84), LPCSTR),


        #+-------------------------------------------------------------------------
        #  Predefined PKCS #7 data structures that can be encoded / decoded.
        #--------------------------------------------------------------------------
        'PKCS7_SIGNER_INFO'                  : cast(PVOID(500), LPCSTR),

        #+-------------------------------------------------------------------------
        #  Predefined PKCS #7 data structures that can be encoded / decoded.
        #--------------------------------------------------------------------------
        'CMS_SIGNER_INFO'                    : cast(PVOID(501), LPCSTR),
        
        #+-------------------------------------------------------------------------
        #  CERT_RDN attribute Object Identifiers
        #--------------------------------------------------------------------------
        # Labeling attribute types:
        'szOID_COMMON_NAME' : "2.5.4.3",    # case-ignore string
        'szOID_SUR_NAME' : "2.5.4.4",    # case-ignore string
        'szOID_DEVICE_SERIAL_NUMBER' : "2.5.4.5",    # printable string

        # Geographic attribute types:
        'szOID_COUNTRY_NAME' : "2.5.4.6",    # printable 2char string
        'szOID_LOCALITY_NAME' : "2.5.4.7",    # case-ignore string
        'szOID_STATE_OR_PROVINCE_NAME' : "2.5.4.8",    # case-ignore string
        'szOID_STREET_ADDRESS' : "2.5.4.9",    # case-ignore string

        # Organizational attribute types:
        'szOID_ORGANIZATION_NAME' : "2.5.4.10",    # case-ignore string
        'szOID_ORGANIZATIONAL_UNIT_NAME' : "2.5.4.11",    # case-ignore string
        'szOID_TITLE' : "2.5.4.12",    # case-ignore string

        # Explanatory attribute types:
        'szOID_DESCRIPTION' : "2.5.4.13",    # case-ignore string
        'szOID_SEARCH_GUIDE' : "2.5.4.14",
        'szOID_BUSINESS_CATEGORY' : "2.5.4.15",    # case-ignore string

        # Postal addressing attribute types:
        'szOID_POSTAL_ADDRESS' : "2.5.4.16",
        'szOID_POSTAL_CODE' : "2.5.4.17",    # case-ignore string
        'szOID_POST_OFFICE_BOX' : "2.5.4.18",    # case-ignore string
        'szOID_PHYSICAL_DELIVERY_OFFICE_NAME' : "2.5.4.19",    # case-ignore string

        # Telecommunications addressing attribute types:
        'szOID_TELEPHONE_NUMBER' : "2.5.4.20",    # telephone number
        'szOID_TELEX_NUMBER' : "2.5.4.21",
        'szOID_TELETEXT_TERMINAL_IDENTIFIER' : "2.5.4.22",
        'szOID_FACSIMILE_TELEPHONE_NUMBER' : "2.5.4.23",
        'szOID_X21_ADDRESS' : "2.5.4.24",    # numeric string
        'szOID_INTERNATIONAL_ISDN_NUMBER' : "2.5.4.25",    # numeric string
        'szOID_REGISTERED_ADDRESS' : "2.5.4.26",
        'szOID_DESTINATION_INDICATOR' : "2.5.4.27",    # printable string

        # Preference attribute types:
        'szOID_PREFERRED_DELIVERY_METHOD' : "2.5.4.28",

        # OSI application attribute types:
        'szOID_PRESENTATION_ADDRESS' : "2.5.4.29",
        'szOID_SUPPORTED_APPLICATION_CONTEXT' : "2.5.4.30",

        # Relational application attribute types:
        'szOID_MEMBER' : "2.5.4.31",
        'szOID_OWNER' : "2.5.4.32",
        'szOID_ROLE_OCCUPANT' : "2.5.4.33",
        'szOID_SEE_ALSO' : "2.5.4.34",

        # Security attribute types:
        'szOID_USER_PASSWORD' : "2.5.4.35",
        'szOID_USER_CERTIFICATE' : "2.5.4.36",
        'szOID_CA_CERTIFICATE' : "2.5.4.37",
        'szOID_AUTHORITY_REVOCATION_LIST' : "2.5.4.38",
        'szOID_CERTIFICATE_REVOCATION_LIST' : "2.5.4.39",
        'szOID_CROSS_CERTIFICATE_PAIR' : "2.5.4.40",

        # Undocumented attribute types???
        #'szOID_???' : "2.5.4.41",
        'szOID_GIVEN_NAME' : "2.5.4.42",    # case-ignore string
        'szOID_INITIALS' : "2.5.4.43",    # case-ignore string

        # The DN Qualifier attribute type specifies disambiguating information to add
        # to the relative distinguished name of an entry. It is intended to be used
        # for entries held in multiple DSAs which would otherwise have the same name,
        # and that its value be the same in a given DSA for all entries to which
        # the information has been added.
        'szOID_DN_QUALIFIER' : "2.5.4.46",

        # Pilot user attribute types:
        'szOID_DOMAIN_COMPONENT' : "0.9.2342.19200300.100.1.25",    # IA5, UTF8 string

        # used for PKCS 12 attributes
        'szOID_PKCS_12_FRIENDLY_NAME_ATTR' : "1.2.840.113549.1.9.20",
        'szOID_PKCS_12_LOCAL_KEY_ID' : "1.2.840.113549.1.9.21",
        'szOID_PKCS_12_KEY_PROVIDER_NAME_ATTR' : "1.3.6.1.4.1.311.17.1",
        'szOID_LOCAL_MACHINE_KEYSET' : "1.3.6.1.4.1.311.17.2",
        'szOID_PKCS_12_EXTENDED_ATTRIBUTES' : "1.3.6.1.4.1.311.17.3",
        'szOID_PKCS_12_PROTECTED_PASSWORD_SECRET_BAG_TYPE_ID' : "1.3.6.1.4.1.311.17.4",

        #+-------------------------------------------------------------------------
        #  Microsoft CERT_RDN attribute Object Identifiers
        #--------------------------------------------------------------------------
        # Special RDN containing the KEY_ID. Its value type is CERT_RDN_OCTET_STRING.
        'szOID_KEYID_RDN' : "1.3.6.1.4.1.311.10.7.1",

        #+-------------------------------------------------------------------------
        #  EV RDN OIDs
        #--------------------------------------------------------------------------
        'szOID_EV_RDN_LOCALE' : "1.3.6.1.4.1.311.60.2.1.1",
        'szOID_EV_RDN_STATE_OR_PROVINCE' : "1.3.6.1.4.1.311.60.2.1.2",
        'szOID_EV_RDN_COUNTRY' : "1.3.6.1.4.1.311.60.2.1.3",
        #
        #  CTL Trusted CA Lists
        #
        'szOID_TRUSTED_CODESIGNING_CA_LIST' : "1.3.6.1.4.1.311.2.2.1",
        'szOID_TRUSTED_CLIENT_AUTH_CA_LIST' : "1.3.6.1.4.1.311.2.2.2",
        'szOID_TRUSTED_SERVER_AUTH_CA_LIST' : "1.3.6.1.4.1.311.2.2.3",

        #
        #  encode/decode OID defines
        #
        'SPC_COMMON_NAME_OBJID' : "2.5.4.3",
        'SPC_TIME_STAMP_REQUEST_OBJID' : "1.3.6.1.4.1.311.3.2.1",
        'SPC_INDIRECT_DATA_OBJID' : "1.3.6.1.4.1.311.2.1.4",
        'SPC_SP_AGENCY_INFO_OBJID' : "1.3.6.1.4.1.311.2.1.10",
        'SPC_STATEMENT_TYPE_OBJID' : "1.3.6.1.4.1.311.2.1.11",
        'SPC_SP_OPUS_INFO_OBJID' : "1.3.6.1.4.1.311.2.1.12",
        'SPC_CERT_EXTENSIONS_OBJID' : "1.3.6.1.4.1.311.2.1.14",
        'SPC_PE_IMAGE_DATA_OBJID' : "1.3.6.1.4.1.311.2.1.15",
        'SPC_RAW_FILE_DATA_OBJID' : "1.3.6.1.4.1.311.2.1.18",
        'SPC_STRUCTURED_STORAGE_DATA_OBJID' : "1.3.6.1.4.1.311.2.1.19",
        'SPC_JAVA_CLASS_DATA_OBJID' : "1.3.6.1.4.1.311.2.1.20",
        'SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID' : "1.3.6.1.4.1.311.2.1.21",
        'SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID' : "1.3.6.1.4.1.311.2.1.22",
        'SPC_CAB_DATA_OBJID' : "1.3.6.1.4.1.311.2.1.25",
        'SPC_GLUE_RDN_OBJID' : "1.3.6.1.4.1.311.2.1.25",    # obsolete!
        'SPC_MINIMAL_CRITERIA_OBJID' : "1.3.6.1.4.1.311.2.1.26",
        'SPC_FINANCIAL_CRITERIA_OBJID' : "1.3.6.1.4.1.311.2.1.27",
        'SPC_LINK_OBJID' : "1.3.6.1.4.1.311.2.1.28",
        'SPC_SIGINFO_OBJID' : "1.3.6.1.4.1.311.2.1.30",

        #
        #  Page hash versions
        #
        'SPC_PE_IMAGE_PAGE_HASHES_V1_OBJID' : "1.3.6.1.4.1.311.2.3.1",     # V1
        'SPC_PE_IMAGE_PAGE_HASHES_V2_OBJID' : "1.3.6.1.4.1.311.2.3.2",     # V2

        #Indicates the attribute is an octet encoded PKCS7 
        'szOID_NESTED_SIGNATURE' : "1.3.6.1.4.1.311.2.4.1",
        'szOID_INTENT_TO_SEAL' : "1.3.6.1.4.1.311.2.4.2",
        'szOID_SEALING_SIGNATURE' : "1.3.6.1.4.1.311.2.4.3",
        'szOID_SEALING_TIMESTAMP' : "1.3.6.1.4.1.311.2.4.4",

        #Indicates an enhanced hash for a SIP Indirect Data
        'szOID_ENHANCED_HASH' : "1.3.6.1.4.1.311.2.5.1",

        #Indicates a PKCS9 sequence number as an attribute
        'szOID_PKCS_9_SEQUENCE_NUMBER' : "1.2.840.113549.1.9.25.4",

        #
        #  Catalog entries
        #
        'CAT_NAMEVALUE_OBJID' : "1.3.6.1.4.1.311.12.2.1",
        'CAT_MEMBERINFO_OBJID' : "1.3.6.1.4.1.311.12.2.2",
        'CAT_MEMBERINFO2_OBJID' : "1.3.6.1.4.1.311.12.2.3",
        # Following are the definitions of various algorithm object identifiers
        # RSA
        'szOID_RSA' : "1.2.840.113549",
        'szOID_PKCS' : "1.2.840.113549.1",
        'szOID_RSA_HASH' : "1.2.840.113549.2",
        'szOID_RSA_ENCRYPT' : "1.2.840.113549.3",

        'szOID_PKCS_1' : "1.2.840.113549.1.1",
        'szOID_PKCS_2' : "1.2.840.113549.1.2",
        'szOID_PKCS_3' : "1.2.840.113549.1.3",
        'szOID_PKCS_4' : "1.2.840.113549.1.4",
        'szOID_PKCS_5' : "1.2.840.113549.1.5",
        'szOID_PKCS_6' : "1.2.840.113549.1.6",
        'szOID_PKCS_7' : "1.2.840.113549.1.7",
        'szOID_PKCS_8' : "1.2.840.113549.1.8",
        'szOID_PKCS_9' : "1.2.840.113549.1.9",
        'szOID_PKCS_10' : "1.2.840.113549.1.10",
        'szOID_PKCS_12' : "1.2.840.113549.1.12",

        'szOID_RSA_RSA' : "1.2.840.113549.1.1.1",
        'szOID_RSA_MD2RSA' : "1.2.840.113549.1.1.2",
        'szOID_RSA_MD4RSA' : "1.2.840.113549.1.1.3",
        'szOID_RSA_MD5RSA' : "1.2.840.113549.1.1.4",
        'szOID_RSA_SHA1RSA' : "1.2.840.113549.1.1.5",
        'szOID_RSA_SETOAEP_RSA' : "1.2.840.113549.1.1.6",

        'szOID_RSAES_OAEP' : "1.2.840.113549.1.1.7",
        'szOID_RSA_MGF1' : "1.2.840.113549.1.1.8",
        'szOID_RSA_PSPECIFIED' : "1.2.840.113549.1.1.9",
        'szOID_RSA_SSA_PSS' : "1.2.840.113549.1.1.10",
        'szOID_RSA_SHA256RSA' : "1.2.840.113549.1.1.11",
        'szOID_RSA_SHA384RSA' : "1.2.840.113549.1.1.12",
        'szOID_RSA_SHA512RSA' : "1.2.840.113549.1.1.13",

        'szOID_RSA_DH' : "1.2.840.113549.1.3.1",

        'szOID_RSA_data' : "1.2.840.113549.1.7.1",
        'szOID_RSA_signedData' : "1.2.840.113549.1.7.2",
        'szOID_RSA_envelopedData' : "1.2.840.113549.1.7.3",
        'szOID_RSA_signEnvData' : "1.2.840.113549.1.7.4",
        'szOID_RSA_digestedData' : "1.2.840.113549.1.7.5",
        'szOID_RSA_hashedData' : "1.2.840.113549.1.7.5",
        'szOID_RSA_encryptedData' : "1.2.840.113549.1.7.6",

        'szOID_RSA_emailAddr' : "1.2.840.113549.1.9.1",
        'szOID_RSA_unstructName' : "1.2.840.113549.1.9.2",
        'szOID_RSA_contentType' : "1.2.840.113549.1.9.3",
        'szOID_RSA_messageDigest' : "1.2.840.113549.1.9.4",
        'szOID_RSA_signingTime' : "1.2.840.113549.1.9.5",
        'szOID_RSA_counterSign' : "1.2.840.113549.1.9.6",
        'szOID_RSA_challengePwd' : "1.2.840.113549.1.9.7",
        'szOID_RSA_unstructAddr' : "1.2.840.113549.1.9.8",
        'szOID_RSA_extCertAttrs' : "1.2.840.113549.1.9.9",
        'szOID_RSA_certExtensions' : "1.2.840.113549.1.9.14",
        'szOID_RSA_SMIMECapabilities' : "1.2.840.113549.1.9.15",
        'szOID_RSA_preferSignedData' : "1.2.840.113549.1.9.15.1",

        'szOID_TIMESTAMP_TOKEN' : "1.2.840.113549.1.9.16.1.4",
        'szOID_RFC3161_counterSign' : "1.3.6.1.4.1.311.3.3.1",

        'szOID_RSA_SMIMEalg' : "1.2.840.113549.1.9.16.3",
        'szOID_RSA_SMIMEalgESDH' : "1.2.840.113549.1.9.16.3.5",
        'szOID_RSA_SMIMEalgCMS3DESwrap' : "1.2.840.113549.1.9.16.3.6",
        'szOID_RSA_SMIMEalgCMSRC2wrap' : "1.2.840.113549.1.9.16.3.7",

        'szOID_RSA_MD2' : "1.2.840.113549.2.2",
        'szOID_RSA_MD4' : "1.2.840.113549.2.4",
        'szOID_RSA_MD5' : "1.2.840.113549.2.5",

        'szOID_RSA_RC2CBC' : "1.2.840.113549.3.2",
        'szOID_RSA_RC4' : "1.2.840.113549.3.4",
        'szOID_RSA_DES_EDE3_CBC' : "1.2.840.113549.3.7",
        'szOID_RSA_RC5_CBCPad' : "1.2.840.113549.3.9",


        'szOID_ANSI_X942' : "1.2.840.10046",
        'szOID_ANSI_X942_DH' : "1.2.840.10046.2.1",

        'szOID_X957' : "1.2.840.10040",
        'szOID_X957_DSA' : "1.2.840.10040.4.1",
        'szOID_X957_SHA1DSA' : "1.2.840.10040.4.3",


        # iso(1) member-body(2) us(840) 10045 keyType(2) unrestricted(1)
        'szOID_ECC_PUBLIC_KEY' : "1.2.840.10045.2.1",

        # iso(1) member-body(2) us(840) 10045 curves(3) prime(1) 7
        'szOID_ECC_CURVE_P256' : "1.2.840.10045.3.1.7",

        # iso(1) identified-organization(3) certicom(132) curve(0) 34
        'szOID_ECC_CURVE_P384' : "1.3.132.0.34",

        # iso(1) identified-organization(3) certicom(132) curve(0) 35
        'szOID_ECC_CURVE_P521' : "1.3.132.0.35",


        # iso(1) member-body(2) us(840) 10045 signatures(4) sha1(1)
        'szOID_ECDSA_SHA1' : "1.2.840.10045.4.1",

        # iso(1) member-body(2) us(840) 10045 signatures(4) specified(3)
        'szOID_ECDSA_SPECIFIED' : "1.2.840.10045.4.3",

        # iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 2
        'szOID_ECDSA_SHA256' : "1.2.840.10045.4.3.2",

        # iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 3
        'szOID_ECDSA_SHA384' : "1.2.840.10045.4.3.3",

        # iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 4
        'szOID_ECDSA_SHA512' : "1.2.840.10045.4.3.4",


        # NIST AES CBC Algorithms
        # joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4)  aesAlgs(1) }

        'szOID_NIST_AES128_CBC' : "2.16.840.1.101.3.4.1.2",
        'szOID_NIST_AES192_CBC' : "2.16.840.1.101.3.4.1.22",
        'szOID_NIST_AES256_CBC' : "2.16.840.1.101.3.4.1.42",

        # For the above Algorithms, the AlgorithmIdentifier parameters must be
        # present and the parameters field MUST contain an AES-IV:
        #
        #  AES-IV ::= OCTET STRING (SIZE(16))

        # NIST AES WRAP Algorithms
        'szOID_NIST_AES128_WRAP' : "2.16.840.1.101.3.4.1.5",
        'szOID_NIST_AES192_WRAP' : "2.16.840.1.101.3.4.1.25",
        'szOID_NIST_AES256_WRAP' : "2.16.840.1.101.3.4.1.45",


        #      x9-63-scheme OBJECT IDENTIFIER ::= { iso(1)
        #         identified-organization(3) tc68(133) country(16) x9(840)
        #         x9-63(63) schemes(0) }


        # ECDH single pass ephemeral-static KeyAgreement KeyEncryptionAlgorithm
        'szOID_DH_SINGLE_PASS_STDDH_SHA1_KDF' : "1.3.133.16.840.63.0.2",
        'szOID_DH_SINGLE_PASS_STDDH_SHA256_KDF' : "1.3.132.1.11.1",
        'szOID_DH_SINGLE_PASS_STDDH_SHA384_KDF' : "1.3.132.1.11.2",

        # For the above KeyEncryptionAlgorithm the following wrap algorithms are
        # supported:
        #  szOID_RSA_SMIMEalgCMS3DESwrap
        #  szOID_RSA_SMIMEalgCMSRC2wrap
        #  szOID_NIST_AES128_WRAP
        #  szOID_NIST_AES192_WRAP
        #  szOID_NIST_AES256_WRAP



        # ITU-T UsefulDefinitions
        'szOID_DS' : "2.5",
        'szOID_DSALG' : "2.5.8",
        'szOID_DSALG_CRPT' : "2.5.8.1",
        'szOID_DSALG_HASH' : "2.5.8.2",
        'szOID_DSALG_SIGN' : "2.5.8.3",
        'szOID_DSALG_RSA' : "2.5.8.1.1",
        # NIST OSE Implementors' Workshop (OIW)
        # http:nemo.ncsl.nist.gov/oiw/agreements/stable/OSI/12s_9506.w51
        # http:nemo.ncsl.nist.gov/oiw/agreements/working/OSI/12w_9503.w51
        'szOID_OIW' : "1.3.14",
        # NIST OSE Implementors' Workshop (OIW) Security SIG algorithm identifiers
        'szOID_OIWSEC' : "1.3.14.3.2",
        'szOID_OIWSEC_md4RSA' : "1.3.14.3.2.2",
        'szOID_OIWSEC_md5RSA' : "1.3.14.3.2.3",
        'szOID_OIWSEC_md4RSA2' : "1.3.14.3.2.4",
        'szOID_OIWSEC_desECB' : "1.3.14.3.2.6",
        'szOID_OIWSEC_desCBC' : "1.3.14.3.2.7",
        'szOID_OIWSEC_desOFB' : "1.3.14.3.2.8",
        'szOID_OIWSEC_desCFB' : "1.3.14.3.2.9",
        'szOID_OIWSEC_desMAC' : "1.3.14.3.2.10",
        'szOID_OIWSEC_rsaSign' : "1.3.14.3.2.11",
        'szOID_OIWSEC_dsa' : "1.3.14.3.2.12",
        'szOID_OIWSEC_shaDSA' : "1.3.14.3.2.13",
        'szOID_OIWSEC_mdc2RSA' : "1.3.14.3.2.14",
        'szOID_OIWSEC_shaRSA' : "1.3.14.3.2.15",
        'szOID_OIWSEC_dhCommMod' : "1.3.14.3.2.16",
        'szOID_OIWSEC_desEDE' : "1.3.14.3.2.17",
        'szOID_OIWSEC_sha' : "1.3.14.3.2.18",
        'szOID_OIWSEC_mdc2' : "1.3.14.3.2.19",
        'szOID_OIWSEC_dsaComm' : "1.3.14.3.2.20",
        'szOID_OIWSEC_dsaCommSHA' : "1.3.14.3.2.21",
        'szOID_OIWSEC_rsaXchg' : "1.3.14.3.2.22",
        'szOID_OIWSEC_keyHashSeal' : "1.3.14.3.2.23",
        'szOID_OIWSEC_md2RSASign' : "1.3.14.3.2.24",
        'szOID_OIWSEC_md5RSASign' : "1.3.14.3.2.25",
        'szOID_OIWSEC_sha1' : "1.3.14.3.2.26",
        'szOID_OIWSEC_dsaSHA1' : "1.3.14.3.2.27",
        'szOID_OIWSEC_dsaCommSHA1' : "1.3.14.3.2.28",
        'szOID_OIWSEC_sha1RSASign' : "1.3.14.3.2.29",
        # NIST OSE Implementors' Workshop (OIW) Directory SIG algorithm identifiers
        'szOID_OIWDIR' : "1.3.14.7.2",
        'szOID_OIWDIR_CRPT' : "1.3.14.7.2.1",
        'szOID_OIWDIR_HASH' : "1.3.14.7.2.2",
        'szOID_OIWDIR_SIGN' : "1.3.14.7.2.3",
        'szOID_OIWDIR_md2' : "1.3.14.7.2.2.1",
        'szOID_OIWDIR_md2RSA' : "1.3.14.7.2.3.1",


        # INFOSEC Algorithms
        # joint-iso-ccitt(2) country(16) us(840) organization(1) us-government(101) dod(2) id-infosec(1)
        'szOID_INFOSEC' : "2.16.840.1.101.2.1",
        'szOID_INFOSEC_sdnsSignature' : "2.16.840.1.101.2.1.1.1",
        'szOID_INFOSEC_mosaicSignature' : "2.16.840.1.101.2.1.1.2",
        'szOID_INFOSEC_sdnsConfidentiality' : "2.16.840.1.101.2.1.1.3",
        'szOID_INFOSEC_mosaicConfidentiality' : "2.16.840.1.101.2.1.1.4",
        'szOID_INFOSEC_sdnsIntegrity' : "2.16.840.1.101.2.1.1.5",
        'szOID_INFOSEC_mosaicIntegrity' : "2.16.840.1.101.2.1.1.6",
        'szOID_INFOSEC_sdnsTokenProtection' : "2.16.840.1.101.2.1.1.7",
        'szOID_INFOSEC_mosaicTokenProtection' : "2.16.840.1.101.2.1.1.8",
        'szOID_INFOSEC_sdnsKeyManagement' : "2.16.840.1.101.2.1.1.9",
        'szOID_INFOSEC_mosaicKeyManagement' : "2.16.840.1.101.2.1.1.10",
        'szOID_INFOSEC_sdnsKMandSig' : "2.16.840.1.101.2.1.1.11",
        'szOID_INFOSEC_mosaicKMandSig' : "2.16.840.1.101.2.1.1.12",
        'szOID_INFOSEC_SuiteASignature' : "2.16.840.1.101.2.1.1.13",
        'szOID_INFOSEC_SuiteAConfidentiality' : "2.16.840.1.101.2.1.1.14",
        'szOID_INFOSEC_SuiteAIntegrity' : "2.16.840.1.101.2.1.1.15",
        'szOID_INFOSEC_SuiteATokenProtection' : "2.16.840.1.101.2.1.1.16",
        'szOID_INFOSEC_SuiteAKeyManagement' : "2.16.840.1.101.2.1.1.17",
        'szOID_INFOSEC_SuiteAKMandSig' : "2.16.840.1.101.2.1.1.18",
        'szOID_INFOSEC_mosaicUpdatedSig' : "2.16.840.1.101.2.1.1.19",
        'szOID_INFOSEC_mosaicKMandUpdSig' : "2.16.840.1.101.2.1.1.20",
        'szOID_INFOSEC_mosaicUpdatedInteg' : "2.16.840.1.101.2.1.1.21",

        # NIST Hash Algorithms
        # joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2)

        'szOID_NIST_sha256' : "2.16.840.1.101.3.4.2.1",
        'szOID_NIST_sha384' : "2.16.840.1.101.3.4.2.2",
        'szOID_NIST_sha512' : "2.16.840.1.101.3.4.2.3",
                
        #+-------------------------------------------------------------------------
        #  Extension Object Identifiers
        #--------------------------------------------------------------------------
        'szOID_AUTHORITY_KEY_IDENTIFIER' : "2.5.29.1",
        'szOID_KEY_ATTRIBUTES' : "2.5.29.2",
        'szOID_CERT_POLICIES_95' : "2.5.29.3",
        'szOID_KEY_USAGE_RESTRICTION' : "2.5.29.4",
        'szOID_SUBJECT_ALT_NAME' : "2.5.29.7",
        'szOID_ISSUER_ALT_NAME' : "2.5.29.8",
        'szOID_BASIC_CONSTRAINTS' : "2.5.29.10",
        'szOID_KEY_USAGE' : "2.5.29.15",
        'szOID_PRIVATEKEY_USAGE_PERIOD' : "2.5.29.16",
        'szOID_BASIC_CONSTRAINTS2' : "2.5.29.19",

        'szOID_CERT_POLICIES' : "2.5.29.32",
        'szOID_ANY_CERT_POLICY' : "2.5.29.32.0",
        'szOID_INHIBIT_ANY_POLICY' : "2.5.29.54",

        'szOID_AUTHORITY_KEY_IDENTIFIER2' : "2.5.29.35",
        'szOID_SUBJECT_KEY_IDENTIFIER' : "2.5.29.14",
        'szOID_SUBJECT_ALT_NAME2' : "2.5.29.17",
        'szOID_ISSUER_ALT_NAME2' : "2.5.29.18",
        'szOID_CRL_REASON_CODE' : "2.5.29.21",
        'szOID_REASON_CODE_HOLD' : "2.5.29.23",
        'szOID_CRL_DIST_POINTS' : "2.5.29.31",
        'szOID_ENHANCED_KEY_USAGE' : "2.5.29.37",

        'szOID_ANY_ENHANCED_KEY_USAGE' : "2.5.29.37.0",

        # szOID_CRL_NUMBER -- Base CRLs only.  Monotonically increasing sequence
        # number for each CRL issued by a CA.
        'szOID_CRL_NUMBER' : "2.5.29.20",
        # szOID_DELTA_CRL_INDICATOR -- Delta CRLs only.  Marked critical.
        # Contains the minimum base CRL Number that can be used with a delta CRL.
        'szOID_DELTA_CRL_INDICATOR' : "2.5.29.27",
        'szOID_ISSUING_DIST_POINT' : "2.5.29.28",
        # szOID_FRESHEST_CRL -- Base CRLs only.  Formatted identically to a CDP
        # extension that holds URLs to fetch the delta CRL.
        'szOID_FRESHEST_CRL' : "2.5.29.46",
        'szOID_NAME_CONSTRAINTS' : "2.5.29.30",

        # Note on 1/1/2000 szOID_POLICY_MAPPINGS was changed from' : "2.5.29.5",
        'szOID_POLICY_MAPPINGS' : "2.5.29.33",
        'szOID_LEGACY_POLICY_MAPPINGS' : "2.5.29.5",
        'szOID_POLICY_CONSTRAINTS' : "2.5.29.36",


        # Microsoft PKCS10 Attributes
        'szOID_RENEWAL_CERTIFICATE' : "1.3.6.1.4.1.311.13.1",
        'szOID_ENROLLMENT_NAME_VALUE_PAIR' : "1.3.6.1.4.1.311.13.2.1",
        'szOID_ENROLLMENT_CSP_PROVIDER' : "1.3.6.1.4.1.311.13.2.2",
        'szOID_OS_VERSION' : "1.3.6.1.4.1.311.13.2.3",

        #
        # Extension contain certificate type
        'szOID_ENROLLMENT_AGENT' : "1.3.6.1.4.1.311.20.2.1",

        # Internet Public Key Infrastructure (PKIX)
        'szOID_PKIX' : "1.3.6.1.5.5.7",
        'szOID_PKIX_PE' : "1.3.6.1.5.5.7.1",
        'szOID_AUTHORITY_INFO_ACCESS' : "1.3.6.1.5.5.7.1.1",
        'szOID_SUBJECT_INFO_ACCESS' : "1.3.6.1.5.5.7.1.11",
        'szOID_BIOMETRIC_EXT' : "1.3.6.1.5.5.7.1.2",
        'szOID_QC_STATEMENTS_EXT' : "1.3.6.1.5.5.7.1.3",
        'szOID_LOGOTYPE_EXT' : "1.3.6.1.5.5.7.1.12",

        # Microsoft extensions or attributes
        'szOID_CERT_EXTENSIONS' : "1.3.6.1.4.1.311.2.1.14",
        'szOID_NEXT_UPDATE_LOCATION' : "1.3.6.1.4.1.311.10.2",
        'szOID_REMOVE_CERTIFICATE' : "1.3.6.1.4.1.311.10.8.1",
        'szOID_CROSS_CERT_DIST_POINTS' : "1.3.6.1.4.1.311.10.9.1",

        #  Microsoft PKCS #7 ContentType Object Identifiers
        'szOID_CTL' : "1.3.6.1.4.1.311.10.1",

        #  Microsoft Sorted CTL Extension Object Identifier
        'szOID_SORTED_CTL' : "1.3.6.1.4.1.311.10.1.1",

        # serialized serial numbers for PRS
        #ifndef szOID_SERIALIZED
        'szOID_SERIALIZED' : "1.3.6.1.4.1.311.10.3.3.1",
        #endif

        # UPN principal name in SubjectAltName
        #ifndef szOID_NT_PRINCIPAL_NAME
        'szOID_NT_PRINCIPAL_NAME' : "1.3.6.1.4.1.311.20.2.3",
        #endif

        # Internationalized Email Address in SubjectAltName (OtherName:UTF8)
        #ifndef szOID_INTERNATIONALIZED_EMAIL_ADDRESS
        'szOID_INTERNATIONALIZED_EMAIL_ADDRESS' : "1.3.6.1.4.1.311.20.2.4",
        #endif

        # Windows product update unauthenticated attribute
        #ifndef szOID_PRODUCT_UPDATE
        'szOID_PRODUCT_UPDATE' : "1.3.6.1.4.1.311.31.1",
        #endif

        # CryptUI
        'szOID_ANY_APPLICATION_POLICY' : "1.3.6.1.4.1.311.10.12.1",

        #+-------------------------------------------------------------------------
        #  Object Identifiers for use with Auto Enrollment
        #--------------------------------------------------------------------------
        'szOID_AUTO_ENROLL_CTL_USAGE' : "1.3.6.1.4.1.311.20.1",

        # Extension contain certificate type
        # AKA Certificate template extension (v1)
        'szOID_ENROLL_CERTTYPE_EXTENSION' : "1.3.6.1.4.1.311.20.2",


        'szOID_CERT_MANIFOLD' : "1.3.6.1.4.1.311.20.3",

        #+-------------------------------------------------------------------------
        #  Object Identifiers for use with the MS Certificate Server
        #--------------------------------------------------------------------------
        #ifndef szOID_CERTSRV_CA_VERSION
        'szOID_CERTSRV_CA_VERSION' : "1.3.6.1.4.1.311.21.1",
        #endif


        # szOID_CERTSRV_PREVIOUS_CERT_HASH -- Contains the sha1 hash of the previous
        # version of the CA certificate.
        'szOID_CERTSRV_PREVIOUS_CERT_HASH' : "1.3.6.1.4.1.311.21.2",

        # szOID_CRL_VIRTUAL_BASE -- Delta CRLs only.  Contains the base CRL Number
        # of the corresponding base CRL.
        'szOID_CRL_VIRTUAL_BASE' : "1.3.6.1.4.1.311.21.3",

        # szOID_CRL_NEXT_PUBLISH -- Contains the time when the next CRL is expected
        # to be published.  This may be sooner than the CRL's NextUpdate field.
        'szOID_CRL_NEXT_PUBLISH' : "1.3.6.1.4.1.311.21.4",

        # Enhanced Key Usage for CA encryption certificate
        'szOID_KP_CA_EXCHANGE' : "1.3.6.1.4.1.311.21.5",

        # Enhanced Key Usage for key recovery agent certificate
        'szOID_KP_KEY_RECOVERY_AGENT' : "1.3.6.1.4.1.311.21.6",

        # Certificate template extension (v2)
        'szOID_CERTIFICATE_TEMPLATE' : "1.3.6.1.4.1.311.21.7",

        # The root oid for all enterprise specific oids
        'szOID_ENTERPRISE_OID_ROOT' : "1.3.6.1.4.1.311.21.8",

        # Dummy signing Subject RDN
        'szOID_RDN_DUMMY_SIGNER' : "1.3.6.1.4.1.311.21.9",

        # Application Policies extension -- same encoding as szOID_CERT_POLICIES
        'szOID_APPLICATION_CERT_POLICIES' : "1.3.6.1.4.1.311.21.10",

        # Application Policy Mappings -- same encoding as szOID_POLICY_MAPPINGS
        'szOID_APPLICATION_POLICY_MAPPINGS' : "1.3.6.1.4.1.311.21.11",

        # Application Policy Constraints -- same encoding as szOID_POLICY_CONSTRAINTS
        'szOID_APPLICATION_POLICY_CONSTRAINTS' : "1.3.6.1.4.1.311.21.12",

        'szOID_ARCHIVED_KEY_ATTR' : "1.3.6.1.4.1.311.21.13",
        'szOID_CRL_SELF_CDP' : "1.3.6.1.4.1.311.21.14",


        # Requires all certificates below the root to have a non-empty intersecting
        # issuance certificate policy usage.
        'szOID_REQUIRE_CERT_CHAIN_POLICY' : "1.3.6.1.4.1.311.21.15",
        'szOID_ARCHIVED_KEY_CERT_HASH' : "1.3.6.1.4.1.311.21.16",
        'szOID_ISSUED_CERT_HASH' : "1.3.6.1.4.1.311.21.17",

        # Enhanced key usage for DS email replication
        'szOID_DS_EMAIL_REPLICATION' : "1.3.6.1.4.1.311.21.19",

        'szOID_REQUEST_CLIENT_INFO' : "1.3.6.1.4.1.311.21.20",
        'szOID_ENCRYPTED_KEY_HASH' : "1.3.6.1.4.1.311.21.21",
        'szOID_CERTSRV_CROSSCA_VERSION' : "1.3.6.1.4.1.311.21.22",

        #+-------------------------------------------------------------------------
        #  Object Identifiers for use with the MS Directory Service
        #--------------------------------------------------------------------------
        'szOID_NTDS_REPLICATION' : "1.3.6.1.4.1.311.25.1",


        #+-------------------------------------------------------------------------
        #  Extension Object Identifiers
        #--------------------------------------------------------------------------
        'szOID_SUBJECT_DIR_ATTRS' : "2.5.29.9",

        #+-------------------------------------------------------------------------
        #  Enhanced Key Usage (Purpose) Object Identifiers
        #--------------------------------------------------------------------------
        'szOID_PKIX_KP' : "1.3.6.1.5.5.7.3",

        # Consistent key usage bits: DIGITAL_SIGNATURE, KEY_ENCIPHERMENT
        # or KEY_AGREEMENT
        'szOID_PKIX_KP_SERVER_AUTH' : "1.3.6.1.5.5.7.3.1",

        # Consistent key usage bits: DIGITAL_SIGNATURE
        'szOID_PKIX_KP_CLIENT_AUTH' : "1.3.6.1.5.5.7.3.2",

        # Consistent key usage bits: DIGITAL_SIGNATURE
        'szOID_PKIX_KP_CODE_SIGNING' : "1.3.6.1.5.5.7.3.3",

        # Consistent key usage bits: DIGITAL_SIGNATURE, NON_REPUDIATION and/or
        # (KEY_ENCIPHERMENT or KEY_AGREEMENT)
        'szOID_PKIX_KP_EMAIL_PROTECTION' : "1.3.6.1.5.5.7.3.4",

        # Consistent key usage bits: DIGITAL_SIGNATURE and/or
        # (KEY_ENCIPHERMENT or KEY_AGREEMENT)
        'szOID_PKIX_KP_IPSEC_END_SYSTEM' : "1.3.6.1.5.5.7.3.5",

        # Consistent key usage bits: DIGITAL_SIGNATURE and/or
        # (KEY_ENCIPHERMENT or KEY_AGREEMENT)
        'szOID_PKIX_KP_IPSEC_TUNNEL' : "1.3.6.1.5.5.7.3.6",

        # Consistent key usage bits: DIGITAL_SIGNATURE and/or
        # (KEY_ENCIPHERMENT or KEY_AGREEMENT)
        'szOID_PKIX_KP_IPSEC_USER' : "1.3.6.1.5.5.7.3.7",

        # Consistent key usage bits: DIGITAL_SIGNATURE or NON_REPUDIATION
        'szOID_PKIX_KP_TIMESTAMP_SIGNING' : "1.3.6.1.5.5.7.3.8",

        # OCSP response signer
        'szOID_PKIX_KP_OCSP_SIGNING' : "1.3.6.1.5.5.7.3.9",

        # Following extension is present to indicate no revocation checking
        # for the OCSP signer certificate
        'szOID_PKIX_OCSP_NOCHECK' : "1.3.6.1.5.5.7.48.1.5",

        # OCSP Nonce
        'szOID_PKIX_OCSP_NONCE' : "1.3.6.1.5.5.7.48.1.2",

        # IKE (Internet Key Exchange) Intermediate KP for an IPsec end entity.
        # Defined in draft-ietf-ipsec-pki-req-04.txt, December 14, 1999.
        'szOID_IPSEC_KP_IKE_INTERMEDIATE' : "1.3.6.1.5.5.8.2.2",


        # iso (1) org (3) dod (6) internet (1) security (5) kerberosv5 (2) pkinit (3) 5
        'szOID_PKINIT_KP_KDC' : "1.3.6.1.5.2.3.5",

        #+-------------------------------------------------------------------------
        #  Microsoft Enhanced Key Usage (Purpose) Object Identifiers
        #+-------------------------------------------------------------------------

        #  Signer of CTLs
        'szOID_KP_CTL_USAGE_SIGNING' : "1.3.6.1.4.1.311.10.3.1",

        #  Signer of TimeStamps
        'szOID_KP_TIME_STAMP_SIGNING' : "1.3.6.1.4.1.311.10.3.2",

        #ifndef szOID_SERVER_GATED_CRYPTO
        'szOID_SERVER_GATED_CRYPTO' : "1.3.6.1.4.1.311.10.3.3",
        #endif

        #ifndef szOID_SGC_NETSCAPE
        'szOID_SGC_NETSCAPE' : "2.16.840.1.113730.4.1",
        #endif

        'szOID_KP_EFS' : "1.3.6.1.4.1.311.10.3.4",
        'szOID_EFS_RECOVERY' : "1.3.6.1.4.1.311.10.3.4.1",

        # Can use Windows Hardware Compatible (WHQL)
        'szOID_WHQL_CRYPTO' : "1.3.6.1.4.1.311.10.3.5",

        # Signed by the NT5 build lab
        'szOID_NT5_CRYPTO' : "1.3.6.1.4.1.311.10.3.6",

        # Signed by and OEM of WHQL
        'szOID_OEM_WHQL_CRYPTO' : "1.3.6.1.4.1.311.10.3.7",

        # Signed by the Embedded NT
        'szOID_EMBEDDED_NT_CRYPTO' : "1.3.6.1.4.1.311.10.3.8",

        # Signer of a CTL containing trusted roots
        'szOID_ROOT_LIST_SIGNER' : "1.3.6.1.4.1.311.10.3.9",

        # Can sign cross-cert and subordinate CA requests with qualified
        # subordination (name constraints, policy mapping, etc.)
        'szOID_KP_QUALIFIED_SUBORDINATION' : "1.3.6.1.4.1.311.10.3.10",

        # Can be used to encrypt/recover escrowed keys
        'szOID_KP_KEY_RECOVERY' : "1.3.6.1.4.1.311.10.3.11",

        # Signer of documents
        'szOID_KP_DOCUMENT_SIGNING' : "1.3.6.1.4.1.311.10.3.12",


        # The default WinVerifyTrust Authenticode policy is to treat all time stamped
        # signatures as being valid forever. This OID limits the valid lifetime of the
        # signature to the lifetime of the certificate. This allows timestamped
        # signatures to expire. Normally this OID will be used in conjunction with
        # szOID_PKIX_KP_CODE_SIGNING to indicate new time stamp semantics should be
        # used. Support for this OID was added in WXP.
        'szOID_KP_LIFETIME_SIGNING' : "1.3.6.1.4.1.311.10.3.13",

        'szOID_KP_MOBILE_DEVICE_SOFTWARE' : "1.3.6.1.4.1.311.10.3.14",

        'szOID_KP_SMART_DISPLAY' : "1.3.6.1.4.1.311.10.3.15",

        'szOID_KP_CSP_SIGNATURE' : "1.3.6.1.4.1.311.10.3.16",

        #ifndef szOID_DRM
        'szOID_DRM' : "1.3.6.1.4.1.311.10.5.1",
        #endif


        # Microsoft DRM EKU
        #ifndef szOID_DRM_INDIVIDUALIZATION
        'szOID_DRM_INDIVIDUALIZATION' : "1.3.6.1.4.1.311.10.5.2",
        #endif


        #ifndef szOID_LICENSES
        'szOID_LICENSES' : "1.3.6.1.4.1.311.10.6.1",
        #endif

        #ifndef szOID_LICENSE_SERVER
        'szOID_LICENSE_SERVER' : "1.3.6.1.4.1.311.10.6.2",
        #endif

        #ifndef szOID_KP_SMARTCARD_LOGON
        'szOID_KP_SMARTCARD_LOGON' : "1.3.6.1.4.1.311.20.2.2",
        #endif


        'szOID_KP_KERNEL_MODE_CODE_SIGNING' : "1.3.6.1.4.1.311.61.1.1",

        'szOID_KP_KERNEL_MODE_TRUSTED_BOOT_SIGNING' : "1.3.6.1.4.1.311.61.4.1",

        # Signer of CRL
        'szOID_REVOKED_LIST_SIGNER' : "1.3.6.1.4.1.311.10.3.19",

        # Signer of Kits-built code
        'szOID_WINDOWS_KITS_SIGNER' : "1.3.6.1.4.1.311.10.3.20",

        # Signer of Windows RT code
        'szOID_WINDOWS_RT_SIGNER' : "1.3.6.1.4.1.311.10.3.21",

        # Signer of Protected Process Light code
        'szOID_PROTECTED_PROCESS_LIGHT_SIGNER' : "1.3.6.1.4.1.311.10.3.22",

        # Signer of Windows TCB code
        'szOID_WINDOWS_TCB_SIGNER' : "1.3.6.1.4.1.311.10.3.23",

        # Signer of Protected Process code
        'szOID_PROTECTED_PROCESS_SIGNER' : "1.3.6.1.4.1.311.10.3.24",

        # Signer of third-party components that are Windows in box
        'szOID_WINDOWS_THIRD_PARTY_COMPONENT_SIGNER' : "1.3.6.1.4.1.311.10.3.25",

        # Signed by the Windows Software Portal
        'szOID_WINDOWS_SOFTWARE_EXTENSION_SIGNER' : "1.3.6.1.4.1.311.10.3.26",

        # CTL containing disallowed entries
        'szOID_DISALLOWED_LIST' : "1.3.6.1.4.1.311.10.3.30",

        # HAL Extensions
        'szOID_KP_KERNEL_MODE_HAL_EXTENSION_SIGNING' : "1.3.6.1.4.1.311.61.5.1",

        # Signer of Windows Store applications
        'szOID_WINDOWS_STORE_SIGNER' : "1.3.6.1.4.1.311.76.3.1",

        # Signer of dynamic code generators
        'szOID_DYNAMIC_CODE_GEN_SIGNER' : "1.3.6.1.4.1.311.76.5.1",

        # Signer of Microsoft code
        'szOID_MICROSOFT_PUBLISHER_SIGNER' : "1.3.6.1.4.1.311.76.8.1",

        #+-------------------------------------------------------------------------
        #  Microsoft Attribute Object Identifiers
        #+-------------------------------------------------------------------------
        'szOID_YESNO_TRUST_ATTR' : "1.3.6.1.4.1.311.10.4.1",

        #+-------------------------------------------------------------------------
        #  Qualifiers that may be part of the szOID_CERT_POLICIES and
        #  szOID_CERT_POLICIES95 extensions
        #+-------------------------------------------------------------------------
        'szOID_PKIX_POLICY_QUALIFIER_CPS' : "1.3.6.1.5.5.7.2.1",
        'szOID_PKIX_POLICY_QUALIFIER_USERNOTICE' : "1.3.6.1.5.5.7.2.2",

        'szOID_ROOT_PROGRAM_FLAGS' : "1.3.6.1.4.1.311.60.1.1",

        # OID for old qualifer
        'szOID_CERT_POLICIES_95_QUALIFIER1' : "2.16.840.1.113733.1.7.1.1",

        #+=========================================================================
        #  TPM Object Identifiers
        #-=========================================================================

        # Subject Alt Name Directory Name RDNs
        'szOID_RDN_TPM_MANUFACTURER' : "2.23.133.2.1",
        'szOID_RDN_TPM_MODEL' : "2.23.133.2.2",
        'szOID_RDN_TPM_VERSION' : "2.23.133.2.3",

        # TPM Manufacturer ASCII Hex Strings
        #  AMD                     "AMD"   0x41 0x4D 0x44 0x00
        #  Atmel                   "ATML"  0x41 0x54 0x4D 0x4C
        #  Broadcom                "BRCM"  0x42 0x52 0x43 0x4D
        #  IBM                     "IBM"   0x49 0x42 0x4d 0x00
        #  Infineon                "IFX"   0x49 0x46 0x58 0x00
        #  Intel                   "INTC"  0x49 0x4E 0x54 0x43
        #  Lenovo                  "LEN"   0x4C 0x45 0x4E 0x00
        #  National Semiconductor  "NSM "  0x4E 0x53 0x4D 0x20
        #  Qualcomm                "QCOM"  0x51 0x43 0x4F 0x4D
        #  SMSC                    "SMSC"  0x53 0x4D 0x53 0x43
        #  ST Microelectronics     "STM "  0x53 0x54 0x4D 0x20
        #  Samsung                 "SMSN"  0x53 0x4D 0x53 0x4E
        #  Sinosun                 "SNS"   0x53 0x4E 0x53 0x00
        #  Texas Instruments       "TXN"   0x54 0x58 0x4E 0x00
        #  Winbond                 "WEC"   0x57 0x45 0x43 0x00
        #
        # Obtained from: http:#www.trustedcomputinggroup.org/files/static_page_files/B4D74EEA-1A4B-B294-D022691CD8A6FD41/Vendor_ID_Registry_0.5_clean.pdf


        # pkcs10 attributes
        'szOID_ENROLL_EK_INFO' : "1.3.6.1.4.1.311.21.23",
        'szOID_ENROLL_ATTESTATION_STATEMENT' : "1.3.6.1.4.1.311.21.24",
        'szOID_ENROLL_KSP_NAME' : "1.3.6.1.4.1.311.21.25", # pkcs10 and cmc full response
                                                                            # ksp_name encoded as a unicode
                                                                            # string. See CERT_RDN_UNICODE_STRING.
                                                                            # on CERT_NAME_VALUE structure. It
                                                                            # must be null terminated.

        # CMC Full Response Tagged Attributes
        'szOID_ENROLL_EKPUB_CHALLENGE' : "1.3.6.1.4.1.311.21.26",
        'szOID_ENROLL_CAXCHGCERT_HASH' : "1.3.6.1.4.1.311.21.27",
        'szOID_ENROLL_ATTESTATION_CHALLENGE' : "1.3.6.1.4.1.311.21.28",
        'szOID_ENROLL_ENCRYPTION_ALGORITHM' : "1.3.6.1.4.1.311.21.29", # algorithm oid

        # TPM certificate EKU OIDs
        'szOID_KP_TPM_EK_CERTIFICATE' : "2.23.133.8.1",
        'szOID_KP_TPM_PLATFORM_CERTIFICATE' : "2.23.133.8.2",
        'szOID_KP_TPM_AIK_CERTIFICATE' : "2.23.133.8.3",

        # EK validation Issuance Policy OIDs
        'szOID_ENROLL_EKVERIFYKEY' : "1.3.6.1.4.1.311.21.30",
        'szOID_ENROLL_EKVERIFYCERT' : "1.3.6.1.4.1.311.21.31",
        'szOID_ENROLL_EKVERIFYCREDS' : "1.3.6.1.4.1.311.21.32",

        # Signed decimal string encoded as a Printable String
        'szOID_ENROLL_SCEP_ERROR' : "1.3.6.1.4.1.311.21.33",

        # Subject Directory Attributes
        'szOID_ATTR_SUPPORTED_ALGORITHMS' : "2.5.4.52",
        'szOID_ATTR_TPM_SPECIFICATION' : "2.23.133.2.16",
        'szOID_ATTR_TPM_SECURITY_ASSERTIONS' : "2.23.133.2.18"
    }
MsgParam = {
        #+-------------------------------------------------------------------------
        #  Get parameter types and their corresponding data structure definitions.
        #--------------------------------------------------------------------------
        'CMSG_TYPE_PARAM' : 1,
        'CMSG_CONTENT_PARAM' : 2,
        'CMSG_BARE_CONTENT_PARAM' : 3,
        'CMSG_INNER_CONTENT_TYPE_PARAM' : 4,
        'CMSG_SIGNER_COUNT_PARAM' : 5,
        'CMSG_SIGNER_INFO_PARAM' : 6,
        'CMSG_SIGNER_CERT_INFO_PARAM' : 7,
        'CMSG_SIGNER_HASH_ALGORITHM_PARAM' : 8,
        'CMSG_SIGNER_AUTH_ATTR_PARAM' : 9,
        'CMSG_SIGNER_UNAUTH_ATTR_PARAM' : 10,
        'CMSG_CERT_COUNT_PARAM' : 11,
        'CMSG_CERT_PARAM' : 12,
        'CMSG_CRL_COUNT_PARAM' : 13,
        'CMSG_CRL_PARAM' : 14,
        'CMSG_ENVELOPE_ALGORITHM_PARAM' : 15,
        'CMSG_RECIPIENT_COUNT_PARAM' : 17,
        'CMSG_RECIPIENT_INDEX_PARAM' : 18,
        'CMSG_RECIPIENT_INFO_PARAM' : 19,
        'CMSG_HASH_ALGORITHM_PARAM' : 20,
        'CMSG_HASH_DATA_PARAM' : 21,
        'CMSG_COMPUTED_HASH_PARAM' : 22,
        'CMSG_ENCRYPT_PARAM' : 26,
        'CMSG_ENCRYPTED_DIGEST' : 27,
        'CMSG_ENCODED_SIGNER' : 28,
        'CMSG_ENCODED_MESSAGE' : 29,
        'CMSG_VERSION_PARAM' : 30,
        'CMSG_ATTR_CERT_COUNT_PARAM' : 31,
        'CMSG_ATTR_CERT_PARAM' : 32,
        'CMSG_CMS_RECIPIENT_COUNT_PARAM' : 33,
        'CMSG_CMS_RECIPIENT_INDEX_PARAM' : 34,
        'CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM' : 35,
        'CMSG_CMS_RECIPIENT_INFO_PARAM' : 36,
        'CMSG_UNPROTECTED_ATTR_PARAM' : 37,
        'CMSG_SIGNER_CERT_ID_PARAM' : 38,
        'CMSG_CMS_SIGNER_INFO_PARAM' : 39
    }
ObjectType = {
        'CERT_QUERY_OBJECT_FILE' : 0x00000001,
        'CERT_QUERY_OBJECT_BLOB' : 0x00000002
    }
Encoding = {
        'PKCS_7_ASN_ENCODING' : 0x10000,
        'X509_ASN_ENCODING' : 1
    }
ENCODING = Encoding['X509_ASN_ENCODING'] | Encoding['PKCS_7_ASN_ENCODING']
ContentType = {
        # encoded single certificate
        'CERT_QUERY_CONTENT_CERT' : 1,
        # encoded single CTL
        'CERT_QUERY_CONTENT_CTL' : 2,
        # encoded single CRL
        'CERT_QUERY_CONTENT_CRL' : 3,
        # serialized store
        'CERT_QUERY_CONTENT_SERIALIZED_STORE' : 4,
        # serialized single certificate
        'CERT_QUERY_CONTENT_SERIALIZED_CERT' : 5,
        # serialized single CTL
        'CERT_QUERY_CONTENT_SERIALIZED_CTL' : 6,
        # serialized single CRL
        'CERT_QUERY_CONTENT_SERIALIZED_CRL' : 7,
        # a PKCS#7 signed message
        'CERT_QUERY_CONTENT_PKCS7_SIGNED' : 8,
        # a PKCS#7 message, such as enveloped message.  But it is not a signed message,
        'CERT_QUERY_CONTENT_PKCS7_UNSIGNED' : 9,
        # a PKCS7 signed message embedded in a file
        'CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED' : 10,
        # an encoded PKCS#10
        'CERT_QUERY_CONTENT_PKCS10' : 11,
        # an encoded PFX BLOB
        'CERT_QUERY_CONTENT_PFX' : 12,
        # an encoded CertificatePair (contains forward and/or reverse cross certs)
        'CERT_QUERY_CONTENT_CERT_PAIR' : 13,
        # an encoded PFX BLOB, which was loaded to phCertStore
        'CERT_QUERY_CONTENT_PFX_AND_LOAD' : 14
    }
ExpectedConentTypeFlags = {
#encoded single certificate
        'CERT_QUERY_CONTENT_FLAG_CERT' : 1 << ContentType['CERT_QUERY_CONTENT_CERT'],
#encoded single CTL
        'CERT_QUERY_CONTENT_FLAG_CTL' : 1 << ContentType['CERT_QUERY_CONTENT_CTL'],
#encoded single CRL
        'CERT_QUERY_CONTENT_FLAG_CRL' : 1 << ContentType['CERT_QUERY_CONTENT_CRL'],
#serialized store
        'CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE' : 1 << ContentType['CERT_QUERY_CONTENT_SERIALIZED_STORE'],
#serialized single certificate
        'CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT' : 1 << ContentType['CERT_QUERY_CONTENT_SERIALIZED_CERT'],
#serialized single CTL
        'CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL' : 1 << ContentType['CERT_QUERY_CONTENT_SERIALIZED_CTL'],
#serialized single CRL
        'CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL' : 1 << ContentType['CERT_QUERY_CONTENT_SERIALIZED_CRL'],
#an encoded PKCS#7 signed message
        'CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED' : 1 << ContentType['CERT_QUERY_CONTENT_PKCS7_SIGNED'],
#an encoded PKCS#7 message.  But it is not a signed message
        'CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED' : 1 << ContentType['CERT_QUERY_CONTENT_PKCS7_UNSIGNED'],
#the content includes an embedded PKCS7 signed message
        'CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED' : 1 << ContentType['CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED'],
#an encoded PKCS#10
        'CERT_QUERY_CONTENT_FLAG_PKCS10' : 1 << ContentType['CERT_QUERY_CONTENT_PKCS10'],
#an encoded PFX BLOB
        'CERT_QUERY_CONTENT_FLAG_PFX' : 1 << ContentType['CERT_QUERY_CONTENT_PFX'],
#an encoded CertificatePair (contains forward and/or reverse cross certs)
        'CERT_QUERY_CONTENT_FLAG_CERT_PAIR' : 1 << ContentType['CERT_QUERY_CONTENT_CERT_PAIR'],
#an encoded PFX BLOB, and we do want to load it (not included in
#CERT_QUERY_CONTENT_FLAG_ALL)
        'CERT_QUERY_CONTENT_FLAG_PFX_AND_LOAD' : 1 << ContentType['CERT_QUERY_CONTENT_PFX_AND_LOAD'],
#content can be any type
        'CERT_QUERY_CONTENT_FLAG_ALL' : 
              ( 1 << ContentType['CERT_QUERY_CONTENT_CERT'] |                  \
                1 << ContentType['CERT_QUERY_CONTENT_CTL']  |                  \
                1 << ContentType['CERT_QUERY_CONTENT_CRL']  |                  \
                1 << ContentType['CERT_QUERY_CONTENT_SERIALIZED_STORE'] |      \
                1 << ContentType['CERT_QUERY_CONTENT_SERIALIZED_CERT']  |      \
                1 << ContentType['CERT_QUERY_CONTENT_SERIALIZED_CTL']   |      \
                1 << ContentType['CERT_QUERY_CONTENT_SERIALIZED_CRL']   |      \
                1 << ContentType['CERT_QUERY_CONTENT_PKCS7_SIGNED']     |      \
                1 << ContentType['CERT_QUERY_CONTENT_PKCS7_UNSIGNED']   |      \
                1 << ContentType['CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED'] |    \
                1 << ContentType['CERT_QUERY_CONTENT_PKCS10']             |    \
                1 << ContentType['CERT_QUERY_CONTENT_PFX']                |    \
                1 << ContentType['CERT_QUERY_CONTENT_CERT_PAIR'] ),

#content types allowed for Issuer certificates
        'CERT_QUERY_CONTENT_FLAG_ALL_ISSUER_CERT' :                            
              ( 1 << ContentType['CERT_QUERY_CONTENT_CERT']             |      \
                1 << ContentType['CERT_QUERY_CONTENT_SERIALIZED_STORE'] |      \
                1 << ContentType['CERT_QUERY_CONTENT_SERIALIZED_CERT']  |      \
                1 << ContentType['CERT_QUERY_CONTENT_PKCS7_SIGNED']     |      \
                1 << ContentType['CERT_QUERY_CONTENT_PKCS7_UNSIGNED']   )
    }
FormatType = {
        #the content is in binary format
        'CERT_QUERY_FORMAT_BINARY' : 1,
        #the content is base64 encoded
        'CERT_QUERY_FORMAT_BASE64_ENCODED' : 2,
        #the content is ascii hex encoded with "{ASN}" prefix
        'CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED' : 3
    }
ExpectedFormatTypeFlags = {
        #the content is in binary format
        'CERT_QUERY_FORMAT_FLAG_BINARY' : 1 << FormatType['CERT_QUERY_FORMAT_BINARY'],

        #the content is base64 encoded
        'CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED' : 1 << FormatType['CERT_QUERY_FORMAT_BASE64_ENCODED'],

        #the content is ascii hex encoded with "{ASN}" prefix
        'CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED' : 1 << FormatType['CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED'],

        #the content can be of any format
        'CERT_QUERY_FORMAT_FLAG_ALL' :
                  ( 1 << FormatType['CERT_QUERY_FORMAT_BINARY']   |       \
                    1 << FormatType['CERT_QUERY_FORMAT_BASE64_ENCODED']   |
                    1 << FormatType['CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED']   
                    )
    }   
WinTrustDataUIChoice = {
        'All' : 1,
        'None' : 2,
        'NoBad' : 3,
        'NoGood' : 4
    }
WinTrustDataRevocationChecks = {
        'None' : 0x00000000,
        'WholeChain': 0x00000001
    }
WinTrustDataChoice = {
        'File' : 1,
        'Catalog' : 2,
        'Blob' : 3,
        'Signer' : 4,
        'Certificate' : 5
    }
WinTrustDataStateAction =  {
        'Ignore' : 0x00000000,
        'Verify' : 0x00000001,
        'Close' : 0x00000002,
        'AutoCache' : 0x00000003,
        'AutoCacheFlush' : 0x00000004
    }
WinTrustDataProvFlags = {
        'UseIe4TrustFlag' : 0x00000001,
        'NoIe4ChainFlag' : 0x00000002,
        'NoPolicyUsageFlag' : 0x00000004,
        'RevocationCheckNone' : 0x00000010,
        'RevocationCheckEndCert' : 0x00000020,
        'RevocationCheckChain' : 0x00000040,
        'RevocationCheckChainExcludeRoot' : 0x00000080,
        'SaferFlag' : 0x00000100,        # Used by software restriction policies. Should not be used.
        'HashOnlyFlag' : 0x00000200,
        'UseDefaultOsverCheck' : 0x00000400,
        'LifetimeSigningFlag' : 0x00000800,
        'CacheOnlyUrlRetrieval' : 0x00001000,      # affects CRL retrieval and AIA retrieval
        'DisableMD2andMD4' : 0x00002000      # Win7 SP1+: Disallows use of MD2 or MD4 in the chain except for the root 
    }
WinTrustDataUIContext= {
        'Execute' : 0,
        'Install' : 1
    }
WinVerifyTrustResult = {
         'Success' : 0,
         'ProviderUnknown' : 0x800b0001,            #  Trust provider is not recognized on this system
         'ActionUnknown' : 0x800b0002,              #  Trust provider does not support the specified action
         'SubjectFormUnknown' : 0x800b0003,         #  Trust provider does not support the form specified for the subject
         'SubjectNotTrusted' : 0x800b0004,          #  Subject failed the specified verification action
         'FileNotSigned' : 0x800B0100,              #  TRUST_E_NOSIGNATURE - File was not signed
         'SubjectExplicitlyDistrusted' : 0x800B0111,#  Signer's certificate is in the Untrusted Publishers store
         'SignatureOrFileCorrupt' : 0x80096010,     #  TRUST_E_BAD_DIGEST - file was probably corrupt
         'SubjectCertExpired' : 0x800B0101,         #  CERT_E_EXPIRED - Signer's certificate was expired
         'SubjectCertificateRevoked' : 0x800B010C,  #  CERT_E_REVOKED Subject's certificate was revoked
         'UntrustedRoot' : 0x800B0109               #  CERT_E_UNTRUSTEDROOT - A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider.
     }
SpcLinkChoice = {
        'SPC_URL_LINK_CHOICE' : 1,
        'SPC_MONIKER_LINK_CHOICE' : 2,
        'SPC_FILE_LINK_CHOICE' : 3
    }
CertNameType = {
        #+-------------------------------------------------------------------------
        #  Certificate name types
        #--------------------------------------------------------------------------
        'CERT_NAME_EMAIL_TYPE' : 1,
        'CERT_NAME_RDN_TYPE' : 2,
        'CERT_NAME_ATTR_TYPE' : 3,
        'CERT_NAME_SIMPLE_DISPLAY_TYPE' : 4,
        'CERT_NAME_FRIENDLY_DISPLAY_TYPE' : 5,
        'CERT_NAME_DNS_TYPE' : 6,
        'CERT_NAME_URL_TYPE' : 7,
        'CERT_NAME_UPN_TYPE' : 8,
    }
CertNameFlags = {
        #+-------------------------------------------------------------------------
        #  Certificate name flags
        #--------------------------------------------------------------------------
        'CERT_NAME_ISSUER_FLAG' : 0x1,
        'CERT_NAME_DISABLE_IE4_UTF8_FLAG' : 0x00010000,


        # Following is only applicable to CERT_NAME_DNS_TYPE. When set returns
        # all names not just the first one. Returns a multi-string. Each string
        # will be null terminated. The last string will be double null terminated. 
        'CERT_NAME_SEARCH_ALL_NAMES_FLAG' : 0x2,
    }
CertNameStr = {
        # certenrolld_begin -- CERT_NAME_STR_*_FLAG
        #+-------------------------------------------------------------------------
        #  Certificate name string types
        #--------------------------------------------------------------------------
        'CERT_SIMPLE_NAME_STR' : 1,
        'CERT_OID_NAME_STR' : 2,
        'CERT_X500_NAME_STR' : 3,
        'CERT_XML_NAME_STR' : 4,
    }
CertNameStrFlags = {

        #+-------------------------------------------------------------------------
        #  Certificate name string type flags OR'ed with the above types
        #--------------------------------------------------------------------------
        'CERT_NAME_STR_SEMICOLON_FLAG' : 0x40000000,
        'CERT_NAME_STR_NO_PLUS_FLAG' : 0x20000000,
        'CERT_NAME_STR_NO_QUOTING_FLAG' : 0x10000000,
        'CERT_NAME_STR_CRLF_FLAG' : 0x08000000,
        'CERT_NAME_STR_COMMA_FLAG' : 0x04000000,
        'CERT_NAME_STR_REVERSE_FLAG' : 0x02000000,
        'CERT_NAME_STR_FORWARD_FLAG' : 0x01000000,

        'CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG' : 0x00010000,
        'CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG' : 0x00020000,
        'CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG' : 0x00040000,
        'CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG' : 0x00080000,
        'CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG' : 0x00100000,
        'CERT_NAME_STR_ENABLE_PUNYCODE_FLAG' : 0x00200000,
        # certenrolld_end
    }

CryptAcquireContextFlags = {
        'CRYPT_VERIFYCONTEXT' : 0xF0000000,
        'CRYPT_NEWKEYSET' : 0x00000008,
        'CRYPT_DELETEKEYSET' : 0x00000010,
        'CRYPT_MACHINE_KEYSET' : 0x00000020,
        'CRYPT_SILENT' : 0x00000040,
    }
CryptProv = {
        'PROV_RSA_FULL' : 1,
        'PROV_RSA_SIG' : 2,
        'PROV_DSS' : 3,
        'PROV_FORTEZZA' : 4,
        'PROV_MS_EXCHANGE' : 5,
        'PROV_SSL' : 6,
        'PROV_RSA_SCHANNEL' : 12,
        'PROV_DSS_DH' : 13,
        'PROV_EC_ECDSA_SIG' : 14,
        'PROV_EC_ECNRA_SIG' : 15,
        'PROV_EC_ECDSA_FULL' : 16,
        'PROV_EC_ECNRA_FULL' : 17,
        'PROV_DH_SCHANNEL' : 18,
        'PROV_SPYRUS_LYNKS' : 20,
        'PROV_RNG' : 21,
        'PROV_INTEL_SEC' : 22,
        'PROV_REPLACE_OWF' : 23,
        'PROV_RSA_AES' : 24,
    }