from WinCrypto.crypt_flags import *
from WinCrypto.crypt32 import *
from ctypes import *
from struct import *
import time
import binascii

class Signature:
    def __init__( self, filename ):
        self.filename = filename
        self.dwEncoding, self.dwContentType, self.dwFormatType = DWORD(0),DWORD(0),DWORD(0)
        self.hStore, self.hMsg, self.ppvContext = PVOID(0), PVOID(0), NULL
        dwFlags = DWORD(0)
        
        if not CryptQueryObject( ObjectType['CERT_QUERY_OBJECT_FILE'], LPWSTR(filename), 
                          ExpectedConentTypeFlags['CERT_QUERY_CONTENT_FLAG_ALL'],
                          ExpectedFormatTypeFlags['CERT_QUERY_FORMAT_FLAG_BINARY'],
                          dwFlags,
                          self.dwEncoding, self.dwContentType, self.dwFormatType, 
                          self.hStore, self.hMsg, self.ppvContext ):
            raise WindowsError( "CryptQueryObject failed %x" % GetLastError() )
            
        dwSignerInfo = DWORD(0)
        if not CryptMsgGetParam( self.hMsg, MsgParam['CMSG_SIGNER_INFO_PARAM'], 0,
                                 None, dwSignerInfo ):
            raise WindowsError( "CryptMsgGetParam failed %x" % GetLastError() )
            
        self._SignerInfoBuffer = malloc(dwSignerInfo.value)
        if not CryptMsgGetParam( self.hMsg, MsgParam['CMSG_SIGNER_INFO_PARAM'], 0,
                                 self._SignerInfoBuffer, dwSignerInfo ):
            raise WindowsError( "CryptMsgGetParam failed %x" % GetLastError() )
        
        self.SignerInfo = cast(self._SignerInfoBuffer, POINTER(CMSG_SIGNER_INFO)).contents
        self.ProgramName, self.PublisherLink, self.MoreInfoLink = GetProgAndPublisherInfo( self.SignerInfo )
        self.DateOfTimeStamp = GetDateOfTimeStamp( self.SignerInfo )
        
        GetStatementType( self.SignerInfo )
        
        self.CertInfo = CERT_INFO()
        self.CertInfo.Issuer = self.SignerInfo.Issuer
        self.CertInfo.SerialNumber = self.SignerInfo.SerialNumber
            
        PCERT_CONTEXT = CertFindCertificateInStore( self.hStore, 
                                    ENCODING,
                                    0,
                                    CertCompare['CERT_FIND_SUBJECT_CERT'],
                                    byref(self.CertInfo),
                                    None )
        if PCERT_CONTEXT:
            self.CertContext = cast(PCERT_CONTEXT, POINTER(CERT_CONTEXT)).contents
            self.Certificate = Certificate( self.CertContext )
        
        
    def __str__( self ):
        _s = ["Signer Information:"]
        _s.append( "Name:            %s" %   self.ProgramName )
        _s.append( "E-mail:          %s" % ( self.PublisherLink if self.PublisherLink else "Not available" ))
        _s.append( "Info:            %s" % ( self.MoreInfoLink if self.MoreInfoLink else "Not available" ))
        _s.append( "Signing Time:    %s" % ( self.DateOfTimeStamp if self.DateOfTimeStamp else "Not available" ))
        _s.append( "%s" % ( self.Certificate ) )
        _s.append( "%s" % ( self.SignerInfo ) )
        return "\n".join(_s)
               
def GetProgAndPublisherInfo( pSignerInfo ):
    lpszProgramName, lpszPublisherLink, lpszMoreInfoLink = None, None, None
    dwData = DWORD(0)
    for attr in pSignerInfo.AuthAttrs.attributes():
        if not str(attr.pszObjId) == OID['SPC_SP_OPUS_INFO_OBJID']:
            continue
        if not CryptDecodeObject(   ENCODING,
                                    OID['SPC_SP_OPUS_INFO_OBJID'],
                                    attr.attributes()[0].pbData,
                                    attr.attributes()[0].cbData,
                                    0, None, dwData ):
            raise WindowsError( "CryptDecodeObject failed %x" % GetLastError() )
            break
        pBuf = malloc(dwData.value)
        if not CryptDecodeObject(   ENCODING,
                                    OID['SPC_SP_OPUS_INFO_OBJID'],
                                    attr.attributes()[0].pbData,
                                    attr.attributes()[0].cbData,
                                    0, pBuf, dwData ):
            raise WindowsError( "CryptDecodeObject failed %x" % GetLastError() )
            break
        OpusInfo = cast(pBuf, POINTER(SPC_SP_OPUS_INFO)).contents
        if OpusInfo.pwszProgramName:
            lpszProgramName = "%s" % OpusInfo.pwszProgramName
        if OpusInfo.pPublisherInfo:
            PublisherInfo = OpusInfo.pPublisherInfo.contents
            if PublisherInfo.dwLinkChoice  == SpcLinkChoice['SPC_URL_LINK_CHOICE']:
                lpszPublisherLink = "%s" % PublisherInfo.pwszUrl
            elif PublisherInfo.dwLinkChoice == SpcLinkChoice['SPC_FILE_LINK_CHOICE']:
                lpszPublisherLink = "%s" % PublisherInfo.pwszFile
        if OpusInfo.pMoreInfo:
            MoreInfo = OpusInfo.pMoreInfo.contents
            if MoreInfo.dwLinkChoice  == SpcLinkChoice['SPC_URL_LINK_CHOICE']:
                lpszMoreInfoLink = "%s" % MoreInfo.pwszUrl
            elif MoreInfo.dwLinkChoice == SpcLinkChoice['SPC_FILE_LINK_CHOICE']:
                lpszMoreInfoLink = "%s" % MoreInfo.pwszFile    
        free(pBuf)
        break
    return lpszProgramName, lpszPublisherLink, lpszMoreInfoLink
       
def GetStatementType( pSignerInfo ):
    dwData = DWORD(0)
    for attr in pSignerInfo.AuthAttrs.attributes():
        if not str(attr.pszObjId) == OID['SPC_STATEMENT_TYPE_OBJID']:
            continue
        if not CryptDecodeObject(   ENCODING,
                                    OID['SPC_STATEMENT_TYPE_OBJID'],
                                    attr.attributes()[0].pbData,
                                    attr.attributes()[0].cbData,
                                    0, None, dwData ):
            raise WindowsError( "CryptDecodeObject failed %x" % GetLastError() )
            break
        pBuf = malloc(dwData.value)
        if not CryptDecodeObject(   ENCODING,
                                    OID['SPC_STATEMENT_TYPE_OBJID'],
                                    attr.attributes()[0].pbData,
                                    attr.attributes()[0].cbData,
                                    0, pBuf, dwData ):
            raise WindowsError( "CryptDecodeObject failed %x" % GetLastError() )
            break
        StatementType = cast(pBuf, POINTER(SPC_STATEMENT_TYPE)).contents
        free(pBuf)
        break
    return 

def GetDateOfTimeStamp( pSignerInfo ):
    # time.struct_time
    dwData = DWORD(0)
    for attr in pSignerInfo.AuthAttrs.attributes():
        if not str(attr.pszObjId) == OID['szOID_RSA_signingTime']:
            continue
        lft, ft = FILETIME(), FILETIME()
        dwData = DWORD( sizeof(ft) )
        if not CryptDecodeObject(   ENCODING,
                                    OID['szOID_RSA_signingTime'],
                                    attr.attributes()[0].pbData,
                                    attr.attributes()[0].cbData,
                                    0, cast(byref(ft), PBYTE), dwData ):
            raise WindowsError( "CryptDecodeObject failed %x" % GetLastError() )
        
        windll.kernel32.FileTimeToLocalFileTime.argtypes = [POINTER(FILETIME),POINTER(FILETIME)]
        windll.kernel32.FileTimeToLocalFileTime(byref(ft), byref(lft));
        #Int32x32To64
        ft_dec, = unpack('>Q', pack('>LL', lft.dwLowDateTime, lft.dwHighDateTime))

        try:
            from datetime import datetime
            EPOCH_AS_FILETIME = 116444736000000000;  HUNDREDS_OF_NANOSECONDS = 10000000
            dt = datetime.fromtimestamp((ft_dec - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
            return dt
        except ValueError:
            pass
    return None
    
def CryptQueryFile( szFileName, dwFlags = 0 ):
    dwEncoding, dwContentType, dwFormatType = DWORD(0),DWORD(0),DWORD(0)
    hStore, hMsg, ppvContext = c_void_p(0), c_void_p(0), None
    
    if not CryptQueryObject( ObjectType['CERT_QUERY_OBJECT_FILE'], c_wchar_p(szFileName), 
                      ExpectedConentTypeFlags['CERT_QUERY_CONTENT_FLAG_ALL'],
                      ExpectedFormatTypeFlags['CERT_QUERY_FORMAT_FLAG_BINARY'],
                      dwFlags,
                      dwEncoding, dwContentType, dwFormatType, 
                      hStore, hMsg, ppvContext ):
        raise WindowsError( "CryptQueryObject failed %x" % GetLastError() )
                    
    dwSignerInfo = DWORD(0)
    if not CryptMsgGetParam( hMsg, MsgParam['CMSG_SIGNER_INFO_PARAM'], 0,
                             None, dwSignerInfo ):
        raise WindowsError( "CryptMsgGetParam failed %x" % GetLastError() )
        
    pBuf = malloc(dwSignerInfo.value)
    if not CryptMsgGetParam( hMsg, MsgParam['CMSG_SIGNER_INFO_PARAM'], 0,
                             pBuf, dwSignerInfo ):
        raise WindowsError( "CryptMsgGetParam failed %x" % GetLastError() )
    
    pSignerInfo = cast(pBuf, POINTER(CMSG_SIGNER_INFO)).contents    
    ProgramName, PublisherLink, MoreInfoLink = GetProgAndPublisherInfo( pSignerInfo )
    DateOfTimeStamp = GetDateOfTimeStamp( pSignerInfo )
    free( pBuf )
    return ProgramName, PublisherLink, MoreInfoLink, DateOfTimeStamp
               
        
class Certificate():
    def __init__( self, CertContext, Issuer=False ):
        IssuerFlag = 1 if Issuer else 0
        self.CC = CertContext
        if not Issuer:
            self.Issuer = Certificate( self.CC, True )
        self.EMail = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_RSA_emailAddr'] )
        self.CommonName = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_COMMON_NAME'] )
        self.CountryName = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_COUNTRY_NAME'] )
        self.DomainComponent = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_DOMAIN_COMPONENT'] )
        self.GivenName = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_GIVEN_NAME'] )
        self.Initials = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_INITIALS'] )
        self.Organization = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_ORGANIZATION_NAME'] )
        self.OrgUnit = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_ORGANIZATIONAL_UNIT_NAME'] )
        self.State = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_STATE_OR_PROVINCE_NAME'] )
        self.StreetAddress = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_STREET_ADDRESS'] )
        self.SurName = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_SUR_NAME'] )
        self.Title = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_TITLE'] )
        self.UnstructuredAddress = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_RSA_unstructAddr'] )
        self.UnstructuredName = self.GetNameString( CertNameType['CERT_NAME_ATTR_TYPE'], IssuerFlag, OID['szOID_RSA_unstructName'] )
        self.SimpleName = self.GetNameString( CertNameType['CERT_NAME_SIMPLE_DISPLAY_TYPE'], IssuerFlag, None )
        self.FriendlyName = self.GetNameString( CertNameType['CERT_NAME_FRIENDLY_DISPLAY_TYPE'], IssuerFlag, None )
        self.URL = self.GetNameString( CertNameType['CERT_NAME_URL_TYPE'], IssuerFlag, None )
        
    def __str__( self ):
        r = ["Certificate Information:"]
        for v in vars(self):
            value = vars(self)[v]
            try:
                if type(value) == type(u'') and len(value):
                    r.append("\t%s = %s" % ( v, value.encode('ascii') ) )
            except:
                pass
        return "\n".join(r)
        
    def GetNameStr( self, CertNameStrType ):
        str_size = CertNameToStr( ENCODING,
                            self,
                            CertNameStrType,
                            NULL,
                            0 )
        if str_size:
            StringBuffer = cast(malloc(str_size * sizeof(c_wchar)), c_wchar_p)
            str_size = CertNameToStr( ENCODING,
                                self,
                                CertNameStrType,
                                StringBuffer,
                                str_size )
            r_string = StringBuffer.value
            free( StringBuffer)
            return r_string            
            
        return ""
    def GetNameString( self, Type, Flags, TypePara ):
        r = ""
        str_size = CertGetNameString(   self.CC, 
                                    Type, 
                                    Flags, 
                                    TypePara, 
                                    cast(NULL, LPWSTR), 
                                    0
                                )
        if str_size:
            pBuf = malloc(str_size * sizeof(WCHAR))
            CertGetNameString(  self.CC, 
                                Type, 
                                Flags, 
                                TypePara, 
                                cast(pBuf, LPWSTR),
                                str_size
                            )
            r = cast(pBuf, LPWSTR).value[:]
            free(pBuf)
            return r
        return None
        
if __name__ == '__main__':
    for f in (r"c:\windows\system32\kernel32.dll", r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\40.0.2214.94\pdf.dll",
                r"C:\windows\regedit.exe",
                r"C:\Program Files (x86)\BreakPoint Software\Hex Workshop v6\HWorks32.exe"):
        try:
            sig  = Signature(f)
            print( "File: %s" % sig.filename )
            print( "What: %s" % sig.ProgramName )
            print( "Who: %s" % sig.PublisherLink )
            print( "About: %s" % sig.MoreInfoLink )
            print( "What: %s" % sig.Certificate.FriendlyName )
            print( "From: %s" % sig.Certificate.Organization )
        except:
            print( "No more information about %s" % f )
        print