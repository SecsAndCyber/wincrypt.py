from WinCrypto.WinCrypt import * 
class AESCipher():
    __doc__ = 'AES cipher object'
    
    @staticmethod
    def new( key, *args, **kwargs ):
        return AESCipher( key, *args, **kwargs )
        
    def __init__(self, key, *args, **kwargs ):
        """
            Initialize an AES cipher object

            See also `new()` at the module level.

        """
        if not len(key) in key_size:
            raise ValueError("AES key must be either 16, 24, or 32 bytes long")
        
        self.key = str_to_PBYTE(key)
        self.mode= kwargs.get('mode', MODE_ECB)
        self.IV= kwargs.get('IV', '')
        self.block_size = block_size
        self.hProvider = HCRYPTPROV()
        self.hKey = HCRYPTKEY()
        if len(key) == 16:
            self.KeyBlob = AES128HEADER(BLOBHEADER(PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, CALG_AES_128), 16, self.key)
        if len(key) == 24:
            self.KeyBlob = AES192HEADER(BLOBHEADER(PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, CALG_AES_192), 24, self.key)
        if len(key) == 32:
            self.KeyBlob = AES256HEADER(BLOBHEADER(PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, CALG_AES_256), 32, self.key)
        try:
            assert AcquireContext( self.hProvider, None, MS_ENH_RSA_AES_PROV, CryptProv['PROV_RSA_AES'], CryptAcquireContextFlags['CRYPT_VERIFYCONTEXT'] )
            assert ImportKey( self.hProvider, cast(pointer(self.KeyBlob),PBYTE) , sizeof(self.KeyBlob), None, 0, self.hKey )
            
            if self.mode == MODE_CBC:
                if not len(self.IV) == block_size:
                    raise ValueError("IV must be %d bytes long" % block_size )
                bData = str_to_PBYTE(self.IV)
                assert SetKeyParam( self.hKey, KP_IV, cast(pointer(bData),PBYTE), 0 )
            elif self.mode == MODE_CFB:
                raise NotImplementedError()
            elif self.mode == MODE_CTR:
                raise NotImplementedError()
            elif self.mode == MODE_ECB:
                bData = DWORD(CRYPT_MODE_ECB)
                assert SetKeyParam( self.hKey, KP_MODE, cast(pointer(bData),PBYTE), 0 )
            elif self.mode == MODE_OFB:
                raise NotImplementedError()
            elif self.mode == MODE_OPENPGP:
                raise NotImplementedError()
            elif self.mode == MODE_PGP:
                raise NotImplementedError()
            
        except AssertionError:
            raise Exception( hex(windll.kernel32.GetLastError()) )
     
    def encrypt(self, plaintext):
        """
            Encrypt data with the key and the parameters set at initialization.

            The cipher object is stateful; encryption of a long block
            of data can be broken up in two or more calls to `encrypt()`.
            That is, the statement:

                >>> c.encrypt(a) + c.encrypt(b)

            is always equivalent to:

                 >>> c.encrypt(a+b)

            That also means that you cannot reuse an object for encrypting
            or decrypting other data with the same key.

            This function does not perform any padding.

             - For `MODE_ECB`, `MODE_CBC`, and `MODE_OFB`, *plaintext* length
               (in bytes) must be a multiple of *block_size*.

             - For `MODE_CFB`, *plaintext* length (in bytes) must be a multiple
               of *segment_size*/8.

             - For `MODE_CTR`, *plaintext* can be of any length.

             - For `MODE_OPENPGP`, *plaintext* must be a multiple of *block_size*,
               unless it is the last chunk of the message.

            :Parameters:
              plaintext : byte string
                The piece of data to encrypt.
            :Return:
                the encrypted data, as a byte string. It is as long as
                *plaintext* with one exception: when encrypting the first message
                chunk with `MODE_OPENPGP`, the encypted IV is prepended to the
                returned ciphertext.
        """
        if len(plaintext) % block_size:
            raise ValueError("Input strings must be a multiple of %d in length" % block_size)
        pBuffer = str_to_PBYTE(plaintext)
        dwBuffer= DWORD( len(plaintext) )
        if Encrypt( self.hKey, None, 0, 0, pBuffer, dwBuffer, len(plaintext) ):
            return string_at( pBuffer, dwBuffer.value )
        raise Exception( hex(windll.kernel32.GetLastError()) )
        
    def decrypt(self, ciphertext):
        """
            Decrypt data with the key and the parameters set at initialization.

            The cipher object is stateful; decryption of a long block
            of data can be broken up in two or more calls to `decrypt()`.
            That is, the statement:

                >>> c.decrypt(a) + c.decrypt(b)

            is always equivalent to:

                 >>> c.decrypt(a+b)

            That also means that you cannot reuse an object for encrypting
            or decrypting other data with the same key.

            This function does not perform any padding.

             - For `MODE_ECB`, `MODE_CBC`, and `MODE_OFB`, *ciphertext* length
               (in bytes) must be a multiple of *block_size*.

             >>> c.decrypt(a+b)

            That also means that you cannot reuse an object for encrypting
            or decrypting other data with the same key.

            This function does not perform any padding.

             - For `MODE_ECB`, `MODE_CBC`, and `MODE_OFB`, *ciphertext* length
               (in bytes) must be a multiple of *block_size*.

             - For `MODE_CFB`, *ciphertext* length (in bytes) must be a multiple
               of *segment_size*/8.

             - For `MODE_CTR`, *ciphertext* can be of any length.

             - For `MODE_OPENPGP`, *plaintext* must be a multiple of *block_size*,
               unless it is the last chunk of the message.

            :Parameters:
              ciphertext : byte string
                The piece of data to decrypt.
            :Return: the decrypted data (byte string, as long as *ciphertext*).
        """
        if len(ciphertext) % block_size:
            raise ValueError("Input strings must be a multiple of %d in length" % block_size)
        pBuffer = str_to_PBYTE(ciphertext)
        dwBuffer= DWORD( len(ciphertext) )
        if Decrypt( self.hKey, None, 0, 0, pBuffer, dwBuffer ):
            return string_at( pBuffer, dwBuffer.value )
        raise Exception( hex(windll.kernel32.GetLastError()) )
        
a = AESCipher("0"*16)
assert 'f95c7f6b192b22bffefd1b779933fbfcf95c7f6b192b22bffefd1b779933fbfc' == binascii.hexlify(a.encrypt("0"*16)+a.encrypt("0"*16))
a = AESCipher("0"*16)
assert 'ab4bc5ff39c0c04865184854896b1bb6ab4bc5ff39c0c04865184854896b1bb6' == binascii.hexlify(a.decrypt("0"*16)+a.decrypt("0"*16))
assert 'f95c7f6b192b22bffefd1b779933fbfc' == binascii.hexlify(AESCipher("0"*16).encrypt("0"*16))
assert 'f95c7f6b192b22bffefd1b779933fbfcf95c7f6b192b22bffefd1b779933fbfc' == binascii.hexlify(AESCipher("0"*16).encrypt("0"*32))
assert 'ab4bc5ff39c0c04865184854896b1bb6' == binascii.hexlify(AESCipher("0"*16).decrypt("0"*16))
assert 'ab4bc5ff39c0c04865184854896b1bb6ab4bc5ff39c0c04865184854896b1bb6' == binascii.hexlify(AESCipher("0"*16).decrypt("0"*32))


a = AESCipher("0"*16, mode=MODE_CBC, IV="0"*16)
assert '14ccded8373d555098acebb3a5d29d7dc4c587b6072c0bff086a886e604d5a9b' == binascii.hexlify(a.encrypt("0"*16)+a.encrypt("0"*16))
a = AESCipher("0"*16, mode=MODE_CBC, IV="0"*16)
assert '9b7bf5cf09f0f07855287864b95b2b869b7bf5cf09f0f07855287864b95b2b86' == binascii.hexlify(a.decrypt("0"*16)+a.decrypt("0"*16))
assert '14ccded8373d555098acebb3a5d29d7d' == binascii.hexlify(AESCipher("0"*16, mode=MODE_CBC, IV="0"*16).encrypt("0"*16))
assert '14ccded8373d555098acebb3a5d29d7dc4c587b6072c0bff086a886e604d5a9b' == binascii.hexlify(AESCipher("0"*16, mode=MODE_CBC, IV="0"*16).encrypt("0"*32))
assert '9b7bf5cf09f0f07855287864b95b2b86' == binascii.hexlify(AESCipher("0"*16, mode=MODE_CBC, IV="0"*16).decrypt("0"*16))
assert '9b7bf5cf09f0f07855287864b95b2b869b7bf5cf09f0f07855287864b95b2b86' == binascii.hexlify(AESCipher("0"*16, mode=MODE_CBC, IV="0"*16).decrypt("0"*32))

assert 'c80046fe161ae8bf99548885c5514862' == hashlib.md5(AESCipher("0"*16, mode=MODE_CBC, IV="0"*16).encrypt("0"*(100*block_size))).hexdigest()
assert '77bb58bd7f9fa4a05ff8f78fb389347b' == hashlib.md5(AESCipher("0"*16, mode=MODE_CBC, IV="0"*16).decrypt("0"*(100*block_size))).hexdigest()

assert 'fc5fec08ac2bf65ba772262224d6aea7' == hashlib.md5(AESCipher("0"*24, mode=MODE_CBC, IV="0"*16).encrypt("0"*(100*block_size))).hexdigest()
assert '29d45d0b6d6a6815f9fd9e1cbb1c7609' == hashlib.md5(AESCipher("0"*24, mode=MODE_CBC, IV="0"*16).decrypt("0"*(100*block_size))).hexdigest()

assert '513d4265325a8863e3d6fef3572c643e' == hashlib.md5(AESCipher("0"*32, mode=MODE_CBC, IV="0"*16).encrypt("0"*(100*block_size))).hexdigest()
assert 'd6ea23b43d6f789b6a3692a6e29923da' == hashlib.md5(AESCipher("0"*32, mode=MODE_CBC, IV="0"*16).decrypt("0"*(100*block_size))).hexdigest()
