#include <iostream>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
using namespace CryptoPP;
int main()
{
    AES::Encryption aes;
    std::cout << "Default key len=" << aes.DefaultKeyLength() << std::endl;
    std::cout << "min key len=" << aes.MinKeyLength() << std::endl;
    std::cout << "max key len=" << aes.MaxKeyLength() << std::endl;
    std::cout << "block size=" << aes.BlockSize() << std::endl;
    AutoSeededRandomPool rng;
    SecByteBlock key, iv;
    std::string msg = "aaaaaaaa";
    std::string cipher, recover;
    try
    {
        CBC_Mode<AES>::Encryption cbc_aes_enc;
        std::cout << "Default iv len=" << cbc_aes_enc.DefaultIVLength() << std::endl;
        std::cout << "min iv len=" << cbc_aes_enc.MinIVLength() << std::endl;
        std::cout << "max iv len=" << cbc_aes_enc.MaxIVLength() << std::endl;
        std::cout << "MSG:";
        StringSource sSrc(msg, true, new HexEncoder(new FileSink(std::cout)));
        std::cout << std::endl;
        key.resize(cbc_aes_enc.DefaultKeyLength()); //分配空间
        iv.resize(cbc_aes_enc.DefaultIVLength());
        rng.GenerateBlock(key, key.size());
        rng.GenerateBlock(iv, iv.size());
        cbc_aes_enc.SetKeyWithIV(key, key.size(), iv, iv.size());                                         //设置CBC的密钥和iv
        StringSource Enc(msg, true, new StreamTransformationFilter(cbc_aes_enc, new StringSink(cipher))); //用cbc_aes_enc加密msg，并将结果存放在cipher中
        std::cout << "Cipher:";
        StringSource sCipher(cipher, true, new HexEncoder(new FileSink(std::cout)));
    }
    catch (const Exception &e)
    {
        std::cout << "Exception:" << e.what() << std::endl;
        exit(0);
    }
    try
    {
        // Decode
        CBC_Mode<AES>::Decryption aes_dec;
        aes_dec.SetKeyWithIV(key, key.size(), iv, iv.size());
        StringSource Dec(cipher, true, new StreamTransformationFilter(aes_dec, new StringSink(recover)));
        std::cout << std::endl
                  << "recover:";
        StringSource sRecover(recover, true, new HexEncoder(new FileSink(std::cout)));
        std::cout << std::endl;
    }
    catch (const Exception &e)
    {
        std::cout << "Exception:" << e.what() << std::endl;
        exit(0);
    }
    return 0;
}