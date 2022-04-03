#include <iostream>
#include <stdio.h>
#include <cryptopp/sha.h>
using namespace std;
using namespace CryptoPP;
int main()
{
    try
    {
        SHA256 sha;
        cout << "DigestSize=" << sha.DigestSize() << endl;
        CryptoPP::byte msg[] = "a b c d";
        CryptoPP::byte msg1[] = "a b ";
        CryptoPP::byte msg2[] = "c d";
        sha.Update(msg1, sizeof(msg1) - 1); // remove \0
        sha.Update(msg2, sizeof(msg2) - 1);
        SecByteBlock digest1(sha.DigestSize());
        // size_t len1 = sha.DigestSize();                        //最终hash值的大小
        // CryptoPP::byte *digest1 = sha.CreateUpdateSpace(len1); //存放hash值的空间,len1也是返回参数，代表实际申请到的空间大小
        // if (len1 < sha.DigestSize())
        //{
        //     cout << "No enough space" << endl;
        //     exit(-1);
        // }
        sha.Final(digest1); //计算hash值并重置内部状态
        cout << "digest1=0x";
        for (size_t i = 0; i < sha.DigestSize(); i++)
        {
            printf("%02X", digest1[i]);
        }
        cout << endl;
        /* 第二种计算方式 */
        SecByteBlock digest2(sha.DigestSize()); //存放hash的空间
        // size_t len2 = sha.DigestSize();
        // CryptoPP::byte *digest2 = sha.CreateUpdateSpace(len2);//CreateUpdateSpace申请的空间会随着内部状态的重置而销毁
        // if (len2 < sha.DigestSize())
        //{
        //     cout << "No space" << endl;
        //     exit(-1);
        // }
        sha.CalculateDigest(digest2, msg, sizeof(msg) - 1);
        cout << "digest2=0x";
        for (size_t i = 0; i < sha.DigestSize(); i++)
        {
            printf("%02X", digest2[i]);
        }
        cout << endl;
        /* 验证正确性*/
        bool res;
        res = sha.VerifyDigest(digest1, msg, sizeof(msg) - 1); //用于验证的hash值存放在SecByteBlock中
        cout << "res=" << boolalpha << res << endl;
        // delete[] digest1;
    }
    catch (const exception &e)
    {
        cout << "Exception:" << e.what() << endl;
    }
    return 0;
}