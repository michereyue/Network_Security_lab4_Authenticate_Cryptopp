#ifndef PACKET_H
#define PACKET_H

#include <cryptopp/words.h>
using namespace CryptoPP;

#define HASH_LENGTH 32         // hash值的长度(Byte)
#define MAX_LENGTH 128         // payload的长度
#define USERNAME_MAX_LENGTH 16 // username
#define AUTHENCODE_LENGTH 32   //认证码长度
#define MY_IV_LENGTH 16        //初始向量长度
#define AES_KEY_LENGTH 32      //密钥长度

typedef CryptoPP::byte Byte;

struct datapkt //客户端发送的请求包格式
{
    bool R; //该包存放的是注册信息
    Byte payload[MAX_LENGTH];
};
struct registerPayload //用于注册的包格式
{
    Byte username[USERNAME_MAX_LENGTH];
    Byte hash[HASH_LENGTH]; //用户名与口令的散列值
};
struct authenPayload
{
    Byte username[USERNAME_MAX_LENGTH];
    Byte hash[HASH_LENGTH];             //散列值2
    Byte authenCode[AUTHENCODE_LENGTH]; //认证码
};
struct replypkt //应答包格式
{
    uint32_t status;
    /*状态码
        0-注册失败，payload部分为错误信息
        1-注册成功，payload部分为注册成功的信息
        2-认证失败，payload部分为错误信息
        3-认证成功，payload部分为加密后的认证码
    */
    Byte payload[MAX_LENGTH];
};

#endif
