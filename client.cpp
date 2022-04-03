#include "mydb.h"
#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
using namespace CryptoPP;
using namespace std;

#define HASH_LENGTH 32         // hash值的长度(Byte)
#define MAX_LENGTH 128         // payload的长度
#define USERNAME_MAX_LENGTH 16 // username
#define AUTHENCODE_LENGTH 32   //认证码长度
#define IV_LENGTH 16           //初始向量长度
#define AES_KEY_LENGTH 32      //密钥长度
typedef CryptoPP::byte Byte;

typedef struct datapkt //客户端发送的请求包格式
{
    bool R; //该包存放的是注册信息
    Byte payload[MAX_LENGTH];
};
typedef struct registerPayload //用于注册的包格式
{
    Byte username[USERNAME_MAX_LENGTH];
    Byte hash[HASH_LENGTH]; //用户名与口令的散列值
};
typedef struct authenPayload
{
    Byte username[USERNAME_MAX_LENGTH];
    Byte hash[HASH_LENGTH];             //散列值2
    Byte authenCode[AUTHENCODE_LENGTH]; //认证码
};
typedef struct replypkt //应答包格式
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
/*
    -u 用户名 -p 口令
    用户名和口令都是16字节
    -r 注册模式
*/
Byte username[USERNAME_MAX_LENGTH];
Byte passwd[USERNAME_MAX_LENGTH];
bool R = false; // true:register
int port = 8888;
char *serverip = "172.19.24.188";
void PrintUsage()
{
    cout << "Usage:\t./client -u username -p passwd [-r]" << endl;
    cout << "\tUsername and Passwd must be shorter than " << USERNAME_MAX_LENGTH - 1 << endl;
    cout << "\tRegister mode is triggered on if '-r' is assigned." << endl;
}

int main(int argc, char **argv)
{
    string optstring("u:p:r");
    int opt;
    bool flag_u = false;
    bool flag_p = false;
    while ((opt = getopt(argc, argv, optstring.c_str())) != -1)
    {
        switch (opt)
        {
        case 'u':
            //用户名的长度限制
            if (strlen(optarg) + 1 > USERNAME_MAX_LENGTH)
            {
                cout << "Error:username have to be shorter than " << USERNAME_MAX_LENGTH - 1 << endl;
                exit(-1);
            }
            memcpy(username, optarg, sizeof(username));
            flag_u = true;
            break;
        case 'p':
            //口令的长度限制
            if (strlen(optarg) + 1 > USERNAME_MAX_LENGTH)
            {
                cout << "Error:passwd have to be shorter than " << USERNAME_MAX_LENGTH - 1 << endl;
                exit(-1);
            }
            memcpy(passwd, optarg, sizeof(passwd));
            flag_p = true;
            break;
        case 'r':
            R = true;
            break;
        default:
            PrintUsage();
            exit(0);
            break;
        }
    }
    if (!flag_u || !flag_p)
    {
        PrintUsage();
        exit(0);
    }
    if (!R)
    {
        //认证模式
        cout << "Authentication Mode!" << endl;
        //计算用户名和口令的散列值(不包含末尾的\0)
        SHA256 sha;
        sha.Update(username, strlen((char *)username));
        sha.Update(passwd, strlen((char *)passwd));
        SecByteBlock digest1(sha.DigestSize()); //散列值1的存放空间
        sha.Final(digest1);                     //计算散列值1，并刷新状态
        cout << "username:";
        StringSource sUsername(username, true, new HexEncoder(new FileSink(std::cout)));
        cout << endl;
        cout << "passwd:";
        StringSource sPasswd(passwd, true, new HexEncoder(new FileSink(cout)));
        cout << endl;
        cout << "digest1=";
        StringSource sDigest1(digest1, true, new HexEncoder(new FileSink(std::cout)));

        //生成随机的认证码
        Byte authenCode[AUTHENCODE_LENGTH];
        AutoSeededRandomPool rng;
        rng.GenerateBlock(authenCode, sizeof(authenCode));

        //由散列值1与认证码计算散列值2
        sha.Update(digest1, digest1.size());
        sha.Update(authenCode, sizeof(authenCode));
        SecByteBlock digest2(sha.DigestSize());
        sha.Final(digest2);
        cout << endl
             << "digest2=";
        StringSource sDigest2(digest2, true, new HexEncoder(new FileSink(std::cout)));

        //构造发送数据包
        struct datapkt *send_pkt = (struct datapkt *)malloc(sizeof(struct datapkt));
        send_pkt->R = false;
        struct authenPayload *apayload = (struct authenPayload *)malloc(sizeof(struct authenPayload));
        memcpy(apayload->username, username, USERNAME_MAX_LENGTH);
        memcpy(apayload->hash, digest1.data(), digest1.size());
        memcpy(apayload->authenCode, authenCode, sizeof(authenCode));
        memcpy(send_pkt->payload, apayload, sizeof(struct authenPayload));

        //创建socket，发送数据包,接收应答数据包
        int clientsock = socket(AF_INET, SOCK_STREAM, 0);
        if (clientsock <= 0)
        {
            perror("Create socket");
            exit(-1);
        }
        struct sockaddr_in saddr;
        bzero(&saddr, sizeof(saddr));
        saddr.sin_family = PF_INET;
        saddr.sin_port = htons(port);
        inet_pton(AF_INET, serverip, &saddr.sin_addr.s_addr);
        if (connect(clientsock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
        {
            perror("connect");
            exit(-1);
        }
        int res = 0;
        if ((res = send(clientsock, send_pkt, sizeof(struct datapkt), 0)) <= 0)
        {
            perror("send data pkt");
            exit(-1);
        }
        struct replypkt *reply = (struct replypkt *)malloc(sizeof(struct replypkt));
        if ((res = recv(clientsock, reply, sizeof(struct replypkt), 0)) <= 0)
        {
            perror("recv reply pkt");
            exit(-1);
        }

        //解析应答包
        if (reply->status < 2)
        {
            cout << "ERROR:这是一个注册请求的应答包." << endl;
            exit(-1);
        }
        if (reply->status > 3)
        {
            cout << "ERROR:应答包:不合法的状态码" << endl;
            exit(-1);
        }
        if (reply->status == 2)
        {
            //认证失败
            cout << "认证失败:" << reply->payload << endl;
            exit(0);
        }
        if (reply->status == 3)
        {
            //认证成功
            // AES-CBC解密得到认证码，十六进制编码后写入文件
            //用digest1做解密密钥,digest1的前16字节做初始向量
            CBC_Mode<AES>::Decryption dec;
            Byte *piv = (Byte *)malloc(IV_LENGTH);
            memcpy(piv, digest1.data(), IV_LENGTH);
            SecByteBlock iv(piv, IV_LENGTH);
            dec.SetKeyWithIV(digest1, digest1.size(), iv, iv.size());
            string recover; //解密得到的认证码
            StringSource Dec(reply->payload, true, new StreamTransformationFilter(dec, new StringSink(recover)));
            cout << endl
                 << "解密得到的认证码:";
            StringSource sRecover(recover, true, new HexEncoder(new FileSink(cout)));
            cout << endl;
            // TODO: 写到文件
        }
    }
    else
    {
        //注册模式
        cout << "Register Mode!" << endl;
        //计算用户名和口令的散列值(不包含末尾的\0)
        SHA256 sha;
        sha.Update(username, strlen((char *)username));
        sha.Update(passwd, strlen((char *)passwd));
        SecByteBlock digest1(sha.DigestSize()); //散列值1的存放空间
        sha.Final(digest1);                     //计算散列值1，并刷新状态
        cout << "username:";
        StringSource sUsername(username, true, new HexEncoder(new FileSink(std::cout)));
        cout << endl;
        cout << "passwd:";
        StringSource sPasswd(passwd, true, new HexEncoder(new FileSink(cout)));
        cout << endl;
        cout << "digest1=";
        StringSource sDigest1(digest1, true, new HexEncoder(new FileSink(std::cout)));

        //构造注册数据包
        struct datapkt *send_pkt = (struct datapkt *)malloc(sizeof(struct datapkt));
        send_pkt->R = true;
        struct registerPayload *rpayload = (struct registerPayload *)malloc(sizeof(struct registerPayload));
        memcpy(rpayload->username, username, USERNAME_MAX_LENGTH);
        memcpy(rpayload->hash, digest1.data(), digest1.size());
        memcpy(send_pkt->payload, rpayload, sizeof(struct registerPayload));

        //创建socket，发送数据包,接收应答数据包
        int clientsock = socket(AF_INET, SOCK_STREAM, 0);
        if (clientsock <= 0)
        {
            perror("Create socket");
            exit(-1);
        }
        struct sockaddr_in saddr;
        bzero(&saddr, sizeof(saddr));
        saddr.sin_family = PF_INET;
        saddr.sin_port = htons(port);
        inet_pton(AF_INET, serverip, &saddr.sin_addr.s_addr);
        if (connect(clientsock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
        {
            perror("connect");
            exit(-1);
        }
        int res = 0;
        if ((res = send(clientsock, send_pkt, sizeof(struct datapkt), 0)) <= 0)
        {
            perror("send data pkt");
            exit(-1);
        }
        struct replypkt *reply = (struct replypkt *)malloc(sizeof(struct replypkt));
        if ((res = recv(clientsock, reply, sizeof(struct replypkt), 0)) <= 0)
        {
            perror("recv reply pkt");
            exit(-1);
        }

        //解析注册应答包
        if (reply->status > 3)
        {
            cout << "ERROR:应答包:不合法的状态码" << endl;
            exit(-1);
        }
        if (reply->status > 1)
        {
            cout << "ERROR:这是一个认证请求的应答包." << endl;
            exit(-1);
        }
        if (reply->status == 0 || reply->status == 1)
        {
            //打印服务端信息
            if (reply->status == 0)
            {
                cout << "注册失败" << endl;
            }
            else
            {
                cout << "注册成功" << endl;
            }
            cout << reply->payload << endl;
            exit(0);
        }
    }
    return 0;
}
