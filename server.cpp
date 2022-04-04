#include "mydb.h"
#include "Packet.h"
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

int main(int argc, char **argv)
{
    int port;
    if (argc < 2)
    {
        cout << "Usage: ./server portnum" << endl;
        exit(0);
    }
    port = atoi(argv[1]);

    //初始化服务器socket
    int serversock = socket(AF_INET, SOCK_STREAM, 0);
    if (serversock <= 0)
    {
        perror("Create socket");
        exit(-1);
    }
    struct sockaddr_in saddr;
    bzero(&saddr, sizeof(saddr));
    saddr.sin_family = PF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serversock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1)
    {
        perror("bind");
        exit(-1);
    }
    if (listen(serversock, 10) == -1)
    {
        perror("listen");
        exit(-1);
    }

    //初始化数据库连接
    MyDB db;
    string host("localhost");
    string user("root");
    string pwd("914075");
    string db_name("authenticate");
    if (!db.initDB(host, user, pwd, db_name))
    {
        perror("init database fail:");
        exit(-1);
    }

    cout << "SERVER ON" << endl;
    while (true)
    {
        struct sockaddr_in caddr;
        bzero(&caddr, sizeof(caddr));
        socklen_t len = sizeof(caddr);
        int cfd = accept(serversock, (struct sockaddr *)&caddr, &len);
        if (cfd < 0)
        {
            perror("accept");
            exit(-1);
        }
        char ip[20];
        inet_ntop(AF_INET, &caddr.sin_addr.s_addr, ip, sizeof(ip));
        cout << "Connected:[" << ip << "][port:" << ntohs(caddr.sin_port) << "]" << endl;
        struct datapkt *recv_pkt = (struct datapkt *)malloc(sizeof(struct datapkt));
        int res = 0;

        //接收请求包
        if ((res = recv(cfd, recv_pkt, sizeof(struct datapkt), 0)) <= 0)
        {
            perror("recv data pkt");
            exit(-1);
        }
        if (!recv_pkt->R)
        {
            //认证模式
            struct authenPayload *apayload = (struct authenPayload *)recv_pkt->payload;

            //取用户名查询数据库，得到散列值1
            string sql("select * from auth_code where username='" + string((char *)apayload->username) + "';");
            // cout << sql << endl; // TODO:
            string digest1_str("");
            if (!db.SqlQuery(sql, digest1_str))
            {
                //没有username对应元组，认证失败，状态码为2，payload为错误信息
                struct replypkt *reply_pkt = (struct replypkt *)malloc(sizeof(struct replypkt));
                reply_pkt->status = 2;
                string errmsg("认证失败，没有'" + string((char *)apayload->username) + "'的相关信息.\0");
                memcpy(reply_pkt->payload, errmsg.c_str(), strlen(errmsg.c_str()) + 1);
                if ((res = send(cfd, reply_pkt, sizeof(struct replypkt), 0)) <= 0)
                {
                    perror("send reply pkt status=2 1");
                    exit(-1);
                }
                close(cfd);
                continue;
            }
            else
            {
                //进一步判断散列值2是否相等
                //由用户名和散列值1计算散列值2
                SHA256 sha;
                string digest1_dec_hex;
                //数据库中存储的是十六进制编码的字符串，十六进制解码
                StringSource HexDec1(digest1_str, true, new HexDecoder(new StringSink(digest1_dec_hex)));
                SecByteBlock digest1((Byte *)digest1_dec_hex.c_str(), sha.DigestSize());
                sha.Update(digest1, digest1.size());
                sha.Update(apayload->authenCode, AUTHENCODE_LENGTH);
                SecByteBlock digest2(sha.DigestSize());
                sha.Final(digest2);
                //手动比较
                SecByteBlock digest2_recv(sha.DigestSize());
                digest2_recv.Assign(apayload->hash, sha.DigestSize());
                bool hashflag = (digest2 == digest2_recv) ? true : false;
                // bool hashflag = sha.Verify(apayload->hash);
                if (!hashflag)
                {
                    //认证失败，散列值2不匹配，发送错误信息
                    //十六进制编码，方便打印
                    string digest2_hex, digest2_recv_hex;
                    StringSource HexEnc2_1(string((char *)digest2.data()), true, new HexEncoder(new StringSink(digest2_hex)));
                    StringSource HexEnc2_2(string((char *)digest2_recv.data()), true, new HexEncoder(new StringSink(digest2_recv_hex)));

                    struct replypkt *reply_pkt = (struct replypkt *)malloc(sizeof(struct replypkt));
                    reply_pkt->status = 2;
                    string errmsg("认证失败,散列值2不匹配\n散列值2应为:" + digest2_hex + "客户端实际发送的散列值2为:" + digest2_recv_hex + ".\n\0");
                    memcpy(reply_pkt->payload, errmsg.c_str(), strlen(errmsg.c_str()) + 1);
                    if ((res = send(cfd, reply_pkt, sizeof(struct replypkt), 0)) <= 0)
                    {
                        perror("send reply pkt status=2 2");
                        exit(-1);
                    }
                    close(cfd);
                    continue;
                }
                else
                {
                    //认证成功，状态码为3，payload为AES-CBC加密后的认证码
                    struct replypkt *reply_pkt = (struct replypkt *)malloc(sizeof(struct replypkt));
                    reply_pkt->status = 3;

                    // AES-CBC加密认证码
                    CBC_Mode<AES>::Encryption cbc_aes_enc;
                    SecByteBlock key, iv;
                    string cipher;
                    //密钥为散列值1，初始向量为散列值1的前16字节
                    key = digest1;
                    iv.Assign(digest1.data(), MY_IV_LENGTH);
                    //检查key与iv的长度
                    if (key.size() > cbc_aes_enc.MaxKeyLength())
                    {
                        cout << "AES-CBC 密钥过长:" << key.size() << endl;
                        exit(-1);
                    }
                    if (iv.size() > cbc_aes_enc.MaxIVLength())
                    {
                        cout << "AES-CBC IV过长：" << iv.size() << endl;
                        exit(-1);
                    }
                    //加密,构造报文
                    cbc_aes_enc.SetKeyWithIV(key, key.size(), iv, iv.size());
                    StringSource Enc(string((char *)apayload->authenCode), true, new StreamTransformationFilter(cbc_aes_enc, new StringSink(cipher)));
                    cipher.append("\0"); // TODO:
                    if (cipher.length() + 1 > MAX_LENGTH)
                    {
                        cout << "密文长度过长:" << cipher.length() << endl;
                        exit(-1);
                    }
                    memcpy(reply_pkt->payload, cipher.c_str(), cipher.length() + 1);
                    //发送应答包
                    if ((res = send(cfd, reply_pkt, sizeof(struct replypkt), 0)) <= 0)
                    {
                        perror("send reply pkt status=3");
                        exit(-1);
                    }
                } // if(!hashflag)
            }     // if(db.SqlQuery())
        }         // if(!R)
        else
        {
            //注册模式
            struct registerPayload *rpayload = (struct registerPayload *)recv_pkt->payload;
            struct replypkt *replypkt = (struct replypkt *)malloc(sizeof(struct replypkt));
            string reply_payload;
            bool flag = true;
            if (strlen((char *)rpayload->username) + 1 > USERNAME_MAX_LENGTH)
            {
                flag = false;
                reply_payload = string("注册失败,用户名过长.");
            }
            else if (strlen((char *)rpayload->hash) != HASH_LENGTH)
            {
                flag = false;
                reply_payload = string("散列值2长度有误:") + string((to_string((int)strlen((char *)rpayload->hash))));
            }
            else
            {
                //在数据库中插入
                //将散列值2十六进制编码
                string hash_hex;
                StringSource enchex(string((char *)rpayload->hash), true, new HexEncoder(new StringSink(hash_hex)));
                string sql("insert into auth_code values('" + string((char *)rpayload->username) + "','" + hash_hex + "');");
                string param;
                if (!db.SqlQuery(sql, param))
                {
                    //加入数据库失败
                    flag = false;
                    reply_payload = string("插入数据库失败(" + sql + ").");
                }
            }
            if (!flag)
            {
                //注册失败
                replypkt->status = 0;
                // payload为错误原因
                memcpy(replypkt->payload, reply_payload.c_str(), reply_payload.length() + 1);
            }
            else
            {
                //注册成功
                replypkt->status = 1;
                // payload为注册成功的信息
                reply_payload = string("注册成功");
                memcpy(replypkt->payload, reply_payload.c_str(), reply_payload.length() + 1);
            }
            //发送应答包
            send(cfd, replypkt, sizeof(struct replypkt), 0);
        }
        close(cfd);
        continue;
    } // while
}