#ifndef MYDB_H
#define MYDB_H
#include <iostream>
#include <mariadb/mysql.h>
#include <string>
using namespace std;

class MyDB
{
public:
    MyDB();
    ~MyDB();
    bool initDB(string host, string user, string pwd, string db_name);
    bool SqlQuery(string sql, string &hashcode);

private:
    MYSQL *mysql;      //句柄指针
    MYSQL_RES *result; //指向查询结果的指针
    MYSQL_ROW row;     //按行返回的查询信息
};
#endif