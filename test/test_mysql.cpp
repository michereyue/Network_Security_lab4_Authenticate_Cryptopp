#include <iostream>
#include <mariadb/mysql.h>

int main()
{
    MYSQL *mysql;
    mysql_real_connect(mysql, host.c_str(), user.c_str(), passwd.c_str(), db_name.c_str(), 0, NULL, 0);
}