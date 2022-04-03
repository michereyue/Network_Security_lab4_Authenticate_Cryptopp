#include "mydb.h"

MyDB::MyDB()
{
    mysql = mysql_init(NULL);
    if (mysql == NULL)
    {
        cout << mysql_error(mysql);
        exit(-1);
    }
}
MyDB::~MyDB()
{
    if (mysql != NULL)
    {
        mysql_close(mysql);
    }
}
bool MyDB::initDB(string host, string user, string pwd, string db_name)
{
    mysql = mysql_real_connect(mysql, host.c_str(), user.c_str(), pwd.c_str(), db_name.c_str(), 0, NULL, 0);
    if (mysql == NULL)
    {
        cout << mysql_error(mysql);
        return false;
    }
    return true;
}
bool MyDB::SqlQuery(string sql, string &hashcode)
{
    if (mysql_query(mysql, sql.c_str()))
    { //成功返回0
        cout << mysql_error(mysql);
        return false;
    }
    else
    {
        result = mysql_store_result(mysql); //获取结果
        if (result)
        {
            int col_num = mysql_num_fields(result); //结果的列数，即字段数
            int row_num = mysql_num_rows(result);   //结果的元组个数
            for (int i = 0; i < row_num; i++)
            {
                //打印每一行
                row = mysql_fetch_row(result); //获取下一行
                if (row == NULL)
                    break;
                int j;
                for (j = 0; j < col_num; j++)
                {
                    //打印每一个字段
                    cout << row[j] << "\t";
                }
                hashcode = string(row[j - 1]);
                cout << endl;
            }
        }
        else
        {
            // result==null
            if (mysql_field_count(mysql) == 0) //执行的是非查询语句，则返回改变的行数
            {
                int row_num = mysql_affected_rows(mysql);
                cout << "Num of rows affected:" << row_num << endl;
            }
            else
            { //查询有错误
                cout << mysql_error(mysql);
                return false;
            }
        }
    }
    return true;
}