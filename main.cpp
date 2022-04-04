#include "mydb.h"
using namespace std;

int main()
{
    string a("B1DF0CCE95B967D67980FF5B7C6F806876768777F4D5AF0D7B015AD662DC220E");

    MyDB db;
    string host("localhost");
    string user("root");
    string pwd("914075");
    string db_name("authenticate");
    db.initDB(host, user, pwd, db_name);
    string hashcode;
    db.SqlQuery("select * from auth_code;", hashcode);
    cout << hashcode << endl;
    db.SqlQuery("insert ;", hashcode);
    cout << hashcode << endl;
    getchar();
    return 0;
}