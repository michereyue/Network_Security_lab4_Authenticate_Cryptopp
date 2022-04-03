#include <iostream>
#include <cryptopp/integer.h>
using CryptoPP::Integer;
using std::cout;
using std::endl;

int main()
{
    Integer j("1111");
    j %= 19;
    cout << j << endl;
    return 0;
}