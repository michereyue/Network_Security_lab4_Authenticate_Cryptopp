#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <iostream>
using namespace std;
using namespace CryptoPP;
int main()
{
    AutoSeededX917RNG<AES> rng;
    word32 i = rng.GenerateWord32();
    cout << i << endl;
    CryptoPP::byte output[64]; //与std冲突
    rng.GenerateBlock(output, 64);

    return 0;
}