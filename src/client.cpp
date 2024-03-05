#include "dhencrypt.h"

#include <iostream>

int main()
{
    DHEncrypt dhA;
    auto tokenA = dhA.GetToken();

    cout << "A public key: " << tokenA->publicKey << endl;

    DHEncrypt dhB(*tokenA);
    auto tokenB = dhB.GetToken();

    cout << "B public key: " << tokenB->publicKey << endl;

    dhA.SetRemotePublicKey(tokenB->publicKey);
    cout << "A secret key: " << *dhA.GetSecretKey() << endl;

    cout << "B secret key: " << *dhB.GetSecretKey() << endl;
}
