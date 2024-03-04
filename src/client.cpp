#include "common.h"
#include <iostream>

int main()
{
    auto KeyPair1 = GenerateKeyPair();

    std::cout << "1 Private Key: " << HexEncode(KeyPair1.PrivateKey) << std::endl;
    std::cout << "1 Public Key: " << HexEncode(KeyPair1.PublicKey) << std::endl;

    auto KeyPair2 = GenerateKeyPair();

    std::cout << "2 Private Key: " << HexEncode(KeyPair2.PrivateKey) << std::endl;
    std::cout << "2 Public Key: " << HexEncode(KeyPair2.PublicKey) << std::endl;

    auto SecretKey = GetSecretKey(KeyPair1.p, KeyPair1.q, KeyPair1.g, KeyPair1.PublicKey, KeyPair2.PrivateKey);
    if (SecretKey)
    {
        std::cout << "1 Secret Key: " << HexEncode(*SecretKey) << std::endl;
    }
    else
    {
        std::cout << "1 Secret Key: None" << std::endl;
    }

    auto SecretKey2 = GetSecretKey(KeyPair2.p, KeyPair2.q, KeyPair2.g, KeyPair2.PublicKey, KeyPair1.PrivateKey);
    if (SecretKey2)
    {
        std::cout << "2 Secret Key: " << HexEncode(*SecretKey2) << std::endl;
    }
    else
    {
        std::cout << "2 Secret Key: None" << std::endl;
    }

    return 0;
}
