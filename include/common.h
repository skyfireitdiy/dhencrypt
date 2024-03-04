#include "cryptopp/integer.h"
_Pragma("once")

#include <string>
#include <cryptopp/dh.h>
#include <optional>

    struct KeyPair
{
    CryptoPP::Integer p;
    CryptoPP::Integer q;
    CryptoPP::Integer g;
    CryptoPP::SecByteBlock PrivateKey;
    CryptoPP::SecByteBlock PublicKey;
};

KeyPair GenerateKeyPair();
KeyPair GenerateKeyPair(CryptoPP::Integer p, CryptoPP::Integer q, CryptoPP::Integer g);

std::string HexEncode(const CryptoPP::SecByteBlock &data);

std::optional<CryptoPP::SecByteBlock> GetSecretKey(CryptoPP::Integer p, CryptoPP::Integer q, CryptoPP::Integer g, const CryptoPP::SecByteBlock &publicKey, const CryptoPP::SecByteBlock &privateKey);
