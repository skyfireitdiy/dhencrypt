#include "common.h"
#include <cryptopp/osrng.h>
#include <cryptopp/dh.h>
#include <cryptopp/hex.h>
#include <optional>
#include <cryptopp/nbtheory.h>

using namespace CryptoPP;

// 生成DH密钥交换算法的密钥对
KeyPair GenerateKeyPair()
{
    CryptoPP::AutoSeededRandomPool rng;
    PrimeAndGenerator pg;
    pg.Generate(1, rng, 512, 511);
    auto p = pg.Prime();
    auto q = pg.SubPrime();
    auto g = pg.Generator();
    CryptoPP::DH dh(p, q, g);

    CryptoPP::SecByteBlock publicKey(dh.PublicKeyLength());
    CryptoPP::SecByteBlock privateKey(dh.PrivateKeyLength());
    dh.GenerateKeyPair(rng, privateKey, publicKey);

    auto groupParameters = dh.GetGroupParameters();

    return {p, q, g, privateKey, publicKey};
}

KeyPair GenerateKeyPair(CryptoPP::Integer p, CryptoPP::Integer q, CryptoPP::Integer g)
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::DH dh(p, q, g);

    CryptoPP::SecByteBlock publicKey(dh.PublicKeyLength());
    CryptoPP::SecByteBlock privateKey(dh.PrivateKeyLength());
    dh.GenerateKeyPair(rng, privateKey, publicKey);

    auto groupParameters = dh.GetGroupParameters();

    return {p, q, g, privateKey, publicKey};
}

std::string HexEncode(const CryptoPP::SecByteBlock &data)
{
    std::string result;
    HexEncoder encoder(new StringSink(result));
    encoder.Put(data, data.size());
    encoder.MessageEnd();
    return result;
}

std::optional<CryptoPP::SecByteBlock> GetSecretKey(CryptoPP::Integer p, CryptoPP::Integer q, CryptoPP::Integer g, const CryptoPP::SecByteBlock &publicKey, const CryptoPP::SecByteBlock &privateKey)
{
    CryptoPP::DH dh(p, q, g);
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::SecByteBlock sharedSecret(dh.AgreedValueLength());
    if (!dh.Agree(sharedSecret, privateKey, publicKey))
    {
        return std::nullopt;
    }
    return sharedSecret;
}
