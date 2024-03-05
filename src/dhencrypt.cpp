#include "dhencrypt.h"
#include "cryptopp/integer.h"
#include "cryptopp/secblockfwd.h"

DHEncrypt::DHEncrypt()
{
    dh_.AccessGroupParameters().Initialize(rnd, 512);
}

DHEncrypt::DHEncrypt(Token token)
{
    dh_.AccessGroupParameters().Initialize(token.prime, token.generator);
    SetRemotePublicKey(token.publicKey);
}

optional<DHEncrypt::Token> DHEncrypt::GetToken()
{
    if (!dh_.GetGroupParameters().ValidateGroup(rnd, 3))
    {
        return std::nullopt;
    }

    Integer iPrime = dh_.GetGroupParameters().GetModulus();
    Integer iGenerator = dh_.GetGroupParameters().GetSubgroupGenerator();

    privKey = SecByteBlock(dh_.PrivateKeyLength());
    publicKey = SecByteBlock(dh_.PublicKeyLength());
    dh_.GenerateKeyPair(rnd, *privKey, *publicKey);

    return DHEncrypt::Token {iPrime, iGenerator,
                             Integer(*publicKey, publicKey->size())};
}

void DHEncrypt::SetRemotePublicKey(Integer publicKey)
{
    SecByteBlock key(publicKey.MinEncodedSize());
    publicKey.Encode(key, key.size());
    remotePublicKey = key;
}

optional<Integer> DHEncrypt::GetSecretKey()
{
    SecByteBlock secretKey(dh_.AgreedValueLength());
    if (!dh_.Agree(secretKey, *privKey, *remotePublicKey))
    {
        return std::nullopt;
    }
    Integer ret(secretKey, secretKey.size());
    return ret;
}
