#include "dhencrypt.h"
#include "cryptopp/integer.h"
#include "cryptopp/secblockfwd.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/base64.h"

#include <iostream>

DHEncrypt::DHEncrypt()
{
    dh_.AccessGroupParameters().Initialize(rnd, 128);
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

string DHEncrypt::CalculateSHA256(const string &message)
{
    string digest;

    // 创建SHA-256对象
    CryptoPP::SHA256 hash;

    // 计算哈希值
    StringSource(message, true,
                 new CryptoPP::HashFilter(hash,
                                          new CryptoPP::HexEncoder(
                                              new CryptoPP::StringSink(digest))));

    return digest;
}

string DHEncrypt::Encrypt(const string &message, const string &key)
{
    // 计算密钥SHA256
    auto keySha256 = CalculateSHA256(key);
    Integer iKey(keySha256.c_str());

    // 生成随机数
    auto randomNum2 = GenerateRandomNumber<1>();
    char irandomNum2 = strtoul(randomNum2.c_str(), nullptr, 16);

    // 将消息和随机数拼接
    string msgbak = message;
    msgbak.push_back(irandomNum2);

    // 生成密钥
    auto keySize = iKey.MinEncodedSize();
    unsigned char *skey = new unsigned char[keySize];
    iKey.Encode(skey, keySize);

    // 异或加密
    for (int i = 0, j = 0; i < msgbak.size(); i++, j++)
    {
        msgbak[i] ^= skey[j % keySize];
    }

    // 释放密钥
    delete[] skey;

    // 计算哈希加密后消息的
    auto cryptedMsgSha256 = CalculateSHA256(msgbak);

    // 将消息的base64和哈希值拼接
    return EncodeBase64(msgbak) + cryptedMsgSha256;
}

string DHEncrypt::Decrypt(const string &message, const string &key)
{
    // 获取加密消息的哈希值
    auto cryptedMsgSha256 = message.substr(message.size() - 64);
    cout << "crypted msg sha256: " << cryptedMsgSha256 << endl;

    // 获取加密消息
    auto msgbak = DecodeBase64(message.substr(0, message.size() - 64));

    // 计算哈希
    auto sha256 = CalculateSHA256(msgbak);
    cout << "encrypted msg sha256: " << sha256 << endl;

    // 验证哈希
    if (sha256 != cryptedMsgSha256)
    {
        cout << "decrypt failed" << endl;
        return "";
    }

    // 计算密钥哈希
    auto keySha256 = CalculateSHA256(key);
    Integer iKey(keySha256.c_str());

    // 生成密钥
    auto keySize = iKey.MinEncodedSize();
    unsigned char *skey = new unsigned char[keySize];
    iKey.Encode(skey, keySize);

    // 异或解密
    for (int i = 0, j = 0; i < msgbak.size(); i++, j++)
    {
        msgbak[i] ^= skey[j % keySize];
    }

    // 释放密钥
    delete[] skey;

    // 删除随机数
    msgbak.pop_back();

    // 返回解密后的消息
    return msgbak;
}

std::string DHEncrypt::EncodeBase64(const std::string &message)
{
    std::string encoded;

    // 创建Base64编码器
    CryptoPP::Base64Encoder encoder;

    // 设置编码选项
    encoder.Put((const CryptoPP::byte *)message.data(), message.size());
    encoder.MessageEnd();

    // 将编码结果存储到字符串中
    CryptoPP::word64 size = encoder.MaxRetrievable();
    if (size)
    {
        encoded.resize(size);
        encoder.Get((CryptoPP::byte *)&encoded[0], encoded.size());
    }

    return encoded;
}

std::string DHEncrypt::DecodeBase64(const std::string &encoded)
{
    std::string decoded;

    // 创建Base64解码器
    CryptoPP::Base64Decoder decoder;

    // 设置解码选项
    decoder.Put((const CryptoPP::byte *)encoded.data(), encoded.size());
    decoder.MessageEnd();

    // 将解码结果存储到字符串中
    CryptoPP::word64 size = decoder.MaxRetrievable();
    if (size)
    {
        decoded.resize(size);
        decoder.Get((CryptoPP::byte *)&decoded[0], decoded.size());
    }

    return decoded;
}
