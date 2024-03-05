_Pragma("once")
#include "cryptopp/secblockfwd.h"
#include <string>

#include <cryptopp/dh.h>
#include <cryptopp/hex.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>

#include <optional>

    using namespace CryptoPP;
using namespace std;

class DHEncrypt
{
public:
    struct Token
    {
        Integer prime;
        Integer generator;
        Integer publicKey;
    };

public:
    DHEncrypt();
    DHEncrypt(Token token);

    optional<Token> GetToken();
    optional<Integer> GetSecretKey();
    void SetRemotePublicKey(Integer publicKey);

    static string CalculateSHA256(const string &message);
    static std::string EncodeBase64(const std::string &message);
    static std::string DecodeBase64(const std::string &message);
    static string Encrypt(const string &message, const string &key);
    static string Decrypt(const string &message, const string &key);

private:
    optional<SecByteBlock> publicKey;
    optional<SecByteBlock> remotePublicKey;
    optional<SecByteBlock> privKey;

    AutoSeededRandomPool rnd;

    DH dh_;
};

template <size_t N>
string GenerateRandomNumber()
{
    string randomNum;

    // 创建AutoSeededRandomPool对象
    AutoSeededRandomPool rng;

    // 生成128位随机数
    unsigned char buffer[N];
    rng.GenerateBlock(buffer, sizeof(buffer));

    // 将随机数转换为十六进制字符串
    HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(randomNum));
    encoder.Put(buffer, sizeof(buffer));
    encoder.MessageEnd();

    return randomNum;
};
