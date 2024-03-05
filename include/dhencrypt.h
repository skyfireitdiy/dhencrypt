#include "cryptopp/secblockfwd.h"
_Pragma("once")

#include <cryptopp/dh.h>
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

private:
    optional<SecByteBlock> publicKey;
    optional<SecByteBlock> remotePublicKey;
    optional<SecByteBlock> privKey;

    AutoSeededRandomPool rnd;

    DH dh_;
};
