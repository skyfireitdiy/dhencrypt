#include "cryptopp/integer.h"
#include "dhencrypt.h"
#include "Comm.h"
#include <string>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/transport/TSocket.h>

#include <iostream>
#include <sstream>

using namespace apache::thrift;
using namespace apache::thrift::transport;
using namespace apache::thrift::protocol;

void ConvertToken2AuthReq(DHEncrypt::Token token, AuthReq &authReq)
{
    ostringstream so;
    so << token.prime;
    authReq.token.prime = so.str();
    so.str("");
    so << token.generator;
    authReq.token.generator = so.str();
    so.str("");
    so << token.publicKey;
    authReq.token.publicKey = so.str();
}

int main()
{
    DHEncrypt dhe;
    auto token = dhe.GetToken();

    cout << "client prime: " << token->prime << endl;
    cout << "client generator: " << token->generator << endl;
    cout << "client public_key: " << token->publicKey << endl;

    std::shared_ptr<TSocket> socket(new TSocket("localhost", 10250)); // 设置服务器地址和端口
    std::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
    std::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));
    transport->open(); // 打开连接

    CommClient client(protocol);
    AuthResp authResp;
    AuthReq authReq;

    ConvertToken2AuthReq(*token, authReq);

    cout << "converted prime: " << authReq.token.prime << endl;
    cout << "converted generator: " << authReq.token.generator << endl;
    cout << "converted public_key: " << authReq.token.publicKey << endl;

    try
    {
        client.auth(authResp, authReq);
        cout << "receive server public_key: " << authResp.publicKey << endl;

        Integer publicKey(authResp.publicKey.c_str());
        dhe.SetRemotePublicKey(publicKey);
        auto secretKey = dhe.GetSecretKey();
        cout << "client secretKey: " << *secretKey << endl;

        ostringstream so;
        so << *secretKey;
        auto keyStr = so.str();

        string data;
        while (getline(cin, data))
        {
            if (data == "quit")
            {
                break;
            }

            string encrypted = dhe.Encrypt(data, keyStr);
            string resp;

            client.sendMsg(resp, encrypted);
            string decrypted = dhe.Decrypt(resp, keyStr);
            cout << "receive server response: " << decrypted << endl;
        }

        transport->close();
    }
    catch (...)
    {
    }
}
