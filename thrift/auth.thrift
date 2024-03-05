
struct Token {
1: string prime;
2: string generator;
3: string publicKey;
}

struct AuthReq{
1:Token token
}

struct AuthResp{
1:string publicKey
}

service Comm {
    AuthResp auth(1:AuthReq req),
             string sendMsg(1:string msg)
}
