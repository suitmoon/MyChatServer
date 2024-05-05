#include "chatserver.hpp"
#include "json.hpp"
#include "chatservice.hpp"

#include <iostream>
#include <functional>
#include <string>
#include <openssl/aes.h>
using namespace std;
using namespace placeholders;
using json = nlohmann::json;

// 初始化聊天服务器对象
ChatServer::ChatServer(EventLoop *loop,
                       const InetAddress &listenAddr,
                       const string &nameArg)
    : _server(loop, listenAddr, nameArg), _loop(loop),
    key{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
      iv{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
{
    // 注册链接回调
    _server.setConnectionCallback(std::bind(&ChatServer::onConnection, this, _1));

    // 注册消息回调
    _server.setMessageCallback(std::bind(&ChatServer::onMessage, this, _1, _2, _3));

    // 设置线程数量
    _server.setThreadNum(4);
}

// 启动服务
void ChatServer::start()
{
    _server.start();
}

// 上报链接相关信息的回调函数
void ChatServer::onConnection(const TcpConnectionPtr &conn)
{
    // 客户端断开链接
    if (!conn->connected())
    {
        ChatService::instance()->clientCloseException(conn);
        conn->shutdown();
    }
}

// 上报读写事件相关信息的回调函数
void ChatServer::onMessage(const TcpConnectionPtr &conn,
                           Buffer *buffer,
                           Timestamp time)
{
    //  服务器收到数据
    string ciphertext_hex = buffer->retrieveAllAsString();
    cout<<"服务器收到"<<ciphertext_hex<<endl;
    // Convert the ciphertext from a hexadecimal string to binary
    int ciphertext_len = ciphertext_hex.size() / 2;
    unsigned char* ciphertext = new unsigned char[ciphertext_len];
    for(int i = 0; i < ciphertext_len; i++)
    {
        unsigned int temp;
        sscanf(ciphertext_hex.substr(2*i, 2).c_str(), "%02x", &temp);
        ciphertext[i] = temp;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    int max_plaintext_len = ciphertext_len;
    unsigned char* plaintext = new unsigned char[max_plaintext_len];

    int actual_plaintext_len;
    EVP_DecryptUpdate(ctx, plaintext, &actual_plaintext_len, ciphertext, ciphertext_len);

    int final_plaintext_len;
    EVP_DecryptFinal_ex(ctx, plaintext + actual_plaintext_len, &final_plaintext_len);

    actual_plaintext_len += final_plaintext_len;

    // Convert the plaintext to a string
    string plaintext_str((char*)plaintext, actual_plaintext_len);

    delete[] plaintext;
    delete[] ciphertext;
    EVP_CIPHER_CTX_free(ctx);

    
    cout<<"服务器解密后数据"<<plaintext_str<<endl;
    // 数据的反序列化
    json js = json::parse(plaintext_str);
    // 达到的目的：完全解耦网络模块的代码和业务模块的代码
    // 通过js["msgid"] 获取=》业务handler=》conn  js  time
    auto msgHandler = ChatService::instance()->getHandler(js["msgid"].get<int>());
    // 回调消息绑定好的事件处理器，来执行相应的业务处理
    msgHandler(conn, js, time);
}