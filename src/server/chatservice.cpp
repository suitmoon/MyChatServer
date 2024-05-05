#include "chatservice.hpp"
#include "public.hpp"
#include <muduo/base/Logging.h>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <iostream>
#include <string>
#include <stdio.h>

using namespace std;
using namespace muduo;

// 获取单例对象的接口函数
ChatService *ChatService::instance()
{
    static ChatService service;
    return &service;
}

void ChatService::decryptWithPrivateKey(const string &name, const string &encryptedData, string &pwd)
{
    // 将 PEM 格式的私钥字符串加载到内存中
    BIO* bio = BIO_new_mem_buf(KeyMap[name].c_str(), -1);
    RSA* privateKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    // 计算 RSA 私钥解密后的最大长度
    int decryptedSize = RSA_size(privateKey);
    std::vector<unsigned char> decrypted(decryptedSize);
    // 使用 RSA 私钥执行解密操作
    int result = RSA_private_decrypt(encryptedData.size(), reinterpret_cast<const unsigned char*>(encryptedData.data()),
                                      decrypted.data(), privateKey, RSA_PKCS1_PADDING);
    RSA_free(privateKey);
    pwd = string(decrypted.begin(), decrypted.begin() + result);
}

// 注册消息以及对应的Handler回调操作
ChatService::ChatService()
{
    // 用户基本业务管理相关事件处理回调注册
    _msgHandlerMap.insert({LOGIN_MSG, std::bind(&ChatService::login, this, _1, _2, _3)});
    _msgHandlerMap.insert({LOGINOUT_MSG, std::bind(&ChatService::loginout, this, _1, _2, _3)});
    _msgHandlerMap.insert({REG_MSG, std::bind(&ChatService::reg, this, _1, _2, _3)});
    _msgHandlerMap.insert({ONE_CHAT_MSG, std::bind(&ChatService::oneChat, this, _1, _2, _3)});
    _msgHandlerMap.insert({ADD_FRIEND_MSG, std::bind(&ChatService::addFriend, this, _1, _2, _3)});

    // 群组业务管理相关事件处理回调注册
    _msgHandlerMap.insert({CREATE_GROUP_MSG, std::bind(&ChatService::createGroup, this, _1, _2, _3)});
    _msgHandlerMap.insert({ADD_GROUP_MSG, std::bind(&ChatService::addGroup, this, _1, _2, _3)});
    _msgHandlerMap.insert({GROUP_CHAT_MSG, std::bind(&ChatService::groupChat, this, _1, _2, _3)});

    //返回公钥
    _msgHandlerMap.insert({RSA_public, std::bind(&ChatService::get_RSA_public, this, _1, _2, _3)});    

    // 连接redis服务器
    if (_redis.connect())
    {
        // 设置上报消息的回调
        _redis.init_notify_handler(std::bind(&ChatService::handleRedisSubscribeMessage, this, _1, _2));
    }
}

// 服务器异常，业务重置方法
void ChatService::reset()
{
    // 把online状态的用户，设置成offline
    _userModel.resetState();
}

// 获取消息对应的处理器
MsgHandler ChatService::getHandler(int msgid)
{
    // 记录错误日志，msgid没有对应的事件处理回调
    auto it = _msgHandlerMap.find(msgid);
    if (it == _msgHandlerMap.end())
    {
        // 返回一个默认的处理器，空操作
        return [=](const TcpConnectionPtr &conn, json &js, Timestamp) {
            LOG_ERROR << "msgid:" << msgid << " can not find handler!";
        };
    }
    else
    {
        return _msgHandlerMap[msgid];
    }
}

// 处理登录业务  id  pwd   pwd
void ChatService::login(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    
    //int fd = js["fd"].get<int>();
    int id = js["id"].get<int>();
    string password;
    base64_decode(js["password"],password);
    //std::cout<<"base64解密后密码"<<password<<endl;
    //std::cout<<"----------分界线"<<endl;
    string pwd = KeyMap[conn->name()];
   // std::cout<<"非对称密钥"<<conn->name()<<endl;
    //std::cout<<"----------遍历map分界线"<<endl;
        // 使用迭代器遍历
    //for (auto it = KeyMap.begin(); it != KeyMap.end(); ++it) {
    //    std::cout << "Key: " << it->first << ", Value: " << it->second << std::endl;
   // }
    //std::cout<<"----------密钥分界线"<<endl;
    decryptWithPrivateKey(conn->name(), password, pwd);
    //std::cout<<"非对称解密后密码"<<pwd<<endl;

    User user = _userModel.query(id);
    if (user.getId() == id && user.getPwd() == pwd)
    {
        if (user.getState() == "online")
        {
            // 该用户已经登录，不允许重复登录
            json response;
            response["msgid"] = LOGIN_MSG_ACK;
            response["errno"] = 2;
            response["errmsg"] = "this account is using, input another!";
            
            conn->send(aesencryptedjson(response.dump()));
        }
        else
        {
            // 登录成功，记录用户连接信息
            {
                lock_guard<mutex> lock(_connMutex);
                _userConnMap.insert({id, conn});
            }

            // id用户登录成功后，向redis订阅channel(id)
            _redis.subscribe(id); 

            // 登录成功，更新用户状态信息 state offline=>online
            user.setState("online");
            _userModel.updateState(user);

            json response;
            response["msgid"] = LOGIN_MSG_ACK;
            response["errno"] = 0;
            response["id"] = user.getId();
            response["name"] = user.getName();
            // 查询该用户是否有离线消息
            vector<string> vec = _offlineMsgModel.query(id);
            if (!vec.empty())
            {
                response["offlinemsg"] = vec;
                // 读取该用户的离线消息后，把该用户的所有离线消息删除掉
                _offlineMsgModel.remove(id);
            }

            // 查询该用户的好友信息并返回
            vector<User> userVec = _friendModel.query(id);
            if (!userVec.empty())
            {
                vector<string> vec2;
                for (User &user : userVec)
                {
                    json js;
                    js["id"] = user.getId();
                    js["name"] = user.getName();
                    js["state"] = user.getState();
                    vec2.push_back(js.dump());
                }
                response["friends"] = vec2;
            }

            // 查询用户的群组信息
            vector<Group> groupuserVec = _groupModel.queryGroups(id);
            if (!groupuserVec.empty())
            {
                // group:[{groupid:[xxx, xxx, xxx, xxx]}]
                vector<string> groupV;
                for (Group &group : groupuserVec)
                {
                    json grpjson;
                    grpjson["id"] = group.getId();
                    grpjson["groupname"] = group.getName();
                    grpjson["groupdesc"] = group.getDesc();
                    vector<string> userV;
                    for (GroupUser &user : group.getUsers())
                    {
                        json js;
                        js["id"] = user.getId();
                        js["name"] = user.getName();
                        js["state"] = user.getState();
                        js["role"] = user.getRole();
                        userV.push_back(js.dump());
                    }
                    grpjson["users"] = userV;
                    groupV.push_back(grpjson.dump());
                }

                response["groups"] = groupV;
            }
            
            conn->send(aesencryptedjson(response.dump()));
            //conn->send(response.dump());
        }
    }
    else
    {
        // 该用户不存在，用户存在但是密码错误，登录失败
        json response;
        response["msgid"] = LOGIN_MSG_ACK;
        response["errno"] = 1;
        response["errmsg"] = "id or password is invalid!";
        conn->send(aesencryptedjson(response.dump()));
    }
}

// 处理注册业务  name  password
void ChatService::reg(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    string name = js["name"];
    string pwd = js["password"];

    User user;
    user.setName(name);
    user.setPwd(pwd);
    bool state = _userModel.insert(user);
    if (state)
    {
        // 注册成功
        json response;
        response["msgid"] = REG_MSG_ACK;
        response["errno"] = 0;
        response["id"] = user.getId();
        conn->send(aesencryptedjson(response.dump()));
    }
    else
    {
        // 注册失败
        json response;
        response["msgid"] = REG_MSG_ACK;
        response["errno"] = 1;
        conn->send(aesencryptedjson(response.dump()));
    }
}

// 处理注销业务
void ChatService::loginout(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    int userid = js["id"].get<int>();

    {
        lock_guard<mutex> lock(_connMutex);
        auto it = _userConnMap.find(userid);
        if (it != _userConnMap.end())
        {
            _userConnMap.erase(it);
        }
    }

    // 用户注销，相当于就是下线，在redis中取消订阅通道
    _redis.unsubscribe(userid); 

    // 更新用户的状态信息
    User user(userid, "", "", "offline");
    _userModel.updateState(user);
}

// 处理客户端异常退出
void ChatService::clientCloseException(const TcpConnectionPtr &conn)
{
    User user;
    {
        lock_guard<mutex> lock(_connMutex);
        for (auto it = _userConnMap.begin(); it != _userConnMap.end(); ++it)
        {
            if (it->second == conn)
            {
                // 从map表删除用户的链接信息
                user.setId(it->first);
                _userConnMap.erase(it);
                break;
            }
        }
    }

    // 用户注销，相当于就是下线，在redis中取消订阅通道
    _redis.unsubscribe(user.getId()); 

    // 更新用户的状态信息
    if (user.getId() != -1)
    {
        user.setState("offline");
        _userModel.updateState(user);
    }
}

// 一对一聊天业务
void ChatService::oneChat(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    int toid = js["toid"].get<int>();

    {
        lock_guard<mutex> lock(_connMutex);
        auto it = _userConnMap.find(toid);
        if (it != _userConnMap.end())
        {
            // toid在线，转发消息   服务器主动推送消息给toid用户
            
            it->second->send(aesencryptedjson(js.dump()));
            return;
        }
    }

    // 查询toid是否在线 
    User user = _userModel.query(toid);
    if (user.getState() == "online")
    {
        _redis.publish(toid, aesencryptedjson(js.dump()));
        return;
    }

    // toid不在线，存储离线消息
    _offlineMsgModel.insert(toid, js.dump());
}

// 添加好友业务 msgid id friendid
void ChatService::addFriend(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    int userid = js["id"].get<int>();
    int friendid = js["friendid"].get<int>();

    // 存储好友信息
    _friendModel.insert(userid, friendid);
}

// 创建群组业务
void ChatService::createGroup(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    int userid = js["id"].get<int>();
    string name = js["groupname"];
    string desc = js["groupdesc"];

    // 存储新创建的群组信息
    Group group(-1, name, desc);
    if (_groupModel.createGroup(group))
    {
        // 存储群组创建人信息
        _groupModel.addGroup(userid, group.getId(), "creator");
    }
}

// 加入群组业务
void ChatService::addGroup(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    int userid = js["id"].get<int>();
    int groupid = js["groupid"].get<int>();
    _groupModel.addGroup(userid, groupid, "normal");
}

// 群组聊天业务
void ChatService::groupChat(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    int userid = js["id"].get<int>();
    int groupid = js["groupid"].get<int>();
    vector<int> useridVec = _groupModel.queryGroupUsers(userid, groupid);

    lock_guard<mutex> lock(_connMutex);
    for (int id : useridVec)
    {
        auto it = _userConnMap.find(id);
        if (it != _userConnMap.end())
        {
            // 转发群消息
            it->second->send(aesencryptedjson(js.dump()));
        }
        else
        {
            // 查询toid是否在线 
            User user = _userModel.query(id);
            if (user.getState() == "online")
            {
                _redis.publish(id, aesencryptedjson(js.dump()));
            }
            else
            {
                // 存储离线群消息
                _offlineMsgModel.insert(id, aesencryptedjson(js.dump()));
            }
        }
    }
}

// 从redis消息队列中获取订阅的消息
void ChatService::handleRedisSubscribeMessage(int userid, string msg)
{
    lock_guard<mutex> lock(_connMutex);
    auto it = _userConnMap.find(userid);
    if (it != _userConnMap.end())
    {
        it->second->send(msg);
        return;
    }

    // 存储该用户的离线消息
    _offlineMsgModel.insert(userid, msg);
}

//base64编码
void ChatService::base64_decode(const std::string &encoded, std::string &pwd)
{
    // 创建 BIO 对象并将 Base64 编码的数据写入其中
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new_mem_buf(encoded.c_str(), -1);
    bio = BIO_push(b64, bio);

    // 创建缓冲区来存储解码后的数据
    const int maxlen = 1024;
    char outbuf[maxlen];
    memset(outbuf, 0, sizeof(outbuf));

    // 执行解码操作
    int len = BIO_read(bio, outbuf, encoded.length());
    pwd = string(outbuf, len);
}

//获取公钥并且存储私钥
void ChatService::get_RSA_public(const TcpConnectionPtr &conn, json &js, Timestamp time){
    
    
    //发送公钥  非对称加密
    // 生成 RSA 密钥对并提取公钥
    RSA* keypair = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(keypair, 2048, e, NULL);
    BN_free(e);

    RSA* pubkey = RSAPublicKey_dup(keypair);

    // 将公钥转换为字符串
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, pubkey);
    char* buffer;
    long length = BIO_get_mem_data(bio, &buffer);
    string publicKeyStr(buffer, length);
    RSA* privkey = RSAPrivateKey_dup(keypair);
    json jsonkey;
    jsonkey["msgid"] = RSA_public_ACK;
    jsonkey["key"] = publicKeyStr;
    int fd = ++counter;
    jsonkey["fd"] = fd;    
    
    conn->send(aesencryptedjson(jsonkey.dump()));
    
    // 将私钥转换为字符串
    BIO* bio_private = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio_private, keypair, NULL, NULL, 0, NULL, NULL);
    char* buffer_private;
    long length_private = BIO_get_mem_data(bio_private, &buffer_private);
    string privateKeyStr(buffer_private, length_private);

    KeyMap[conn->name()] = privateKeyStr;
    


    
}

// 对称加密
string ChatService::aesencryptedjson(const string& plaintext){
    unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    unsigned char iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    int plaintext_len = plaintext.size();
    int max_ciphertext_len = plaintext_len + AES_BLOCK_SIZE; // Allow space for padding
    unsigned char* ciphertext = new unsigned char[max_ciphertext_len];

    int actual_ciphertext_len;
    EVP_EncryptUpdate(ctx, ciphertext, &actual_ciphertext_len, (unsigned char*)plaintext.c_str(), plaintext_len);

    int final_ciphertext_len;
    EVP_EncryptFinal_ex(ctx, ciphertext + actual_ciphertext_len, &final_ciphertext_len);

    actual_ciphertext_len += final_ciphertext_len;

    // Convert the ciphertext to a hexadecimal string
    string ciphertext_hex;
    for(int i = 0; i < actual_ciphertext_len; i++)
    {
        char hex[3];
        sprintf(hex, "%02x", ciphertext[i]);
        ciphertext_hex += hex;
    }

    delete[] ciphertext;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_hex;
}


