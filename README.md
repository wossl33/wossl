## <p align=center>OpenSSL管理平台</p>
### 简介
OpenSSL管理平台为OpenSSL操作提供可视化的界面，方便快捷地完成对称算法、哈希校验、非对称算法、证书管理、SSL安全等操作。
##### 功能模块：
- 对称算法：AES、DES、Triple DES。
- 哈希校验：MD2、MD4、MD5、SHA1、SHA224、SHA256、SHA384、SHA512、RIPEMD、RIPEMD160、HMAC。
- 非对称算法：公私钥的加解密、公钥的解析提取、公私钥对的生成以及加密私钥的密码修改等。
- 证书工具：证书查看、CSR查看、CSR生成、私钥校验、证书格式转换、自签名证书生成。
- SSL检测：握手过程探测、协议/加密套件、SSL常见漏洞扫描、SSL健康检查等。
##### 开发环境：
基于Python2.7，具体依赖库请参考requirements或pip install requirements在线安装。
### 预览
![预览1](https://gitee.com/uploads/images/2017/1225/181036_9f54bd3f_1700467.png "预览1")
![预览2](https://gitee.com/uploads/images/2017/1225/181103_37ea20ce_1700467.png "预览2")
![预览3](https://gitee.com/uploads/images/2017/1225/181114_496249dd_1700467.png "预览3")
### 项目部署
##### 测试环境
切换至工作目录,运行python run.py
##### 生产环境
推荐：nginx + gunicorn + flask
<br>例如Centos 7.0下，建立系统服务wossld.service：
```
[Unit]
Description=Gunicorn Demo
After=network.target

[Service]
User=root
Group=root
PIDFile=/tmp/gunicorn.pid
WorkingDirectory=/root/wossl 项目路径
ExecStart=/usr/bin/gunicorn -c wsgi_config.py wsgi:app
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target 
```
<br>服务启动：service wossld start
<br>服务停止：service wossld stop
<br>flask生产环境部署请参考：http://docs.jinkan.org/docs/flask/deploying/wsgi-standalone.html
##### 获取客户端IP:
views.py:
```
# 首页
@app.route('/')
def index():
    # 测试环境下获取客户端IP
    client_ip=request.remote_addr
    # 生产环境下获取客户端IP
    '''
    if request.headers['X-Real-IP']:
        client_ip=request.headers['X-Real-IP']
    else:
        client_ip=request.headers['X-Forwarded-For']
    '''
    return render_template('index.html',client_ip=client_ip)
```
