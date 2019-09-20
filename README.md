轻量级代理
======
纯go实现的基于http，socks5代理,主要用于翻墙


使用方法
======
修改文件目录下的go_proxy.json配置文件：
-------
    {

    "Udp_timeout":60,                    //udp超时时间
    "Ulimit":1024000,                    //linux最大打开文件数(最大打开连接数)，取值范围0-1048576

    }


服务端
-------
任意linux系统
修改目录下的server.json配置文件

        {       
             "Servers": [         // 数组 可以配置多个
             
               {
                 "Tls": {
                   "On": true,                                           // 是否打开tls 
                   "Tcp_encrypt":false,                                  //tcp封装tls之前是否加密，需要与客户端一致
                   "Server_cert_path": "cert/serv/server.crt",           //服务器证书
                   "Server_private_key_path": "cert/serv/server.key",    //服务器私钥
                   "Client_cert_paths": [                                //客户端证书路径 只有添加证书的客户端才能正常连接
                     "cert/client/client.crt"
                   ]
                 },
                 "Listen_port": 9999,                                    //监听端口
                 "Enc_method": "chacha20",                               //加密方式，仅支持chacha20和aes-256-cfb
                 "Password": ""                                          //密码，必须为32个字符
               }
               
             ],
       
       }

执行             ./go_proxy -c server.json -s start 

重启(仅支持linux) ./go_proxy -s restart

停止(仅支持linux) ./go_proxy -s stop

或者需要后台运行(仅支持linux) ./go_proxy -c server.json --daemon 


如无意外 netstat -apn | grep LISTEN 能看到go_proxy进程监听的端口


客户端 本地代理
------

修改client.json，支持http和socks5，http不能代理ftp

       {
       
         "Clients": [    //数组 可配置多个
           {
             "Mode": "http",                    //模式 目前只支持http和socks5
             "Ipv6": true,                      //是否打开ipv6支持 需要服务器支持ipv6
             "Local_addr": "0.0.0.0:1234",      //本地监听地址 可以ip或域名
             "Server_addr": "1.2.3.4:1234",     //服务器地址
             "Enc_method": "chacha20",          //加密方式 
             "Password": "",                    //密码 必须32个字符
             "Local_dns_addr": "114.114.114.114:53",  //本地dns地址
             "Remote_dns_addr": "8.8.8.8:53",         //远程dns地址
             "Connection_max_payload": 100,           //单个远程链接最大负载
             "Domain_cache_time": 3600,               //dns缓存时间 秒 0则不换存
             "Udp_in_tcp": false,                     //是否用tcp发送udp包,仅socks5有效,且socks5 udp转发中不能分片,即socks5 udp FRAG字段必需为0，否则丢弃
             "Tls": {                                 
               "On": true,                           //是否打开tls
               "Server_name":"ydx.com",              //证书域名，空则使用 Server_addr
               "Tcp_encrypt": false,                 //tcp封装tls之前是否加密，需要与服务端一致
               "Root_cert_path": "cert/serv/root.crt",  //服务器根证书
               "Client_cert": [                         //客户端证书 多个则随机选一个
                 {
                   "Cert": "cert/client/client.crt",           //证书
                   "Private_key": "cert/client/client.key"     //私钥
                 }
       
               ]
             }
           },
          
         ],
       
     
       }

china_domain    用于排除国内域名,来源于项目 https://github.com/felixonmars/dnsmasq-china-list

china_ipv4      为中国大陆ip段，用于排除国内ip，来源于项目 https://github.com/17mon/china_ip_list

ipv6_white_list 不走代理的ipv6地址

执行             ./go_proxy -c client.json -s start --china-ipv4=china_ipv4 --china-domain=china_domain --ipv6-white-list=ipv6_white_list

重启(仅支持linux) ./go_proxy -s restart

停止(仅支持linux) ./go_proxy -s stop

或者需要后台运行(仅支持linux) ./go_proxy -c client.json --daemon --china-ipv4=china_ipv4 --china-domain=china_domain --ipv6-white-list=ipv6_white_list

然后在系统代理或者一些浏览器插件上代理设置为对应ip和端口

关于证书
-------
开启tls会进行双向校验，因此需要生成服务端与客户端的私钥与自签证书。

服务端需要自身证书与私钥，并添加客户端的证书作为校验(服务端证书链不能超过2级)。

客户端需要自身证书与私钥，并添加服务端的根证书信任(客户端证书链只能一级)。

cert目录下包含生成证书的脚本。

切到cert/serv目录下修改cert/serv/serv.cnf 中 alt_names.IP.1 改为服务器ip 或者 alt_names.NDS.1改为服务器域名，
这里的值要与Client.Server_addr一致

执行 bash create_serv_crt.sh 生成证书与私钥，其中root.crt是根证书，server.crt 和 server.key 是服务器证书与私钥

切到cert/client目录下 执行 bash create_cli_crt.sh 生成单个客户端证书与私钥

bash create_cli_crt.sh ${n}  批量生成 ${n}为整数



 
