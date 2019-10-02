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
             "Mode": "http",                    //模式 本地代理只支持http和socks5
             "Ipv6": true,                      //是否打开ipv6支持 需要服务器支持ipv6
             "Local_addr": "0.0.0.0:1234",      //本地监听地址 可以ip或域名
             "Server_addr": "1.2.3.4:1234",     //服务器地址
             "Enc_method": "chacha20",          //加密方式 
             "Password": "",                    //密码 必须32个字符
             "Local_dns_addr": "114.114.114.114:53",  //本地dns地址
             "Remote_dns_addr": "8.8.8.8:53",         //远程dns地址
             "Connection_max_payload": 10,           //单个远程链接最大负载
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


客户端 iptables透明代理 仅支持linux  
------
仅支持ipv4,且建议在64位机运行(由于我没有找到ipv6 udp 使用tproxy重定向后获取目的端口的方法(除非用原始套接字),故不支持ipv6,如果你知道,希望能告诉我或者提交pull request)
一般来说，作为路由至少要有两块网卡，可以是虚拟机也可以是树梅派。假设eth0为连接公网接口，br0为局域网接口,ip为192.168.1.1。
首先确保linux内核不低于2.6且安装了dnsmasq，iptables，ipset，且通过br0接口的机器能正常访问公网

通常，linux做路由器要打开ip转发：

编辑/etc/sysctl.conf
添加两行

    net.ipv4.ip_forward=1
    net.ipv4.conf.br0.route_localnet=1   // 这条用于将外部网卡路由到本地 br0要改为局域网接口 或者改为all(net.ipv4.conf.all.route_localnet=1)

命令行执行

    sysctl -p

然后iptables设置：

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

这样连接到br0的机器应该能访问公网了(这里省略dhcp等地址获取问题，没有配置dhcp服务器需要手动设置ip地址)。


修改client.json

     {
         "Clients": [    
            {
              "Mode": "iptables",                      //模式iptables
              "Local_port": 3939,                      // 本地监听端口
              "Server_addr": "ydx.com:4343",           //服务器地址
              "Enc_method": "chacha20",                //加密方式 
              "Password": "",                          //密码 必须32个字符
              "Remote_dns_addr": "8.8.4.4:53",         //远程dns地址
              "Connection_max_payload": 10,           //单个远程链接最大负载
              "Udp_in_tcp": false,                     //是否用tcp发送udp包
              "Tls": {
                "On": true,                             //是否打开tls
                "Server_name":"ydx.com",                //证书域名，空则使用 Server_addr
                "Tcp_encrypt": false,                   //tcp封装tls之前是否加密，需要与服务端一致
                "Root_cert_path": "cert/serv/root.crt",  //服务器根证书
                "Client_cert": [                         //客户端证书 多个则随机选一个
                  {
                    "Cert": "cert/client/client.crt",        //证书
                    "Private_key": "cert/client/client.key"  //私钥
                  }
        
                ]
              }
            }
      
         ]
    }

首先修改dnsmasq配置文件：

编辑/etc/dnsmasq.conf：

    取消no-resolv 和 bind-interfaces 注释
    
    取消listen-address注释 并修改为 listen-address=127.0.0.1,192.168.1.1    //192.168.1.1 为br0网关地址 这里一定不要绑定为0.0.0.0,并且不要有监听"0.0.0.0"或者"::"地址的udp套接字
    
    在最后添加

    server=127.0.0.1#9999      //上游dns地址 9999修改为客户端监听的端口

    conf-dir=/etc/dnsmasq.d/   //dnsmasq规则文件的路径

复制dnsmasq_china_list.conf到dnsmasq规则文件的路径 来源于项目: https://github.com/felixonmars/dnsmasq-china-list

在这列表中的域名都会使用指定地址解析，其他域名都会使用上游地址解析。可以自行添加，格式：server=/域名/dns地址。

运行dnsmasq服务

    systemctl start dnsmasq

局域网的主机dns地址设置为192.168.1.1,则可以实现国内域名白名单

添加中国ip到ipset中:

在go_proxy2目录下执行(bash环境 不同shell语法不同)

    ipset create cn_ipv4 hash:net

    for line in `cat china_ipv4`; do ipset add cn_ipv4 $line; done;

添加局域网和服务端地址到ipset：

    ipset create local hash:net

    ipset add local 127.0.0.0/8

    ipset add local 192.168.0.0/16

    ipset add local 169.254.0.0/16

    ipset add local 172.16.0.0/12

    ipset add local 10.0.0.0/8
    
    ipset add local 224.0.0.0/4
    
    ipset add local 255.255.255.255/32
    
    ipset add local 99.99.99.99/32          //99.99.99.99换成服务端ip



创建新链:

    iptables -t nat -N GO_PROXY


局域网和服务端地址return,非中国ip重定向到本地：

    iptables -t nat -A GO_PROXY -p tcp -m set  --match-set local dst -j RETURN

    iptables -t nat -A GO_PROXY -p tcp -m set  --match-set cn_ipv4 dst -j RETURN

    iptables -t nat -A GO_PROXY -p tcp  -j DNAT --to 127.0.0.1:9999               //9999改成客户端本地监听的端口

    iptables -t nat -A PREROUTING -p tcp -j GO_PROXY

    iptables -t nat -A OUTPUT -p tcp -j GO_PROXY


udp中继：

    iptables -t mangle -N GO_PROXY

    iptables -t mangle -A GO_PROXY -p udp -m set  --match-set local dst -j RETURN

    iptables -t mangle -A GO_PROXY -p udp -m set  --match-set cn_ipv4  dst -j RETURN

    iptables -t mangle -A GO_PROXY -p udp -j TPROXY --on-ip 127.0.0.1 --on-port 9999 --tproxy-mark 0x1/0x1      //9999改成客户端本地监听的端口

    iptables -t mangle -A PREROUTING -p udp -j GO_PROXY

添加路由策略：

    ip rule add fwmark  0x1/0x1 table 100

    ip route add local default dev lo table 100


所有路由到192.168.1.1的设备理应都会通过代理访问


关于证书
-------
开启tls会进行双向校验，因此需要生成服务端与客户端的私钥与自签证书。

服务端需要自身证书与私钥，并添加客户端的证书作为校验(服务端证书链不能超过2级,使用tls不是出于安全考虑而是加密和混淆流量)。

客户端需要自身证书与私钥，并添加服务端的根证书信任(客户端证书链只能一级)。

cert目录下包含生成证书的脚本。

切到cert/serv目录下修改cert/serv/serv.cnf 中 alt_names.IP.1 改为服务器ip 或者 alt_names.NDS.1改为服务器域名，
这里的值要与Client.Server_addr一致

执行 bash create_serv_crt.sh 生成证书与私钥，其中root.crt是根证书，server.crt 和 server.key 是服务器证书与私钥

切到cert/client目录下 执行 bash create_cli_crt.sh 生成单个客户端证书与私钥

bash create_cli_crt.sh ${n}  批量生成 ${n}为整数



 
