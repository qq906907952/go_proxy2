package conn

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	. "go_proxy/util"
	"math"
)

type ClientConfig struct {
	Id                     uint16
	Ipv6                   bool
	Domain_cache_time      int64
	Connection_max_payload int
	Mode                   string

	Local_dns_addr string

	Local_addr string
	Local_ip string
	Local_port int
	Zone_id    uint32

	Front_proxy struct {
		User_front_proxy   bool
		Front_proxy_schema string
		Front_proxy_path   string
		Front_proxy_addr   string
		Auth_need          bool
		Username           string
		Passwd             string
	}

	Remoted_dns Addr

	Tcp_server_addr string
	Tcp_Server_Addr Addr

	Udp_server_addr string
	Udp_Server_Addr Addr

	Crypt Crypt_interface

	Udp_crypt Crypt_interface

	Tls_conf *tls.Config

	ConnectionHandler *ConnectionHandler

	Cn_domain_ip_map, Not_cn_domain_ip_map *sync.Map

	Idle_connection_remain_time int

	Udp_in_tcp bool
}

type ServConfig struct {
	Tcp_listen_port       int
	Udp_listen_port       int
	Tls_conf              *tls.Config
	Crypt                 Crypt_interface
	Udp_crypt             Crypt_interface
	ServConnectionHandler *ServerConnectionhandler
	Id                    uint16
}

func parse_local_string_addr(s string, conf *ClientConfig) (Addr, error) {
	addr, err := NewAddrFromString(s, conf.Ipv6)
	if err != nil {
		return nil, err
	}
	if addr.IsDomain() {
		ip, _type, err := Parse_local_domain(addr.String(), conf.Ipv6, conf.Local_dns_addr)
		if err != nil {
			return nil, err
		}
		if _type == Addr_type_ipv4 {
			addr, err = NewAddrFromString(net.IP(ip).String()+":"+strings.Split(addr.StringWithPort(), ":")[1], false)
		} else if _type == Addr_type_ipv6 {
			addr, err = NewAddrFromString(fmt.Sprintf("[%s]:%d", net.IP(ip).String(), addr.ToPortInt()), false)
		} else {
			panic("unknow error")
		}

		if err != nil {
			return nil, err
		}
		return addr, nil
	} else {
		return addr, nil
	}

}

func LoadClientConfig(client *Client, i uint16) (*ClientConfig, []string, error) {

	info := []string{}
	cli_conf := &ClientConfig{
		Id:         i,
		Ipv6:       client.Ipv6,
		Udp_in_tcp: client.Udp_in_tcp,
	}
	if client.Connection_max_payload > 65535 {
		cli_conf.Connection_max_payload = 65500
	} else if client.Connection_max_payload < 1 {
		cli_conf.Connection_max_payload = 1
	} else {
		cli_conf.Connection_max_payload = client.Connection_max_payload
	}

	//check mode
	client.Mode = strings.ToLower(client.Mode)
	if client.Mode != Http && client.Mode != Socks5 && client.Mode != Iptables {
		return nil, nil, errors.New("client mode can only http|socks5|iptables")
	}
	if client.Mode == Iptables && runtime.GOOS != "linux" {
		fmt.Fprintf(os.Stderr, "iptables mode only support on linux\r\n")
		os.Exit(1)
	}
	cli_conf.Mode = client.Mode
	if cli_conf.Mode == Iptables {
		cli_conf.Domain_cache_time = 0
	} else if client.Domain_cache_time != 0 && client.Domain_cache_time < 60 {
		cli_conf.Domain_cache_time = 60
	} else if client.Domain_cache_time > 24*60*60 {
		client.Domain_cache_time = 24 * 60 * 60
	} else {
		cli_conf.Domain_cache_time = client.Domain_cache_time
	}

	info = append(info, fmt.Sprintf("%-25s : %v", "mode ", cli_conf.Mode))
	info = append(info, fmt.Sprintf("%-25s : %v", "ipv6", cli_conf.Ipv6))
	info = append(info, fmt.Sprintf("%-25s : %v", "domain cache time", cli_conf.Domain_cache_time))
	info = append(info, fmt.Sprintf("%-25s : %v", "udp timeout", Config.Udp_timeout))
	if client.Mode != Http {
		info = append(info, fmt.Sprintf("%-25s : %v", "udp in tcp ", cli_conf.Udp_in_tcp))
	}

	//check local dns addr
	if cli_conf.Mode != Iptables {
		if client.Local_dns_addr != "" {
			addr, err := NewAddrFromString(client.Local_dns_addr, client.Ipv6)
			if err != nil {
				return nil, nil, errors.New("check local dns addr fail : " + err.Error())
			}
			if addr.IsDomain() {
				ip, err := net.ResolveIPAddr("ip", addr.String())
				if err != nil || len(ip.IP) == 0 {
					return nil, nil, errors.New("look up local dns addr fail : " + err.Error())
				}

				addr, err = NewAddrFromString(ip.String()+":"+strings.Split(addr.StringWithPort(), ":")[1], client.Ipv6)
				if err != nil {
					return nil, nil, errors.New("parse local dns ip fail : " + err.Error())
				}
			}

			cli_conf.Local_dns_addr = addr.StringWithPort()
			info = append(info, fmt.Sprintf("%-25s : %v", "local dns addr ", cli_conf.Local_dns_addr))
		} else {
			info = append(info, fmt.Sprintf("%-25s : %v", "local dns addr ", "use default dns addr"))
		}
	}

	// check local addr

	if cli_conf.Mode == Iptables {
		if client.Local_Port > 65535 || client.Local_Port < 1 {
			return nil, nil, errors.New("local port illegal")
		}
		cli_conf.Local_port = client.Local_Port
		info = append(info, fmt.Sprintf("%-25s : %v", "listen port ", cli_conf.Local_port))
		if client.Ipv6 {
			if client.Interface == "" {
				cli_conf.Zone_id = 0
				info = append(info, fmt.Sprintf("%-25s : %v", "interface", "not specific"))

			} else {
				i, err := net.InterfaceByName(client.Interface)
				if err != nil {
					return nil, nil, errors.New(err.Error())
				}
				cli_conf.Zone_id = uint32(i.Index)
				info = append(info, fmt.Sprintf("%-25s : %v", "interface",client.Interface))
			}
			info = append(info, fmt.Sprintf("%-25s : %v", "zone id", cli_conf.Zone_id))
		}
	} else {
		if client.Local_addr == "" {
			return nil, nil, errors.New("local addr is nil")
		}
		addr, err := parse_local_string_addr(client.Local_addr, cli_conf)
		if err != nil {
			return nil, nil, errors.New("check local addr fail : " + err.Error())
		}
		cli_conf.Local_addr = addr.StringWithPort()
		cli_conf.Local_ip = addr.String()
		cli_conf.Local_port=addr.ToPortInt()
		info = append(info, fmt.Sprintf("%-25s : %v", "local addr ", cli_conf.Local_addr))
	}

	// check front proxy
	if client.Front_proxy != "" {

		default_port:=map[string]int{
			Http:80,
			Socks5:1080,
		}

		url, err := url.Parse(client.Front_proxy)
		if err != nil {
			return nil, nil, errors.New("parse front proxy addr fail : " + err.Error())
		}
		sch := strings.ToLower(url.Scheme)
		if sch != Http && sch != Socks5  {

		}
		port := 0

		switch sch {
		case Http,Socks5:
			if url.Port() == "" {
				port = default_port[sch]
			} else {
				p, err := strconv.ParseInt(url.Port(), 10, 0)
				if err != nil {
					return nil, nil, err
				}
				port = int(p)
			}
			if sch!=Socks5{
				cli_conf.Front_proxy.Front_proxy_path=url.Path
			}

		default:
			return nil, nil, errors.New("front proxy proto not support")

		}

		addr,err:=parse_local_string_addr(fmt.Sprintf("%s:%d",url.Hostname(),port), cli_conf)
		if err!=nil{
			return nil, nil, errors.New(fmt.Sprintf("front proxy address parse fail: %s",err.Error()))
		}

		cli_conf.Front_proxy.User_front_proxy=true
		cli_conf.Front_proxy.Front_proxy_schema=url.Scheme
		cli_conf.Front_proxy.Front_proxy_addr=addr.StringWithPort()

		if url.User.Username()!=""{
			cli_conf.Front_proxy.Auth_need=true
			cli_conf.Front_proxy.Username=url.User.Username()
			p,ok:=url.User.Password()
			if ok{
				cli_conf.Front_proxy.Passwd=p
				info = append(info, fmt.Sprintf("%-25s : %v", "front proxy", fmt.Sprintf(
					"%s://%s:%s@%s%s",
					cli_conf.Front_proxy.Front_proxy_schema,
					cli_conf.Front_proxy.Username,
					cli_conf.Front_proxy.Passwd,
					cli_conf.Front_proxy.Front_proxy_addr,
					cli_conf.Front_proxy.Front_proxy_path,
				)))
			}else{
				info = append(info, fmt.Sprintf("%-25s : %v", "front proxy", fmt.Sprintf(
					"%s://%s@%s%s",
					cli_conf.Front_proxy.Front_proxy_schema,
					cli_conf.Front_proxy.Username,
					cli_conf.Front_proxy.Front_proxy_addr,
					cli_conf.Front_proxy.Front_proxy_path,
				)))
			}
		}else{
			info = append(info, fmt.Sprintf("%-25s : %v", "front proxy", fmt.Sprintf(
				"%s://%s%s",
				cli_conf.Front_proxy.Front_proxy_schema,
				cli_conf.Front_proxy.Front_proxy_addr,
				cli_conf.Front_proxy.Front_proxy_path,
				)))
		}

	}

	//check server
	tcp_server_addr := strings.TrimRight(strings.TrimLeft(client.Tcp_server_addr, ""), "")
	udp_server_addr := strings.TrimRight(strings.TrimLeft(client.Udp_server_addr, ""), "")

	tcp_addr, err := parse_local_string_addr(tcp_server_addr, cli_conf)
	if err != nil {
		return nil, nil, errors.New("check tcp server addr faile : " + err.Error())
	}
	cli_conf.Tcp_Server_Addr = tcp_addr
	cli_conf.Tcp_server_addr = tcp_addr.StringWithPort()

	info = append(info, fmt.Sprintf("%-25s : %v", "tcp server addr ", cli_conf.Tcp_server_addr))

	if cli_conf.Mode != Http {
		udp_addr, err := parse_local_string_addr(udp_server_addr, cli_conf)
		if err != nil {
			return nil, nil, errors.New("check udp server addr faile : " + err.Error())
		}
		cli_conf.Udp_Server_Addr = udp_addr
		cli_conf.Udp_server_addr = udp_addr.StringWithPort()
		info = append(info, fmt.Sprintf("%-25s : %v", "udp server addr ", cli_conf.Udp_server_addr))
	}

	//check remote dns addr
	if client.Remote_dns_addr != "" {
		addr, err := NewAddrFromString(client.Remote_dns_addr, client.Ipv6)
		if err != nil {
			return nil, nil, errors.New("check remote dns addr fail : " + err.Error())
		}

		if addr.IsDomain() {
			ip, _type, err := Parse_local_domain(addr.String(), cli_conf.Ipv6, cli_conf.Local_dns_addr)
			if err != nil {
				return nil, nil, errors.New("look up remote dns addr ip fail : " + err.Error())
			}
			addr, err = NewAddrFromByte(ip, addr.ToPortByte(), _type)
			if err != nil {
				return nil, nil, errors.New("parse remote dns addr fail : " + err.Error())
			}
		}

		cli_conf.Remoted_dns = addr
		info = append(info, fmt.Sprintf("%-25s : %v", "remote dns addr ", addr.StringWithPort()))
	} else {
		cli_conf.Remoted_dns = nil
		info = append(info, fmt.Sprintf("%-25s : %v", "remote dns addr ", "use remote server default dns addr"))
	}

	//check crypt
	crypt, err := Get_crypt(client.Enc_method, client.Password)
	if err != nil {
		return nil, nil, errors.New("check crypt fail : " + err.Error())
	}

	cli_conf.Crypt = crypt
	cli_conf.Udp_crypt = crypt

	if client.Tls.On {

		cert_pool := x509.NewCertPool()
		root_cert, err := ioutil.ReadFile(client.Tls.Root_cert_path)
		if err != nil {
			return nil, nil, errors.New("server root cert check fail : " + err.Error())
		}

		cert_pool.AppendCertsFromPEM(root_cert)
		cert, err := tls.LoadX509KeyPair(client.Tls.Certificate, client.Tls.Private_key)
		if err != nil {
			return nil, nil, errors.New("load client cert fail : " + err.Error())
		}
		cli_conf.Tls_conf = &tls.Config{
			RootCAs:                cert_pool,
			ServerName:             tcp_addr.String(),
			Certificates:           []tls.Certificate{cert},
			MinVersion:             tls.VersionTLS13,
			SessionTicketsDisabled: true,
		}
		if client.Tls.Server_name != "" {
			cli_conf.Tls_conf.ServerName = client.Tls.Server_name
		}
		info = append(info, fmt.Sprintf("%-25s : %v", "tls server name ", cli_conf.Tls_conf.ServerName))

		if !client.Tls.Tcp_encrypt {
			cli_conf.Crypt = Get_none_crypt()
		}
		info = append(info, fmt.Sprintf("%-25s : %v", "tcp enc method ", cli_conf.Crypt.String()))
	} else {
		info = append(info, fmt.Sprintf("%-25s : %v", "tcp enc method ", cli_conf.Crypt.String()))
	}
	info = append(info, fmt.Sprintf("%-25s : %v", "udp enc method ", cli_conf.Udp_crypt.String()))
	info = append(info, fmt.Sprintf("%-25s : %v", "tls ", client.Tls.On))

	if cli_conf.Connection_max_payload < 64 {
		cli_conf.Idle_connection_remain_time = 8
	} else {
		cli_conf.Idle_connection_remain_time = int(64.0 / math.Sqrt(float64(cli_conf.Connection_max_payload)))
	}

	info = append(info, fmt.Sprintf("%-25s : %v", "max connection payload", cli_conf.Connection_max_payload))
	info = append(info, fmt.Sprintf("%-25s : %v", "idle conn reamin sec", cli_conf.Idle_connection_remain_time))

	cli_conf.ConnectionHandler = NewClientConnectionHandler(cli_conf)

	if cli_conf.Domain_cache_time != 0 {
		cli_conf.Cn_domain_ip_map = &sync.Map{}
		cli_conf.Not_cn_domain_ip_map = &sync.Map{}
		go domain_cache_clean_scheduel(cli_conf.Cn_domain_ip_map, client.Domain_cache_time)
		go domain_cache_clean_scheduel(cli_conf.Not_cn_domain_ip_map, client.Domain_cache_time)

	}

	return cli_conf, info, nil

}

func LoadServerConfig(serve *Serve, i uint16) (*ServConfig, []string, error) {
	s := &ServConfig{}
	s.Tcp_listen_port = serve.Tcp_listen_port
	s.Udp_listen_port = serve.Udp_listen_port
	s.Id = i
	info := []string{fmt.Sprintf("%-25s : %v", "tcp listen port", s.Tcp_listen_port)}
	info = append(info, fmt.Sprintf("%-25s : %v", "udp listen port", s.Udp_listen_port))

	crypt, err := Get_crypt(serve.Enc_method, serve.Password)
	if err != nil {
		return nil, nil, err
	}
	s.Crypt = crypt
	s.Udp_crypt = crypt

	if serve.Tls.On {
		if len(serve.Tls.Client_certs) == 0 {
			return nil, nil, errors.New("client cert is nil")
		}

		cert, err := tls.LoadX509KeyPair(serve.Tls.Server_cert, serve.Tls.Server_private_key)
		if err != nil {
			return nil, nil, errors.New("load server cert and private key exception:" + err.Error())
		}

		cli_cert := x509.NewCertPool()
		for _, v := range serve.Tls.Client_certs {
			b, err := ioutil.ReadFile(v)
			if err != nil {
				log.Fatal("load client cert fail : " + err.Error())
			}
			cli_cert.AppendCertsFromPEM(b)

		}

		s.Tls_conf = &tls.Config{
			Certificates:           []tls.Certificate{cert},
			ClientAuth:             tls.RequireAndVerifyClientCert,
			ClientCAs:              cli_cert,
			MinVersion:             tls.VersionTLS13,
			SessionTicketsDisabled: true,
		}
		if !serve.Tls.Tcp_encrypt {
			s.Crypt = Get_none_crypt()
		}
		info = append(info, fmt.Sprintf("%-25s : %v", "tcp enc method ", s.Crypt.String()))
	} else {
		info = append(info, fmt.Sprintf("%-25s : %v", "tcp enc method ", s.Crypt.String()))
	}
	info = append(info, fmt.Sprintf("%-25s : %v", "udp enc method ", s.Udp_crypt.String()))
	info = append(info, fmt.Sprintf("%-25s : %v", "tls ", serve.Tls.On))

	s.ServConnectionHandler = ServerConnectionhandler{}.new_server_connection_handler(s)
	return s, info, nil
}

func domain_cache_clean_scheduel(domian_map *sync.Map, domian_cache_time int64) {
	var clean = func() {
		domian_map.Range(func(key, value interface{}) bool {
			if time.Now().Unix()-value.(*Domain_record).Time >= domian_cache_time {
				if Verbose_info {
					Print_verbose("domain %s (ip:%s) cache clean", key, net.IP(value.(*Domain_record).Ip).String())
				}
				domian_map.Delete(key)
			}
			return true
		})
	}

	time.Sleep(time.Duration(float64(domian_cache_time)*1.5) * time.Second)
	clean()

	for {
		time.Sleep(time.Duration(domian_cache_time/2) * time.Second)
		clean()
	}
}
