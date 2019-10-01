package conn

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
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
	Local_port int

	Front_proxy_schema string
	Front_proxy_addr   string

	Remoted_dns Addr

	Server_addr string
	Server_Addr Addr

	Crypt Crypt_interface

	Udp_crypt Crypt_interface

	Tls_conf *tls.Config

	Client_cert []tls.Certificate

	ConnectionHandler *ConnectionHandler

	Cn_domain_ip_map, Not_cn_domain_ip_map *sync.Map

	Idle_connection_remain_time int

	Udp_in_tcp bool
}

type ServConfig struct {
	Listen_port           int
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

	if cli_conf.Mode == Iptables {
		cli_conf.Ipv6 = false
		cli_conf.Domain_cache_time = 0
	} else if client.Domain_cache_time != 0 && client.Domain_cache_time < 60 {
		cli_conf.Domain_cache_time = 60
	} else if client.Domain_cache_time > 24*60*60 {
		client.Domain_cache_time = 24 * 60 * 60
	} else {
		cli_conf.Domain_cache_time = client.Domain_cache_time
	}

	//check mode
	client.Mode = strings.ToLower(client.Mode)
	if client.Mode != Http && client.Mode != Socks5 && client.Mode != Iptables {
		return nil, nil, errors.New("client mode can only http|socks5|iptables")
	}
	if client.Mode == Iptables && runtime.GOOS != "linux" {
		fmt.Fprintf(os.Stderr, "iptables mode only support on linux")
		os.Exit(1)
	}
	cli_conf.Mode = client.Mode
	info = append(info, fmt.Sprintf("%-25s : %v", "mode ", cli_conf.Mode))

	info = append(info, fmt.Sprintf("%-25s : %v", "ipv6", cli_conf.Ipv6))
	info = append(info, fmt.Sprintf("%-25s : %v", "con max payload", cli_conf.Connection_max_payload))
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
	} else {
		if client.Local_addr == "" {
			return nil, nil, errors.New("local addr is nil")
		}
		addr, err := parse_local_string_addr(client.Local_addr, cli_conf)
		if err != nil {
			return nil, nil, errors.New("check local addr fail : " + err.Error())
		}
		cli_conf.Local_addr = addr.StringWithPort()
		info = append(info, fmt.Sprintf("%-25s : %v", "local addr ", cli_conf.Local_addr))
	}

	// check front proxy

	if client.Front_proxy != "" {
		//url,err:=url.Parse(client.Front_proxy)
		//if err!=nil{
		//	return nil,errors.New("parse front proxy addr fail : "+err.Error())
		//}
		//sch:= strings.ToLower(url.Scheme)
		//if sch!=Http && sch!=Socks5{
		//	return nil,errors.New("front proxy proto not support")
		//}

	}

	//check server
	server_name := strings.Trim(client.Server_addr, "")
	addr, err := parse_local_string_addr(server_name, cli_conf)
	if err != nil {
		return nil, nil, errors.New("check server addr faile : " + err.Error())
	}
	cli_conf.Server_Addr = addr
	cli_conf.Server_addr = addr.StringWithPort()
	info = append(info, fmt.Sprintf("%-25s : %v", "server addr ", cli_conf.Server_addr))

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
		info = append(info, fmt.Sprintf("%-25s : %v", "remote dns addr ", "use remote servrr default dns addr"))
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
		cli_conf.Tls_conf = &tls.Config{
			RootCAs:                cert_pool,
			ServerName:             strings.Split(server_name, ":")[0],
			MinVersion:             tls.VersionTLS13,
			SessionTicketsDisabled: true,
		}
		if client.Tls.Server_name != "" {
			cli_conf.Tls_conf.ServerName = client.Tls.Server_name
		}
		info = append(info, fmt.Sprintf("%-25s : %v", "tls server name ", cli_conf.Tls_conf.ServerName))

		if len(client.Tls.Client_cert) == 0 {
			return nil, nil, errors.New("tls check fail : client cert is nil")
		}

		client_cert := []tls.Certificate{}
		for _, v := range client.Tls.Client_cert {
			cert, err := tls.LoadX509KeyPair(v.Cert, v.Private_key)
			if err != nil {
				return nil, nil, errors.New("load client cert fail : " + err.Error())
			}
			client_cert = append(client_cert, cert)
		}
		cli_conf.Client_cert = client_cert
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
	s.Listen_port = serve.Listen_port
	s.Id = i
	info := []string{fmt.Sprintf("%-25s : %v", "listen port", s.Listen_port)}

	crypt, err := Get_crypt(serve.Enc_method, serve.Password)
	if err != nil {
		return nil, nil, err
	}
	s.Crypt = crypt
	s.Udp_crypt = crypt

	if serve.Tls.On {
		if len(serve.Tls.Client_cert_paths) == 0 {
			return nil, nil, errors.New("client cert is nil")
		}
		cert, err := tls.LoadX509KeyPair(serve.Tls.Server_cert_path, serve.Tls.Server_private_key_path)
		if err != nil {
			return nil, nil, errors.New("load server cert and private key exception:" + err.Error())
		}
		cli_cert := x509.NewCertPool()
		for _, v := range serve.Tls.Client_cert_paths {
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
