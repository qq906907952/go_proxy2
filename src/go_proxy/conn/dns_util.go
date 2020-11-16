package conn

import (
	"context"
	"go_proxy/exception"
	"net"
	"time"
	"go_proxy/util"
)

type Domain_record struct {
	Ip   []byte
	Time int64

}



func Parse_local_domain(domain string, ipv6 bool,dns_addr string) ([]byte, int, error) {
	var dial  func(_ context.Context, _, _ string) (conn net.Conn, e error) = nil

	if dns_addr!=""{
		dial=func(_ context.Context, _, _ string) (conn net.Conn, e error) {
			return net.Dial("udp", dns_addr)
		}
	}
	need_tcp_try_again:=dial!=nil
tcp_try_again:

	ctx, _ := context.WithTimeout(context.TODO(), time.Duration(util.Config.Udp_timeout)*time.Second)
	ip, err := (&net.Resolver{
		Dial: dial,
		PreferGo:true,
	}).LookupIPAddr(ctx, domain)
	if err != nil {
		if need_tcp_try_again{
			need_tcp_try_again=false
			dial=func(_ context.Context, _, _ string) (conn net.Conn, e error) {
				return net.Dial("tcp", dns_addr)
			}
			goto tcp_try_again
		}
		return nil, 0, err
	}
	var ip4 net.IP = nil

	for _, v := range ip {
		if v.IP.To4() != nil {
			ip4 = v.IP.To4()
			if !ipv6 {
				return v.IP.To4(), Addr_type_ipv4, nil
			}
		} else if v.IP.To16() != nil && ipv6 {
			return v.IP.To16(), Addr_type_ipv6, nil

		}else{
			continue
		}
	}
	if ip4 != nil {
		return ip4, Addr_type_ipv4, nil
	}
	return nil, 0, exception.DnsError{}.New("local domain "+ domain + " can not found A record")

}
