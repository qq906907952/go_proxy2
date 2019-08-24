package local_proxy

import (
	"fmt"
	"go_proxy/conn"
	"go_proxy/util"
	"io"
	"net"
	"os"
	"time"
	"sync"
)

func StartLocalproxy(config *conn.ClientConfig,g *sync.WaitGroup) {
	l, err := net.Listen("tcp", config.Local_addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
		os.Exit(1)
	}
	listen := l.(*net.TCPListener)



	if config.Mode==util.Socks5{
		addr,err:=conn.NewAddrFromString(config.Local_addr,false)
		if err!=nil{
			panic("unknow error")
		}
		ul,err:=net.ListenUDP("udp",&net.UDPAddr{
			Port:addr.ToPortInt(),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}
		if config.Udp_in_tcp{
			go  handle_socks5_udp_forward_tcp(ul,config)
		}else{
			go handle_socks5_udp_forward_udp(ul,config)
		}


	}

	g.Done()
	for {

		con, err := listen.AcceptTCP()
		if err != nil {
			util.Print_log(config.Id, "accept tcp error:"+err.Error())
			continue
		}

		go func(con *net.TCPConn) {
			con.SetKeepAlive(true)
			con.SetKeepAlivePeriod(10 * time.Second)
			con.SetNoDelay(true)

			switch config.Mode {
			case util.Socks5:
				go func(con *net.TCPConn, config *conn.ClientConfig) {

					if err := handle_socks5(con, config); err != nil && err != io.EOF {
						util.Print_log(config.Id, err.Error())
					}
				}(con, config)

			case util.Http:
				go func(con *net.TCPConn, config *conn.ClientConfig) {
					if err := handle_http_con(con, config); err != nil && err != io.EOF {
						util.Print_log(config.Id, err.Error())
					}
				}(con, config)
			case util.Iptables:
				fmt.Fprintf(os.Stderr, "not implement\r\n")
				os.Exit(1)
			default:
				fmt.Fprintf(os.Stderr, "unknow error \r\n")
				os.Exit(1)
			}

		}(con)

	}

}


