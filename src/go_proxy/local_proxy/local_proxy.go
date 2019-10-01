package local_proxy

import (
	"fmt"
	"go_proxy/conn"
	"go_proxy/util"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

func StartLocalproxy(config *conn.ClientConfig, g *sync.WaitGroup) {
	var (
		l    net.Listener
		addr conn.Addr
		err  error
	)

	if config.Mode == util.Iptables {
		addr, err = conn.NewAddrFromString(fmt.Sprintf("127.0.0.1:%d", config.Local_port), false)
		if err != nil {
			fmt.Println(err)
			panic("unknow error")
		}
		l, err = net.Listen("tcp4", addr.StringWithPort())
	} else {
		addr, err = conn.NewAddrFromString(config.Local_addr, false)
		if err != nil {
			panic("unknow error")
		}
		l, err = net.Listen("tcp", config.Local_addr)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
		os.Exit(1)
	}

	listen := l.(*net.TCPListener)

	if config.Mode == util.Socks5 { //handle udp proxy
		ul, err := net.ListenUDP("udp", &net.UDPAddr{
			Port: addr.ToPortInt(),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}

		if config.Udp_in_tcp {
			go handle_socks5_udp_forward_tcp(ul, config)
		} else {
			remote, err := net.ListenUDP("udp", &net.UDPAddr{})
			if err != nil {
				fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
				os.Exit(1)
			}


			go handle_socks5_udp_forward_udp(ul,remote, config)
		}
	} else if config.Mode == util.Iptables {
		if config.Remoted_dns == nil {
			fmt.Fprintf(os.Stderr, "iptables mode must set a remote dns addr\r\n")
		}
		_ul, err := net.ListenUDP("udp4", &net.UDPAddr{
			IP:   []byte{127, 0, 0, 1},
			Port: addr.ToPortInt(),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}
		fd, err := _ul.File()
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}
		if err := syscall.SetsockoptInt(int(fd.Fd()), IPPROTO_IP, IP_RECVORIGDSTADDR, 1); err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}
		if err := syscall.SetsockoptInt(int(fd.Fd()), IPPROTO_IP, IP_TRANSPARENT, 1); err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}
		ul, err := net.FileConn(os.NewFile(fd.Fd(), ""))
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}
		_ul.Close()

		if config.Udp_in_tcp {
			go handle_iptables_udp_forward_tcp(ul.(*net.UDPConn), config)
		} else {

			remote_connection, err := net.ListenUDP("udp4", &net.UDPAddr{})

			if err != nil {
				fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
				os.Exit(1)
			}

			remote_dns_connection, err := net.ListenUDP("udp4", &net.UDPAddr{})
			if err != nil {
				fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
				os.Exit(1)
			}

			go handle_iptables_udp_forward_udp(ul.(*net.UDPConn), remote_connection, remote_dns_connection, config)
		}
	} else {
		//doing nothing
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
				if err := handle_socks5(con, config); err != nil {
					if _, ok := err.(net.Error); !ok && err != io.EOF && err != io.ErrUnexpectedEOF {
						util.Print_log(config.Id, err.Error())
					}
				}
			case util.Http:
				if err := handle_http_con(con, config); err != nil {
					if _, ok := err.(net.Error); !ok && err != io.EOF && err != io.ErrUnexpectedEOF {
						util.Print_log(config.Id, err.Error())
					}
				}
			case util.Iptables:
				if err := handle_iptables(con, config); err != nil {
					if _, ok := err.(net.Error); !ok && err != io.EOF && err != io.ErrUnexpectedEOF {
						util.Print_log(config.Id, err.Error())
					}
				}
			default:
				fmt.Fprintf(os.Stderr, "unknow error \r\n")
				os.Exit(1)
			}

		}(con)

	}

}
