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

	if config.Mode == util.Iptables {
		if config.Remoted_dns == nil {
			fmt.Fprintf(os.Stderr, "iptables mode must set a remote dns addr\r\n")
			os.Exit(1)
		}

		w := &sync.WaitGroup{}
		if config.Ipv6 {
			l6, err := net.ListenTCP("tcp6", &net.TCPAddr{

				IP:   net.ParseIP("::1"),
				Port: config.Local_port,
				Zone:"",
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
				os.Exit(1)
			}

			_ul6, err := net.ListenUDP("udp6", &net.UDPAddr{
				IP:   net.ParseIP("::1"),
				Port: config.Local_port,
				Zone:"lo",
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
				os.Exit(1)
			}

			fd, err := _ul6.File()
			if err != nil {
				fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
				os.Exit(1)
			}

			if err := syscall.SetsockoptInt(int(fd.Fd()), IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, 1); err != nil {
				fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
				os.Exit(1)
			}
			if err := syscall.SetsockoptInt(int(fd.Fd()), IPPROTO_IPV6, IP_TRANSPARENT, 1); err != nil {
				fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
				os.Exit(1)
			}
			ul6, err := net.FileConn(os.NewFile(fd.Fd(), ""))
			if err != nil {
				fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
				os.Exit(1)
			}
			_ul6.Close()

			go func() {
				for {
					con, err := l6.AcceptTCP()
					if err != nil {
						util.Print_log(config.Id, "accept tcp error:"+err.Error())
						continue
					}
					go func(con *net.TCPConn) {
						con.SetKeepAlive(true)
						con.SetKeepAlivePeriod(10 * time.Second)
						con.SetNoDelay(true)

						if err := handle_iptables(con, config); err != nil {
							if _, ok := err.(net.Error); !ok && err != io.EOF && err != io.ErrUnexpectedEOF {
								util.Print_log(config.Id, err.Error())
							}
						}

					}(con)
				}
			}()

			w.Add(1)

			go func() {
				defer w.Done()
				if config.Udp_in_tcp {
					go handle_iptables_udp_forward_tcp(ul6.(*net.UDPConn), config,true)
				} else {

					remote_connection, err := net.ListenUDP("udp", &net.UDPAddr{})

					if err != nil {
						fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
						os.Exit(1)
					}

					remote_dns_connection, err := net.ListenUDP("udp", &net.UDPAddr{})
					if err != nil {
						fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
						os.Exit(1)
					}

					go handle_iptables_udp_forward_udp(ul6.(*net.UDPConn), remote_connection, remote_dns_connection, config,true)
				}
			}()

		}

		l4, err := net.ListenTCP("tcp4", &net.TCPAddr{
			IP:   []byte{127, 0, 0, 1},
			Port: config.Local_port,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}

		_ul4, err := net.ListenUDP("udp4", &net.UDPAddr{
			IP:   []byte{127, 0, 0, 1},
			Port: config.Local_port,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}
		fd, err := _ul4.File()
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
		ul4, err := net.FileConn(os.NewFile(fd.Fd(), ""))
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}
		_ul4.Close()

		if config.Udp_in_tcp {
			go handle_iptables_udp_forward_tcp(ul4.(*net.UDPConn), config,false)
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

			go handle_iptables_udp_forward_udp(ul4.(*net.UDPConn), remote_connection, remote_dns_connection, config,false)

		}

		w.Wait()
		g.Done()

		for {
			con, err := l4.AcceptTCP()
			if err != nil {
				util.Print_log(config.Id, "accept tcp error:"+err.Error())
				continue
			}
			go func(con *net.TCPConn) {
				con.SetKeepAlive(true)
				con.SetKeepAlivePeriod(10 * time.Second)
				con.SetNoDelay(true)

				if err := handle_iptables(con, config); err != nil {
					if _, ok := err.(net.Error); !ok && err != io.EOF && err != io.ErrUnexpectedEOF {
						util.Print_log(config.Id, err.Error())
					}
				}

			}(con)
		}

	} else {
		if config.Mode == util.Socks5 { // handle socks5 udp
			addr, err := conn.NewAddrFromString(config.Local_addr, false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "unknow error \r\n")
				os.Exit(1)
			}
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
				go handle_socks5_udp_forward_udp(ul, remote, config)
			}
		}

		l, err := net.Listen("tcp", config.Local_addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}
		listen := l.(*net.TCPListener)
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

				default:
					fmt.Fprintf(os.Stderr, "unknow error \r\n")
					os.Exit(1)
				}

			}(con)

		}

	}

}
