package local_proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"go_proxy/conn"
	"go_proxy/util"
	"io"
	"net"
	"sync"
	"time"
)

var sockks5_reply = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}

func handle_socks5(con net.Conn, config *conn.ClientConfig) error {
	defer conn.CloseTcp(con.(*net.TCPConn))

	buf := []byte{0, 0}
	_, err := io.ReadAtLeast(con, buf, 2)
	if err != nil {
		return err
	}
	if buf[0] != 5 {
		return errors.New("socks5 recv unexpect data")
	}
	methods_len := int(buf[1])
	buf = make([]byte, methods_len)
	if _, err = io.ReadAtLeast(con, buf, methods_len); err != nil {
		return err
	}

	for _, v := range buf {
		if v == 0 {
			if _, err := con.Write([]byte{5, 0}); err != nil {
				return err
			}
			buf = make([]byte, 4)
			if _, err := io.ReadAtLeast(con, buf, 4); err != nil {
				return err
			}

			if buf[1] == 1 {
				return handle_socks5_tcp(con, config, buf[3])
			} else if buf[1] == 3 {
				return handle_socks5_udp(con, config, buf[3])
			} else {
				break
			}
		}
	}

	return errors.New("socks5 recv unexpect data")

}

func handle_socks5_tcp(con net.Conn, config *conn.ClientConfig, atype byte) error {
	addr, _, err := get_socks5_dest_addr(con, config, atype)

	if err != nil {
		return err
	}
	addr, is_cn, err := convert_addr(addr, config)
	if err != nil {
		return err
	}
	if is_cn {
		return handle_cn_connection(con, addr, nil, sockks5_reply)
	} else {
		local, err := config.ConnectionHandler.Dispatch_client(con)
		if err != nil {
			return err
		}
		frame := &conn.ControlFrame{
			Version:      0,
			ConnectionId: local.ConnectionId,
			Command:      conn.Command_new_conn,
			Protocol:     conn.Proto_tcp,
			Addr:         addr,
		}

		return handle_not_cn_connection(local, frame, sockks5_reply, config)
	}

}

func handle_socks5_udp(con net.Conn, config *conn.ClientConfig, atype byte) error {

	_, _, err := get_socks5_dest_addr(con, config, atype)
	if err != nil {
		return err
	}

	_addr := con.LocalAddr()
	addr, err := conn.NewAddrFromString(_addr.String(), false)
	if err != nil {
		return err
	}
	switch addr.Type() {
	case conn.Addr_type_ipv4:
		con.Write(bytes.Join([][]byte{{5, 0, 0, 1}, addr.ToHostBytes(), addr.ToPortByte()}, nil))
	case conn.Addr_type_ipv6:
		con.Write(bytes.Join([][]byte{{5, 0, 0, 4}, addr.ToHostBytes(), addr.ToPortByte()}, nil))
	default:
		return errors.New("unknow error")

	}
	buf := make([]byte, conn.Tcp_buf_size)
	for {
		if _, err := con.Read(buf); err != nil {
			return nil
		}
	}

}

func handle_socks5_udp_forward_tcp(ul *net.UDPConn, config *conn.ClientConfig) {
	var (
		data_chan = make(chan *conn.UdpFrame, 10000)
		route     = &sync.Map{}
	)

	go func() {

		for {
			frame := <-data_chan
			local, err := config.ConnectionHandler.Dispatch_client(ul)
			if err != nil {
				util.Print_log(config.Id, "connect to remote fail: %s", err.Error())
				_data_chan := data_chan
				data_chan = make(chan *conn.UdpFrame, 10000)
				close(_data_chan)
				continue
			}

			frame.ConnectionId = local.ConnectionId

			local.SendChan <- &conn.ControlFrame{
				Version:      0,
				ConnectionId: local.ConnectionId,
				Command:      conn.Command_new_conn,
				Protocol:     conn.Proto_udp,
			}

			local.SendChan <- frame

			var cancel func()

			local.Local_ctx, cancel = context.WithCancel(context.TODO())
			t_ctx, _ := context.WithTimeout(context.TODO(), time.Duration(util.Config.Udp_timeout)*time.Second)
			ctx, cancel2 := context.WithCancel(context.TODO())

			go func() {
				var remote_close = false
				defer func() {
					cancel2()
					select {
					case local.SendChan <- &conn.ControlFrame{
						Version:      0,
						ConnectionId: local.ConnectionId,
						Command:      conn.Command_close_conn,
					}:

					case <-local.Remote_ctx.Done():
					}

					local.Close(remote_close)

				}()

				for {
					select {
					case frame := <-local.RecvChan:
						switch frame.GetFrameType() {
						case conn.Udp_Frame:
							udp_frame := frame.(*conn.UdpFrame)
							ul.WriteToUDP(bytes.Join([][]byte{{0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, udp_frame.Data}, nil),
								&net.UDPAddr{
									IP:   udp_frame.Local_addr.ToHostBytes(),
									Port: udp_frame.Local_addr.ToPortInt(),
								})

						case conn.Control_frame:
							switch frame.(*conn.ControlFrame).Command {
							case conn.Command_close_conn:
								remote_close = true
								return
							default:
								util.Print_log(config.Id, "recv an unexpect command")
								return
							}

						default:
							util.Print_log(config.Id, "recv an unexpect frame type")
							return

						}

					case <-local.Remote_ctx.Done():
						return
					case <-local.Local_ctx.Done():
						return
					}
				}
			}()

		loop:
			for {
				select {
				case frame := <-data_chan:
					t_ctx, _ = context.WithTimeout(context.TODO(), time.Duration(util.Config.Udp_timeout)*time.Second)
					frame.ConnectionId = local.ConnectionId
					select {
					case local.SendChan <- frame:
					case <-local.Remote_ctx.Done():
						break loop
					}
				case <-local.Remote_ctx.Done():
					break loop
				case <-t_ctx.Done():
					break loop
				case <-ctx.Done():
					break loop
				}

			}

			cancel()

		}
	}()

	for {
		buf := make([]byte, conn.Udp_buf_size)
		i, from, err := ul.ReadFromUDP(buf)
		if err != nil {
			util.Print_log(config.Id, "udp read fail: %s", err.Error())
			continue
		}

		if i < 7 {
			util.Print_log(config.Id, "recv socks5 udp data too short")
			continue
		}
		if buf[2] != 0 {
			continue
		}

		addr, _i, err := get_socks5_dest_addr(bytes.NewReader(buf[4:]), config, buf[3])

		if err != nil {
			util.Print_log(config.Id, "get socks5 udp dest addr fail: %s ", err.Error())
			continue
		}
		go func(local_addr *net.UDPAddr, dest conn.Addr, data []byte) {

			addr, is_cn, err := convert_addr(addr, config)
			if err != nil {
				util.Print_log(config.Id, "parse socks5 udp dest addr fail: %s ", err.Error())
				return
			}
			if is_cn {
				handle_cn_udp(config, route, local_addr, addr, data, ul)

			} else {

				_local_addr, err := conn.NewAddrFromString(local_addr.String(), config.Ipv6)
				if err != nil {
					util.Print_log(config.Id, "convert local addr fail: %s ", err.Error())
					return
				}
				data_chan <- &conn.UdpFrame{
					Version:    0,
					Local_addr: _local_addr,
					Dest_addr:  addr,
					Data:       data,
				}
			}

		}(from, addr, buf[_i+4:i])

	}
}

func handle_socks5_udp_forward_udp(ul *net.UDPConn, config *conn.ClientConfig) {
	var (
		cn_route     = &sync.Map{}
		not_cn_route = &sync.Map{}
	)
	for {
		buf := make([]byte, conn.Udp_buf_size)
		i, from, err := ul.ReadFromUDP(buf)
		if err != nil {
			util.Print_log(config.Id, "udp read fail: %s", err.Error())
			continue
		}

		if i < 7 {
			util.Print_log(config.Id, "recv socks5 udp data too short")
			continue
		}
		if buf[2] != 0 {
			continue
		}

		addr, _i, err := get_socks5_dest_addr(bytes.NewReader(buf[4:]), config, buf[3])

		if err != nil {
			util.Print_log(config.Id, "get socks5 udp dest addr fail: %s ", err.Error())
			continue
		}

		go func(local_addr *net.UDPAddr, dest conn.Addr, data []byte) {
			addr, is_cn, err := convert_addr(addr, config)
			if err != nil {
				util.Print_log(config.Id, "parse socks5 udp dest addr fail: %s ", err.Error())
				return
			}
			if is_cn {
				handle_cn_udp(config, cn_route, local_addr, addr, data, ul)

			} else {
				__local_addr, err := conn.NewAddrFromString(local_addr.String(), false)
				if err != nil {
					util.Print_log(config.Id, "convert local addr fail: %s ", err.Error())
					return
				}
				frame := &conn.UdpFrame{
					Local_addr: __local_addr,
					Dest_addr:  addr,
					Data:       data,
				}
				con, ok := not_cn_route.Load(local_addr.String())
				if ok {
					con.(*net.UDPConn).Write(config.Udp_crypt.Encrypt(frame.ToBytes()))
				} else {
					con, err := net.Dial("udp", config.Server_addr)
					if err != nil {
						util.Print_log(config.Id, "dial remote udp fail: %s ", err.Error())
						return
					}
					not_cn_route.Store(local_addr.String(), con)
					defer func() {
						not_cn_route.Delete(local_addr.String())
						con.Close()

					}()
					con.Write(config.Udp_crypt.Encrypt(frame.ToBytes()))

					for {
						buf := make([]byte, conn.Udp_buf_size)
						con.SetReadDeadline(time.Now().Add(time.Duration(util.Config.Udp_timeout) * time.Second))
						i, err := con.Read(buf)
						if err != nil {
							return
						}
						data, err := config.Udp_crypt.Decrypt(buf[:i])
						if err != nil {
							util.Print_log(config.Id, err.Error())
							return
						}
						frame, err := conn.ParseBytesToFrame(data)

						if err != nil {
							util.Print_log(config.Id, "can not parse udp data to frame: %s", err.Error())
							return
						}
						if frame.GetFrameType() != conn.Udp_Frame {
							util.Print_log(config.Id, "udp recv an not udp frame")
							return
						}
						udp_frame := frame.(*conn.UdpFrame)
						ul.WriteToUDP(bytes.Join([][]byte{{0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, udp_frame.Data}, nil),
							&net.UDPAddr{
								IP:   udp_frame.Local_addr.ToHostBytes(),
								Port: udp_frame.Local_addr.ToPortInt(),
							})

					}

				}

			}

		}(from, addr, buf[_i+4:i])
	}
}

func get_socks5_dest_addr(con io.Reader, config *conn.ClientConfig, atype byte) (addr conn.Addr, i int, err error) {
	i = 0
	switch atype {
	case 1: // ipv4
		ip_port := make([]byte, 6)
		if _, err = io.ReadAtLeast(con, ip_port, 6); err != nil {
			return
		}
		i += 6
		addr, err = conn.NewAddrFromByte(ip_port[:4], ip_port[4:], conn.Addr_type_ipv4)

	case 3: //domain
		domain_len := []byte{0}
		if _, err = io.ReadAtLeast(con, domain_len, 1); err != nil {
			return
		}
		if domain_len[0] == 0 {
			return nil, 0, errors.New("socks5 recv unexpect data")
		}
		domain := make([]byte, domain_len[0])
		port := make([]byte, 2)

		if _, err = io.ReadAtLeast(con, domain, int(domain_len[0])); err != nil {
			return
		}

		if _, err = io.ReadAtLeast(con, port, 2); err != nil {
			return
		}

		_d := string(domain)
		d := net.ParseIP(_d)
		if d.To16() != nil {
			addr, err = conn.NewAddrFromString(fmt.Sprintf("[%s]:%d", _d, binary.BigEndian.Uint16(port)), config.Ipv6)
		} else {
			addr, err = conn.NewAddrFromString(fmt.Sprintf("%s:%d", _d, binary.BigEndian.Uint16(port)), config.Ipv6)
		}
		i += 3 + int(domain_len[0])

	case 4: // ipv6
		ip_port := make([]byte, 18)
		if _, err = io.ReadAtLeast(con, ip_port, 18); err != nil {
			return
		}
		addr, err = conn.NewAddrFromByte(ip_port[:16], ip_port[16:], conn.Addr_type_ipv6)
		i += 18
	default:
		return nil, 0, errors.New("socks5 recv unknow atype")
	}
	return
}

func concatnate_addr(lan_addr net.Addr, dest conn.Addr) string {
	return lan_addr.String() + "|" + dest.StringWithPort()
}

func handle_cn_udp(config *conn.ClientConfig, route *sync.Map, local_addr net.Addr, dest_addr conn.Addr, data []byte, ul *net.UDPConn) {
	key := concatnate_addr(local_addr, dest_addr)
	c, ok := route.Load(key)
	if ok {
		c.(net.Conn).Write(data)
	} else {
		c, err := net.Dial("udp", dest_addr.StringWithPort())
		if err != nil {
			util.Print_log(config.Id, "connect cn udp fail: %s ", err.Error())
			return
		}
		route.Store(key, c)
		defer func() {
			route.Delete(key)
			c.Close()
		}()

		c.Write(data)
		buf := make([]byte, conn.Udp_buf_size)
		for {
			c.SetReadDeadline(time.Now().Add(time.Duration(util.Config.Udp_timeout) * time.Second))
			i, err := c.Read(buf)
			if err != nil {
				return
			}

			ul.WriteTo(bytes.Join([][]byte{{0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, buf[:i]}, nil), local_addr)
		}

	}

}
