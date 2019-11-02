package local_proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"go_proxy/conn"
	"go_proxy/util"
	"net"
	"syscall"
	"time"
)

var (
//linux defined const

//IPPROTO_IP  =syscall.IPPROTO_IP
//IPPROTO_IPV6 =syscall.IPPROTO_IPV6
//IP_RECVORIGDSTADDR = syscall.IP_RECVORIGDSTADDR
//IP_TRANSPARENT = syscall.IP_TRANSPARENT
)

const (
	SO_ORIGIN_DST        = 80
	IPT6_SO_ORIGIN_DST   = 80
	IPPROTO_IP           = 0x0
	IPPROTO_IPV6         = 0x29
	SO_REUSEPORT         = 15
	IP_RECVORIGDSTADDR   = 0x14
	IPV6_RECVORIGDSTADDR = 0x4a
	IP_TRANSPARENT       = 0x13
)

func get_tcp_origin_dest(con *net.TCPConn, config *conn.ClientConfig) (conn.Addr, error) {
	file, err := con.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	t, err := conn.NewAddrFromString(con.RemoteAddr().String(), false)

	if err != nil {
		return nil, err
	}
	switch t.Type() {
	case conn.Addr_type_ipv4:
		addr, err := syscall.GetsockoptIPv6Mreq(int(file.Fd()), IPPROTO_IP, SO_ORIGIN_DST)
		if err != nil {
			return nil, err
		}
		return conn.NewAddrFromByte(addr.Multiaddr[4:8], addr.Multiaddr[2:4], conn.Addr_type_ipv4)
	case conn.Addr_type_ipv6:
		if !config.Ipv6 {
			return nil, errors.New("ipv6 set the false but recv an ipv6 connection")
		}
		addr, err := syscall.GetsockoptICMPv6Filter(int(file.Fd()), IPPROTO_IPV6, IPT6_SO_ORIGIN_DST)
		if err != nil {
			return nil, err
		}

		data := make([]byte, 0, 32)
		for _, v := range addr.Data {
			data = append(data, byte(v&0xff))
			data = append(data, byte((v>>8)&0xff))
			data = append(data, byte((v>>16)&0xff))
			data = append(data, byte((v>>24)&0xff))
		}

		return conn.NewAddrFromByte(data[8:24], data[2:4], conn.Addr_type_ipv6)
		return nil, errors.New("iptables not support ipv6")
	default:
		return nil, errors.New("unknow error")
	}
}

func get_udp_origin_dest(oob []byte, ipv6 bool) (conn.Addr, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("get udp destination addr fail: %s", err.Error()))
	}

	for _, msg := range msgs {
		if msg.Header.Type == IP_RECVORIGDSTADDR && !ipv6 {
			return conn.NewAddrFromByte(msg.Data[4:8], msg.Data[2:4], conn.Addr_type_ipv4)
		}
		if msg.Header.Type == IPV6_RECVORIGDSTADDR && ipv6 {
			return conn.NewAddrFromByte(msg.Data[8:24], msg.Data[2:4], conn.Addr_type_ipv6)
		}
	}

	return nil, errors.New("get udp destination addr fail: IP_RECVORIGDSTADDR not found in socket control message")
}

func handle_iptables(con *net.TCPConn, config *conn.ClientConfig) error {
	defer conn.CloseTcp(con)

	addr, err := get_tcp_origin_dest(con, config)
	if err != nil {
		return err
	}
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
	return handle_not_cn_connection(local, frame, nil, config)
}

func handle_iptables_udp_forward_tcp(ul *net.UDPConn, config *conn.ClientConfig, ipv6 bool) {
	var data_chan = make(chan *conn.UdpFrame)
	var dns_data_chan = make(chan *conn.UdpFrame)

	go remote_udp_2_tcp_loop(data_chan, config, ul, false)
	go remote_udp_2_tcp_loop(dns_data_chan, config, ul, true)

	for {
		data, oob := make([]byte, conn.Udp_buf_size), make([]byte, 1024)
		i, oobi, _, addr, err := ul.ReadMsgUDP(data, oob)
		if err != nil {
			util.Print_log(config.Id, "udp read fail: %s", err.Error())
			continue
		}

		go func(local_addr *net.UDPAddr, data, oob []byte) {
			dest_addr, err := get_udp_origin_dest(oob, ipv6)
			if err != nil {
				util.Print_log(config.Id, err.Error())
				return
			}

			_local_addr, err := conn.NewAddrFromString(local_addr.String(), false)
			if err != nil {
				util.Print_log(config.Id, "convert local addr fail: %s ", err.Error())
				return
			}

			if net.IP(dest_addr.ToHostBytes()).IsLoopback() {
				if dest_addr.ToPortInt() == config.Local_port { //dns request
					select {
					case <-time.After(time.Duration(util.Config.Udp_timeout) * time.Second):
						return
					case dns_data_chan <- &conn.UdpFrame{
						Version:    0,
						Local_addr: _local_addr,
						Dest_addr:  config.Remoted_dns,
						Data:       data,
					}:
						return
					}

				} else {
					util.Print_log(config.Id, "recv an unexpect udp addr with loopback destination ip")
				}
			} else {
				if util.Verbose_info {
					util.Print_verbose("%s connect not cn udp addr:%s", _local_addr.String(), dest_addr.StringWithPort())
				}
				select {
				case <-time.After(time.Duration(util.Config.Udp_timeout) * time.Second):
					return
				case data_chan <- &conn.UdpFrame{
					Version:    0,
					Local_addr: _local_addr,
					Dest_addr:  dest_addr,
					Data:       data,
				}:
					return
				}

			}

		}(addr, data[:i], oob[:oobi])

	}
}

func handle_iptables_udp_forward_udp(ul, remote, remote_dns *net.UDPConn, config *conn.ClientConfig, ipv6 bool) {
	go remote_udp_2_udp_loop(remote, ul, config, false)
	go remote_udp_2_udp_loop(remote_dns, ul, config, true)

	for {
		data, oob := make([]byte, conn.Udp_buf_size), make([]byte, 1024)
		i, oobi, _, addr, err := ul.ReadMsgUDP(data, oob)
		go func(data, oob []byte, addr *net.UDPAddr, err error) {
			if err != nil {
				util.Print_log(config.Id, "udp read from local fail: %s", err.Error())
				return
			}

			dest_addr, err := get_udp_origin_dest(oob, ipv6)
			if err != nil {
				util.Print_log(config.Id, "udp get destination addr fail: %s", err.Error())
				return
			}

			port := make([]byte, 2)
			binary.BigEndian.PutUint16(port, uint16(addr.Port))
			local_addr, err := conn.NewAddrFromByte(addr.IP.To4(), port, conn.Addr_type_ipv4)
			if err != nil {
				util.Print_log(config.Id, "udp read fail: %s", err.Error())
				return
			}

			if err := write_to_remote(remote, remote_dns, config, data, local_addr, dest_addr); err != nil {
				util.Print_log(config.Id, err.Error())
				return
			}

		}(data[:i], oob[:oobi], addr, err)

	}
}

func write_to_remote(remote, remote_dns *net.UDPConn, config *conn.ClientConfig, data []byte, local_addr, dest_addr conn.Addr) error {

	if net.IP(dest_addr.ToHostBytes()).IsLoopback() {
		if dest_addr.ToPortInt() == config.Local_port { //dns request
			remote_dns.WriteToUDP(config.Udp_crypt.Encrypt((&conn.UdpFrame{
				Version:    0,
				Local_addr: local_addr,
				Dest_addr:  config.Remoted_dns,
				Data:       data,
			}).ToBytes()), &net.UDPAddr{
				IP:   config.Server_Addr.ToHostBytes(),
				Port: config.Server_Addr.ToPortInt(),
				Zone: "",
			})
			return nil
		} else {
			return errors.New("recv an unexpect udp addr with loopback destination ip")
		}
	} else {
		if util.Verbose_info {
			util.Print_verbose("%s connect not cn udp addr:%s", local_addr.StringWithPort(), dest_addr.StringWithPort())
		}

		remote.WriteToUDP(config.Udp_crypt.Encrypt((&conn.UdpFrame{
			Version:    0,
			Local_addr: local_addr,
			Dest_addr:  dest_addr,
			Data:       data,
		}).ToBytes()), &net.UDPAddr{
			IP:   config.Server_Addr.ToHostBytes(),
			Port: config.Server_Addr.ToPortInt(),
			Zone: "",
		})

		return nil
	}

}

func write_to_local(udp_frame *conn.UdpFrame) error {
	var (
		fd                int
		err               error
		addr_to_sock_addr = func(addr conn.Addr) syscall.Sockaddr {
			switch addr.Type() {
			case conn.Addr_type_ipv6:
				var ip [16]byte
				for i, v := range addr.ToHostBytes() {
					ip[i] = v
				}
				return &syscall.SockaddrInet6{
					Port: addr.ToPortInt(),
					Addr: ip,
				}
			case conn.Addr_type_ipv4:
				var ip [4]byte
				for i, v := range addr.ToHostBytes() {
					ip[i] = v
				}
				return &syscall.SockaddrInet4{
					Port: addr.ToPortInt(),
					Addr: ip,
				}
			default:
				return nil
			}
		}
	)
	if udp_frame.Dest_addr == nil || udp_frame.Local_addr == nil {
		return errors.New("recv an unexpect udp frame")
	}

	switch udp_frame.Dest_addr.Type() {
	case conn.Addr_type_ipv6:
		fd, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
		if err != nil {
			return errors.New("create udp socket error:" + err.Error())
		}
		defer syscall.Close(fd)

		if err := syscall.SetsockoptInt(fd, IPPROTO_IPV6, IP_TRANSPARENT, 1); err != nil {
			return err
		}
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_REUSEPORT, 1); err != nil {
			return err
		}

	case conn.Addr_type_ipv4:
		fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
		if err != nil {
			return errors.New("create udp socket error:" + err.Error())
		}
		defer syscall.Close(fd)

		if err := syscall.SetsockoptInt(fd, IPPROTO_IP, IP_TRANSPARENT, 1); err != nil {
			return err
		}
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_REUSEPORT, 1); err != nil {
			return err
		}

	default:
		return errors.New("recv an unexpect udp frame")
	}

	if err := syscall.Bind(fd, addr_to_sock_addr(udp_frame.Dest_addr)); err != nil {
		return errors.New("bind udp addr error:" + err.Error())
	}

	if err := syscall.Connect(fd, addr_to_sock_addr(udp_frame.Local_addr)); err != nil {
		return errors.New("udp addr connect error:" + err.Error())
	}
	syscall.Write(fd, udp_frame.Data)
	return nil
}

func remote_udp_2_udp_loop(remote, local *net.UDPConn, config *conn.ClientConfig, is_dns bool) {
	for {
		data := make([]byte, conn.Udp_buf_size)
		i, err := remote.Read(data)

		go func(data []byte, err error) {
			if err != nil {
				util.Print_log(config.Id, "udp read from remote fail: %s", err.Error())
				return
			}

			b, err := config.Udp_crypt.Decrypt(data[:i])

			if err != nil {
				util.Print_log(config.Id, err.Error())
				return
			}

			frame, err := conn.ParseBytesToFrame(b)
			if err != nil {
				util.Print_log(config.Id, err.Error())
				return
			}
			if frame.GetFrameType() != conn.Udp_Frame {
				util.Print_log(config.Id, "udp recv an unexpect frame")
				return
			}
			f := frame.(*conn.UdpFrame)

			if is_dns {
				local.WriteToUDP(f.Data, &net.UDPAddr{
					IP:   net.ParseIP(f.Local_addr.String()),
					Port: f.Local_addr.ToPortInt(),
				})
			} else {
				if err := write_to_local(f); err != nil {
					util.Print_log(config.Id, err.Error())
					return
				}
			}
		}(data[:i], err)
	}
}

func remote_udp_2_tcp_loop(data_chan chan *conn.UdpFrame, config *conn.ClientConfig, local *net.UDPConn, is_dns bool) {
	for {
		frame := <-data_chan
		remote, err := config.ConnectionHandler.Dispatch_client(local)
		if err != nil {
			util.Print_log(config.Id, "connect to remote fail: %s", err.Error())
			continue
		}

		frame.ConnectionId = remote.ConnectionId

		select {
		case <-remote.Remote_ctx.Done():
			continue
		case remote.SendChan <- &conn.ControlFrame{
			Version:      0,
			ConnectionId: remote.ConnectionId,
			Command:      conn.Command_new_conn,
			Protocol:     conn.Proto_udp,
		}:
		}

		select {
		case <-remote.Remote_ctx.Done():
			continue
		case remote.SendChan <- frame:
		}

		var cancel func()

		remote.Local_ctx, cancel = context.WithCancel(context.TODO())
		t_ctx, _ := context.WithTimeout(context.TODO(), time.Duration(util.Config.Udp_timeout)*time.Second)
		ctx, cancel2 := context.WithCancel(context.TODO())

		go func() {
			var remote_close = false
			defer func() {
				cancel2()
				select {
				case remote.SendChan <- &conn.ControlFrame{
					Version:      0,
					ConnectionId: remote.ConnectionId,
					Command:      conn.Command_close_conn,
				}:

				case <-remote.Remote_ctx.Done():
				}

				remote.Close(remote_close)

			}()

			for {
				select {
				case frame := <-remote.RecvChan:
					switch frame.GetFrameType() {
					case conn.Udp_Frame:
						go func(frame *conn.UdpFrame) {
							if is_dns {
								local.WriteToUDP(frame.Data, &net.UDPAddr{
									IP:   net.ParseIP(frame.Local_addr.String()),
									Port: frame.Local_addr.ToPortInt(),
								})
							} else {
								if err := write_to_local(frame); err != nil {
									util.Print_log(config.Id, err.Error())
									return
								}
							}
						}(frame.(*conn.UdpFrame))

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

				case <-remote.Remote_ctx.Done():
					return
				case <-remote.Local_ctx.Done():
					return
				}
			}
		}()

	loop:
		for {
			select {
			case frame := <-data_chan:
				t_ctx, _ = context.WithTimeout(context.TODO(), time.Duration(util.Config.Udp_timeout)*time.Second)
				frame.ConnectionId = remote.ConnectionId
				select {
				case remote.SendChan <- frame:
				case <-remote.Remote_ctx.Done():
					break loop
				}
			case <-remote.Remote_ctx.Done():
				break loop
			case <-t_ctx.Done():
				break loop
			case <-ctx.Done():
				break loop
			}

		}

		cancel()

	}
}
