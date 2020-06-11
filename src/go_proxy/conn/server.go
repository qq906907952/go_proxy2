package conn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"go_proxy/util"
	"io"
	"net"
	"sync"
	"time"
)

func (this *ServerConnectionhandler) Dispatch_serv(serv_con net.Conn) {

	h, err := client_hand_shake(serv_con, this.config)
	if err != nil {
		serv_con.Close()
		util.Print_log(this.config.Id, "serv: "+err.Error())
		return
	}

	ctx, cancel := context.WithCancel(context.TODO())
	remote := &RemoteServerConnection{
		remote:             serv_con,
		connection_info:    h,
		local_close_notify: make(chan uint16, h.Max_payload),
		recvChan:           make(chan Frame),
		sendChan:           &sync.Map{},
		ctx:                ctx,
		lock:               &sync.RWMutex{},
		payload:            0,
		handler:            this,
	}

	rand_bytes := make([]byte, 16)
	rand.Read(rand_bytes)
	remote.id = fmt.Sprintf("%d:%x", this.config.Id, rand_bytes)

	if util.Verbose_info {
		this.lock.Lock()
		this.connection_count += 1
		this.lock.Unlock()
		util.Print_verbose("%s new connection established ,now server connection count %d", remote.id, this.connection_count)
	}

	defer func() {
		cancel()
		remote.close()

	}()
	go func() {
		defer func() {
			if util.Verbose_info {
				util.Print_verbose("%s server loop break", remote.id)
			}
		}()

		for {
			select {
			case frame, ok := <-remote.recvChan:
				if ok {

					if util.Verbose_info {
						if frame.GetFrameType() == Control_frame && frame.(*ControlFrame).Command == Command_close_conn {
							util.Print_verbose("%s server sub connnection %d send close ", remote.id, frame.GetConnectionId())
						}
					}
					remote.write_to_remote(frame)
				}

			case connection_id, ok := <-remote.local_close_notify:
				if ok {
					remote.lock.Lock()
					remote.payload -= 1
					remote.lock.Unlock()
					if util.Verbose_info {
						util.Print_verbose("%s server connection sub connection %d closed, payload %d", remote.id, connection_id, remote.payload)
					}

				}


			case <-ctx.Done():
				return
			}
		}
	}()

	for {

		frame, err := remote.read_from_remote()
		if err != nil {
			if err != io.EOF {
				util.Print_log(this.config.Id, "serve: "+err.Error())
			}

			return
		}

		switch frame.GetFrameType() {
		case Control_frame: // handle new connection

			frame := frame.(*ControlFrame)
			switch frame.Command {
			case Command_new_conn:

				remote.lock.Lock()
				remote.payload += 1
				remote.lock.Unlock()

				if util.Verbose_info {
					util.Print_verbose("%s server connection new sub connection, payload %d", remote.id, remote.payload)
				}

				local_recv_chan := make(chan Frame, 500)
				remote.sendChan.Store(frame.GetConnectionId(), local_recv_chan)

				switch frame.Protocol {
				case Proto_tcp:
					go func(frame *ControlFrame, local_recv_chan chan Frame) {
						connection_id := frame.ConnectionId
						local_close, err := remote.handle_new_tcp_con(frame, local_recv_chan)

						if err != nil && err != io.EOF && err != io.ErrClosedPipe {
							util.Print_log(this.config.Id, "connection close: %s", err.Error())
						}
						if util.Verbose_info {
							util.Print_verbose("%s server connection sub connection %d waitting local close", remote.id, connection_id)
						}
						remote.close_subconnection(connection_id, local_close, local_recv_chan)

					}(frame, local_recv_chan)

				case Proto_udp:

					go func(frame *ControlFrame, local_recv_chan chan Frame) {
						connection_id := frame.ConnectionId
						local_close, err := remote.handle_new_udp_connection(frame, local_recv_chan)
						if err != nil && err != io.EOF && err != io.ErrClosedPipe {
							util.Print_log(this.config.Id, "connection close: %s", err.Error())
						}
						if util.Verbose_info {
							util.Print_verbose("%s server connection sub connection %d waitting local close", remote.id, connection_id)
						}
						remote.close_subconnection(connection_id, local_close, local_recv_chan)
					}(frame, local_recv_chan)

				default:
					util.Print_log(this.config.Id, "serve: recv an frame with unknow proto")
					return
				}

			default:
				ch, ok := remote.sendChan.Load(frame.GetConnectionId())
				if !ok {
					util.Print_log(this.config.Id, "serve: recv an unknow connection id")
					return

				} else {
					ch.(chan Frame) <- frame
				}
			}
		case Data_frame, Udp_Frame:
			ch, ok := remote.sendChan.Load(frame.GetConnectionId())
			if !ok {
				util.Print_log(this.config.Id, "serve: recv an unknow connection id")
				return
			}
			ch.(chan Frame) <- frame

		default:
			util.Print_log(this.config.Id, "serve: recv an unknow frame type")
			return
		}

	}
}

func (this *RemoteServerConnection) handle_new_tcp_con(frame *ControlFrame, local_recv_chan <-chan Frame) (bool, error) {
	var (
		network       string
		connection_id = frame.ConnectionId
		local_close   = false
		send_close    = true
		local_ctx     context.Context
	)

	defer func() {
		if send_close {
			select {
			case this.recvChan <- &ControlFrame{
				Version:      0,
				ConnectionId: connection_id,
				Command:      Command_close_conn,
			}:
			case <-this.ctx.Done():
			}
		}

		if local_ctx != nil {
			<-local_ctx.Done()
		}
	}()

	switch frame.addrType {
	case Addr_domain, Addr_domain_try_ipv6:
		ipv6 := frame.addrType == Addr_domain_try_ipv6
		if this.connection_info.dns_addr_type == Addr_none {
			ip, _type, err := Parse_local_domain(frame.Addr.String(), ipv6, "")
			if err != nil {
				return local_close, err
			}
			frame.Addr, err = NewAddrFromByte(ip, frame.Addr.ToPortByte(), _type)
			if err != nil {
				return local_close, err
			}

			if _type == Addr_type_ipv6 {
				network = "6"
			} else {
				network = "4"
			}
		} else {
			ip, _type, err := Parse_local_domain(frame.Addr.String(), ipv6, this.connection_info.Dns_addr.StringWithPort())
			if err != nil {
				return local_close, err
			}
			if _type == Addr_type_ipv6 {
				network = "6"
			} else {
				network = "4"
			}

			frame.Addr, err = NewAddrFromByte(ip, frame.Addr.ToPortByte(), _type)
			if err != nil {
				return local_close, err
			}
		}

		select {
		case this.recvChan <- &ControlFrame{
			Version:      0,
			ConnectionId: connection_id,
			Command:      Command_domain_ip,
			Addr:         frame.Addr,
		}:
			break
		case <-this.ctx.Done():
			return local_close, nil
		}

	case Addr_type_ipv4:
		network = "4"
	case Addr_type_ipv6:
		network = "6"

	default:
		return local_close, errors.New("recv an unknow addr type")
	}

	var (
		con net.Conn
		err error
	)

	network = "tcp" + network
	defer func() {
		if con != nil {
			CloseTcp(con.(*net.TCPConn))
		}
	}()

	con_ctx, con_cancel := context.WithCancel(context.TODO())
	go func() {
		con, err = net.DialTimeout(network, frame.Addr.StringWithPort(), time.Duration(util.Tcp_timeout)*time.Second)
		con_cancel()
	}()
	select {
	case <-con_ctx.Done():
		if err != nil {
			return local_close, err
		}
		break
		con.(*net.TCPConn).SetNoDelay(true)
		con.(*net.TCPConn).SetKeepAlive(true)
		con.(*net.TCPConn).SetKeepAlivePeriod(10 * time.Second)
	case <-this.ctx.Done():
		return local_close, err
	}

	if len(frame.Data) != 0 {
		con.SetWriteDeadline(time.Now().Add(time.Duration(util.Tcp_timeout) * time.Second))
		if _, err := con.Write(frame.Data); err != nil {
			return local_close, err
		}
	}

	var cancel func()
	local_ctx, cancel = context.WithCancel(context.TODO())
	send_close = false
	go func() {
		defer func() {
			cancel()
		}()

		for {
			var (
				buf = make([]byte, Tcp_buf_size)
				i   int
			)
			i, err = con.Read(buf)

			if err != nil {
				f := &ControlFrame{
					Version:      0,
					ConnectionId: connection_id,
					Command:      Command_close_conn,
				}
				if i > 0 {
					f.Data = buf[:i]
				}
				select {
				case this.recvChan <- f:
					return
				case <-this.ctx.Done():
					return
				}

			} else {
				select {
				case this.recvChan <- &DataFrame{
					Version:      0,
					ConnectionId: connection_id,
					Data:         buf[:i],
				}:
					break
				case <-this.ctx.Done():
					return
				}
			}

		}

	}()

	for {
		select {

		case frame := <-local_recv_chan:

			switch frame.GetFrameType() {
			case Control_frame:
				frame := frame.(*ControlFrame)

				switch frame.Command {
				case Command_close_conn:
					local_close = true
					if len(frame.Data) != 0 {
						con.SetWriteDeadline(time.Now().Add(time.Duration(util.Tcp_timeout) * time.Second))
						con.Write(frame.Data)
					}
					return local_close, nil
				default:
					return local_close, errors.New("recv an illegal command when subconnection established")

				}
			case Data_frame:
				con.SetWriteDeadline(time.Now().Add(time.Duration(util.Tcp_timeout) * time.Second))
				if _, err := con.Write(frame.(*DataFrame).Data); err != nil {
					return local_close, err
				}
			default:
				return local_close, errors.New("recv an unknow frame type")
			}

		case <-local_ctx.Done():
			return local_close, err
		case <-this.ctx.Done():
			return local_close, nil
		}
	}
}

func (this *RemoteServerConnection) handle_new_udp_connection(frame *ControlFrame, local_recv_chan <-chan Frame) (bool, error) {
	var (
		connection_id = frame.ConnectionId
		local_close   = false
		route         = &sync.Map{}
	)

	ctx, cancel := context.WithCancel(context.TODO())

	defer func() {
		cancel()

		g := &sync.WaitGroup{}
		g.Add(1)
		go func() {
			route.Range(func(_, value interface{}) bool {
				value.(*net.UDPConn).Close()
				return true
			})
			g.Done()
		}()

		select {
		case this.recvChan <- &ControlFrame{
			Version:      0,
			ConnectionId: connection_id,
			Command:      Command_close_conn,
		}:
		case <-this.ctx.Done():
		}

		g.Wait()
		for {
			i := 0
			route.Range(func(_, value interface{}) bool {
				i++
				return true
			})
			if i == 0 {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}

	}()

	for {
		select {

		case frame := <-local_recv_chan:
			switch frame.GetFrameType() {
			case Control_frame:
				frame := frame.(*ControlFrame)
				switch frame.Command {
				case Command_close_conn:
					local_close = true
					return local_close, nil
				default:
					return local_close, errors.New("udp connection recv an illegal command")

				}
			case Udp_Frame:
				if frame.(*UdpFrame).local_addr_type == Addr_none || len(frame.(*UdpFrame).Data) == 0 {
					return local_close, errors.New("recv an unexpect udp frame")
				}
				go func(frame *UdpFrame) {

					var (
						err  error
						dest *net.UDPAddr
					)
					switch frame.dest_addr_type {
					case Addr_type_ipv6, Addr_type_ipv4:
						dest = &net.UDPAddr{
							IP:   net.ParseIP(frame.Dest_addr.String()),
							Port: frame.Dest_addr.ToPortInt(),
						}

					case Addr_domain_try_ipv6, Addr_domain:

						var (
							ip   []byte
							ipv6 = frame.dest_addr_type == Addr_domain_try_ipv6
						)

						if this.connection_info.dns_addr_type == Addr_none {
							ip, _, err = Parse_local_domain(frame.Dest_addr.String(), ipv6, "")
						} else {
							ip, _, err = Parse_local_domain(frame.Dest_addr.String(), ipv6, this.connection_info.Dns_addr.StringWithPort())
						}
						if err != nil {
							break
						}
						dest = &net.UDPAddr{
							IP:   ip,
							Port: frame.Dest_addr.ToPortInt(),
						}

					default:
						util.Print_log_without_id("recv an unexpect udp frame")
						return
					}

					if err != nil {
						util.Print_log_without_id("dial udp fail: %s", err.Error())
						return
					}

					lan_addr := frame.Local_addr.StringWithPort()

					con, ok := route.Load(lan_addr)
					if ok {
						con.(*net.UDPConn).WriteTo(frame.Data, dest)
					} else {
						con, err := net.ListenUDP("udp", nil)
						if err != nil {
							util.Print_log_without_id("listen udp fail: %s", err.Error())
							return
						}

						defer func() {
							route.Delete(lan_addr)
							con.Close()
						}()

						route.Store(lan_addr, con)
						con.WriteTo(frame.Data, dest)

						for {
							con.SetReadDeadline(time.Now().Add(time.Duration(util.Config.Udp_timeout) * time.Second))
							buf := make([]byte, Udp_buf_size)
							i, dest, err := con.ReadFrom(buf)
							if err != nil {
								return
							}

							dest_addr, err := NewAddrFromString(dest.String(), false)
							if err != nil {
								return
							}
							select {
							case <-this.ctx.Done():
								return
							case <-ctx.Done():
								return
							default:
								select {
								case this.recvChan <- &UdpFrame{
									Version:      0,
									ConnectionId: connection_id,
									Local_addr:   frame.Local_addr,
									Dest_addr:    dest_addr,
									Data:         buf[:i],
								}:
									continue
								case <-this.ctx.Done():
									return
								case <-ctx.Done():
									return
								}


							}

						}
					}

				}(frame.(*UdpFrame))

			default:
				return local_close, errors.New("udp connection recv an unknow frame type")
			}

		case <-this.ctx.Done():
			return local_close, nil
		}
	}

}

func client_hand_shake(serv_con net.Conn, conf *ServConfig) (*Handshake_info, error) {

	if conf.Tls_conf != nil {
		data_len := []byte{0, 0}
		if _, err := io.ReadAtLeast(serv_con, data_len, 2); err != nil {
			return nil, err
		}

		l := binary.BigEndian.Uint16(data_len)
		buf := make([]byte, l)
		if _, err := io.ReadAtLeast(serv_con, buf, int(l)); err != nil {
			return nil, err
		}
		data, err := conf.Crypt.Decrypt(buf)
		if err != nil {
			return nil, err
		}
		return Parse_handshake_info_from_byte(0, data)

	} else {
		var i int =0
		for _,v:=range conf.Crypt.Get_passwd(){
			i+=int(v)
		}
		i=(i%100)+64
		b:=make([]byte,i)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		serv_con.SetDeadline(time.Now().Add(time.Duration(util.Tcp_timeout) * time.Second))

		if _, err := serv_con.Write(b); err != nil {
			return nil, err
		}

		data_len := []byte{0, 0}
		if _, err := io.ReadAtLeast(serv_con, data_len, 2); err != nil {
			return nil, err
		}
		l := binary.BigEndian.Uint16(data_len)
		buf := make([]byte, l)
		if _, err := io.ReadAtLeast(serv_con, buf, int(l)); err != nil {
			return nil, err
		}

		data, err := conf.Crypt.Decrypt(buf)
		if err != nil {
			return nil, err
		}
		h, err := Parse_handshake_info_from_byte(len(b), data)
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(h.Rand_byte, b) {
			return nil, errors.New("handshake fail,rand data not equal")
		}

		serv_con.SetDeadline(time.Time{})
		return h, nil

	}
}
