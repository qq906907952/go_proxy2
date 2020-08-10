package local_proxy

import (
	"context"
	"errors"
	"go_proxy/conn"
	"go_proxy/util"
	"io"
	"net"
	"time"
)

func convert_addr(addr conn.Addr, config *conn.ClientConfig) (conn.Addr, bool, error) {
	if addr.IsDomain() {
		if addr.IsChinaAddr() {
			is_cn := true
			_ip, ok := config.Cn_domain_ip_map.Load(addr.String())

			if ok {
				var (
					new_addr conn.Addr
					err      error
				)

				if time.Now().Unix()-_ip.(*conn.Domain_record).Time > config.Domain_cache_time {
					config.Cn_domain_ip_map.Delete(addr.String())
					goto china_addr_not_ok
				}
				ip := _ip.(*conn.Domain_record).Ip

				if len(ip) == 16 {
					new_addr, err = conn.NewAddrFromByte(ip, addr.ToPortByte(), conn.Addr_type_ipv6)
					if err != nil {
						return nil, is_cn, err
					}
					return convert_addr(new_addr, config)
				} else if len(ip) == 4 {
					new_addr, err = conn.NewAddrFromByte(ip, addr.ToPortByte(), conn.Addr_type_ipv4)
				} else {
					err = errors.New("cn domain map load an unknow ip type")
				}
				return new_addr, is_cn, err

			}
		china_addr_not_ok:
			ip, _type, err := conn.Parse_local_domain(addr.String(), config.Ipv6, config.Local_dns_addr)
			if err != nil {
				return nil, is_cn, err
			}

			if config.Domain_cache_time != 0 {
				config.Cn_domain_ip_map.Store(addr.String(), &conn.Domain_record{
					Ip:   ip,
					Time: time.Now().Unix(),
				})
			}

			new_addr, err := conn.NewAddrFromByte(ip, addr.ToPortByte(), _type)
			if err != nil {
				return nil, is_cn, err
			}

			if _type == conn.Addr_type_ipv6 {
				return convert_addr(new_addr, config)
			}

			return new_addr, is_cn, nil

		} else {
			is_cn := false
			_ip, ok := config.Not_cn_domain_ip_map.Load(addr.String())

			if ok {
				if  time.Now().Unix()-_ip.(*conn.Domain_record).Time>config.Domain_cache_time{
					config.Not_cn_domain_ip_map.Delete(addr.String())
					return addr, is_cn, nil
				}

				var (
					new_addr conn.Addr
					err      error
				)

				ip := _ip.(*conn.Domain_record).Ip

				if len(ip) == 16 {
					new_addr, err = conn.NewAddrFromByte(ip, addr.ToPortByte(), conn.Addr_type_ipv6)
				} else if len(ip) == 4 {
					new_addr, err = conn.NewAddrFromByte(ip, addr.ToPortByte(), conn.Addr_type_ipv4)
				} else {
					err = errors.New("not cn domain map load an unknow ip type")
					return nil, is_cn, err
				}
				return new_addr, is_cn, err
			} else {
				return addr, is_cn, nil
			}
		}
	} else {
		if addr.IsChinaAddr() {
			return addr, true, nil
		} else {
			return addr, false, nil
		}
	}

}

func handle_cn_connection(config *conn.ClientConfig, con net.Conn, addr conn.Addr, cn_data, local_data []byte) error {

	if util.Verbose_info{
		util.Print_verbose("%s connection cn addr:%s",con.RemoteAddr().String(),addr.StringWithPort())
	}

	cn_con, err := net.Dial("tcp", addr.StringWithPort())
	if err != nil {
		return err
	}

	remote_addr, err := conn.NewAddrFromString(cn_con.RemoteAddr().String(), false)
	if err != nil {
		return err
	}

	if (remote_addr.String() == config.Local_ip || config.Local_ip == "0.0.0.0" || config.Local_ip == "::") && remote_addr.ToPortInt() == config.Local_port {
		return errors.New("local recursive detected, return")
	}

	defer func() {
		conn.CloseTcp(cn_con.(*net.TCPConn))
		conn.CloseTcp(con.(*net.TCPConn))
	}()

	if len(cn_data) != 0 {
		cn_con.Write(cn_data)
	}
	if len(local_data) != 0 {
		con.Write(local_data)
	}

	go func() {
		defer func() {
			conn.CloseTcp(cn_con.(*net.TCPConn))
			conn.CloseTcp(con.(*net.TCPConn))
		}()
		io.Copy(cn_con, con)
	}()

	_, err = io.Copy(con, cn_con);
	return err

}

func handle_not_cn_connection(local *conn.LocalConnection, first_frame *conn.ControlFrame, local_data []byte, config *conn.ClientConfig) error {

	if util.Verbose_info{
		util.Print_verbose("%s connect not cn addr:%s",local.Local.RemoteAddr().String(),first_frame.Addr.StringWithPort())
	}


	var (
		remote_close = false
		send_close   = false
	)

	defer func() {
		if send_close {
			select {
			case local.SendChan <- &conn.ControlFrame{
				Version:      0,
				ConnectionId: local.ConnectionId,
				Command:      conn.Command_close_conn,

			}:

			case <-local.Remote_ctx.Done():
			}
		}

		local.Close(remote_close)

	}()

	local.Local.SetWriteDeadline(time.Now().Add(time.Duration(util.Tcp_timeout) * time.Second))

	if len(local_data) != 0 {
		if _, err := local.Local.Write(local_data); err != nil {
			return err
		}
	}

	select{
	case local.SendChan <- first_frame:
		send_close=true
		break
	case <-local.Remote_ctx.Done():
		return nil
	}

	if first_frame.Addr.IsDomain() {
		ctx, _ := context.WithTimeout(context.TODO(), time.Duration(util.Tcp_timeout)*time.Second)
		select {
		case frame := <-local.RecvChan:

			if frame.GetFrameType() == conn.Control_frame {

				if frame.(*conn.ControlFrame).Command == conn.Command_domain_ip &&
					(frame.(*conn.ControlFrame).Addr.Type() == conn.Addr_type_ipv6 || frame.(*conn.ControlFrame).Addr.Type() == conn.Addr_type_ipv4) {

					frame := frame.(*conn.ControlFrame)
					if config.Domain_cache_time != 0 {
						config.Not_cn_domain_ip_map.Store(first_frame.Addr.String(), &conn.Domain_record{
							Ip:   frame.Addr.ToHostBytes(),
							Time: time.Now().Unix(),
						})
					}

					if len(frame.Data) != 0 {
						local.Local.SetWriteDeadline(time.Now().Add(time.Duration(util.Tcp_timeout) * time.Second))
						if _, err := local.Local.Write(frame.Data); err != nil {
							return err
						}
					}
				} else if frame.(*conn.ControlFrame).Command == conn.Command_close_conn {
					remote_close = true
					return nil
				} else {
					return errors.New("recv an unexpect frame")
				}
			} else {
				return errors.New("recv an unexpect frame")
			}
		case <-ctx.Done():
			return errors.New("recv first frame timeout")
		case <-local.Remote_ctx.Done():
			return nil
		}

	}


	var (
		cancel func()
		err         error
	)

	local.Local_ctx,cancel=context.WithCancel(context.TODO())
	send_close = false

	go func() {
		defer cancel()
		for {
			var (
				buf = make([]byte, conn.Tcp_buf_size)
				i   int
			)
			i, err = local.Local.Read(buf)
			if err != nil {
				f := &conn.ControlFrame{
					Version:      0,
					ConnectionId: local.ConnectionId,
					Command:      conn.Command_close_conn,
				}
				if i > 0 {
					f.Data = buf[:i]
				}
				select {
				case local.SendChan <- f:
					return
				case <-local.Remote_ctx.Done():
					return
				}

			} else {
				select {
				case local.SendChan <- &conn.DataFrame{
					Version:      0,
					ConnectionId: local.ConnectionId,
					Data:         buf[:i],
				}:

					break
				case <-local.Remote_ctx.Done():
					return
				}
			}

		}

	}()

	for {
		select {
		case frame := <-local.RecvChan:
			switch frame.GetFrameType() {
			case conn.Data_frame:
				local.Local.SetWriteDeadline(time.Now().Add(time.Duration(util.Tcp_timeout) * time.Second))
				if _, err := local.Local.Write(frame.(*conn.DataFrame).Data); err != nil {
					return err
				}

			case conn.Control_frame:
				frame := frame.(*conn.ControlFrame)
				switch frame.Command {
				case conn.Command_close_conn:
					remote_close = true
					if len(frame.Data) != 0 {
						local.Local.SetWriteDeadline(time.Now().Add(time.Duration(util.Tcp_timeout) * time.Second))
						local.Local.Write(frame.Data)
					}
					return nil
				default:
					return errors.New("recv an unexpect frame")
				}
			default:
				return errors.New("recv an unexpect frame")
			}

		case <-local.Local_ctx.Done():
			return err
		case <-local.Remote_ctx.Done():
			return nil
		}

	}
}
