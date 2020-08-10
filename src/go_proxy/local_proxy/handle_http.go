package local_proxy

import (
	"bufio"
	"bytes"
	"errors"
	"go_proxy/conn"
	"io"
	"net"
	"net/http"
	"strings"
)

const https_establish_reply = "HTTP/1.1 200 Connection Established\r\n\r\n"

func handle_http_con(con *net.TCPConn, config *conn.ClientConfig) error {

	defer conn.CloseTcp(con)

	req, err := http.ReadRequest(bufio.NewReader(con))
	if err != nil {
		conn.CloseTcp(con)
		return err
	}
	switch strings.ToLower(req.Method) {
	case "connect":
		addr, err := conn.NewAddrFromString(req.Host, config.Ipv6)
		if err != nil {
			return err
		}
		addr, is_cn, err := convert_addr(addr, config)
		if err != nil {
			return err
		}

		if is_cn {
			return handle_cn_connection(config,con, addr, nil, []byte(https_establish_reply))
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

			return handle_not_cn_connection(local, frame, []byte(https_establish_reply), config)
		}

	default:
		host := req.Host
		if host==""{
			return errors.New("http proxy can not determine host")
		}
		split := ":"
		if host[0] == '[' {
			split = "]:"
		}
		if len(strings.Split(host, split)) == 1 {
			host += ":80"
		}
		addr, err := conn.NewAddrFromString(host, config.Ipv6)
		if err != nil {
			return err
		}
		data, err := convert_to_close(req)
		if err != nil {
			return err
		}
		addr, is_cn, err := convert_addr(addr, config)
		if err != nil {
			return err
		}

		if is_cn {
			return handle_cn_connection(config,con, addr, data, nil)

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
				Data:         data,
			}

			return handle_not_cn_connection(local, frame, nil, config)
		}
	}

}

func convert_to_close(req *http.Request) ([]byte, error) {
	req.Header.Del("Proxy-Connection")
	req.Header.Del("proxy-connection")
	req.Header.Del("Connection")
	req.Header.Del("connection")
	req.Header.Add("Connection", "close")
	buf := &bytes.Buffer{}
	req.Write(buf)
	_buf := make([]byte, 1024)
	data := []byte{}
	for {
		i, err := buf.Read(_buf)
		if i > 0 {
			data = bytes.Join([][]byte{data, _buf[:i]}, nil)
		}
		if err != nil {
			if err == io.EOF {
				return data, nil
			} else {
				return nil, err
			}
		}
	}

}
