package conn

import (
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"go_proxy/util"
	"io"
	"net"
	"sync"
	"time"
)

const Tcp_buf_size = 65400
const Udp_buf_size = 65450

type ServerConnection struct {
	Id               string
	remote           net.Conn
	id_chan          chan uint16
	local_new_notify chan *LocalConnection

	local_close_notify   chan uint16
	recvChan             chan Frame
	sendChan             *sync.Map
	ele                  *list.Element
	ctx                  context.Context
	idel_conn_remain_sec int
	handler              *ConnectionHandler
}

func (this *ServerConnection) read_from_remote() (Frame, error) {
	return read_from_remote(this.remote, this.handler.config.Crypt)

}

func (this *ServerConnection) write_to_remote(frame Frame) error {
	return write_to_remote(this.remote, frame, this.handler.config.Crypt)
}

func (this *ServerConnection) close() {

	switch c := this.remote.(type) {
	case *net.TCPConn:
		CloseTcp(c)
	case *tls.Conn:
		c.CloseWrite()
		c.Close()
	}

	if util.Verbose_info {
		util.Print_verbose("server connection %s,closoing,recycling local connection id", this.Id)

	}

	i := len(this.id_chan)
	ctx, _ := context.WithTimeout(context.TODO(), time.Duration(util.Resource_recycle_time_out)*time.Second)

	if i == this.handler.config.Connection_max_payload {
		goto close
	}

	for {
		select {
		case <-this.local_close_notify:
			i += 1
		case <-ctx.Done():
			panic(fmt.Sprintf("client %s id chan recycle timeout", this.Id))
		}

		if i == this.handler.config.Connection_max_payload {
			goto close
		}
	}
close:
	close(this.id_chan)
	close(this.recvChan)
	close(this.local_close_notify)
	close(this.local_new_notify)

	if util.Verbose_info {
		util.Print_verbose("server connection %s closed", this.Id)
	}

	return

}

type LocalConnection struct {
	Proto                int
	Local                net.Conn
	RecvChan             chan Frame
	SendChan             chan<- Frame
	close_nofify         chan<- uint16
	connection_map       *sync.Map
	ConnectionId         uint16
	Remote_ctx           context.Context
	Local_ctx            context.Context
	remote_connection_id string
}

func (this *LocalConnection) Close(remote_close bool) {
	if this.Proto==Proto_tcp{
		CloseTcp(this.Local.(*net.TCPConn))
	}
	if this.Local_ctx!=nil{
		<-this.Local_ctx.Done()
	}
	if util.Verbose_info {
		util.Print_verbose("%s  local connection %d waitting remote close",
			this.remote_connection_id,
			this.ConnectionId)
	}

	if !remote_close {
	recv_close:
		for {
			select {
			case frame := <-this.RecvChan:
				if frame.GetFrameType() == Control_frame && frame.(*ControlFrame).Command == Command_close_conn {
					break recv_close
				} else {
					continue
				}

			case <-this.Remote_ctx.Done():
				break recv_close
			}

		}
	}

	this.connection_map.Delete(this.ConnectionId)
	close(this.RecvChan)
	this.close_nofify <- this.ConnectionId

}

type RemoteServerConnection struct {
	id                 string
	remote             net.Conn
	local_close_notify chan uint16
	recvChan           chan Frame
	sendChan           *sync.Map
	ctx                context.Context
	payload            int
	connection_info    *Handshake_info
	lock               *sync.RWMutex
	handler            *ServerConnectionhandler
}


func (this *RemoteServerConnection) close_subconnection(connection_id uint16,local_close bool,local_recv_chan chan Frame){
	defer func() {
		this.sendChan.Delete(connection_id)
		close(local_recv_chan)
	}()


	if !local_close {
	local_close:
		for {
			select {
			case frame := <-local_recv_chan:
				if frame.GetFrameType() == Control_frame && frame.(*ControlFrame).Command == Command_close_conn {
					break local_close
				}

			case <-this.ctx.Done():
				break local_close
			}
		}
	}

	this.local_close_notify <- connection_id
}

func (this *RemoteServerConnection) write_to_remote(frame Frame) {
	write_to_remote(this.remote, frame, this.handler.config.Crypt)
}

func (this *RemoteServerConnection) read_from_remote() (Frame, error) {
	return read_from_remote(this.remote, this.handler.config.Crypt)

}

func (this *RemoteServerConnection) close() {

	switch c := this.remote.(type) {
	case *net.TCPConn:
		CloseTcp(c)
	case *tls.Conn:
		c.CloseWrite()
		c.Close()
	}

	if util.Verbose_info {
		util.Print_verbose("%s closing,recycling sub connection ", this.id)
	}

	ctx, _ := context.WithTimeout(context.TODO(), time.Duration(util.Resource_recycle_time_out)*time.Second)
recycling:
	for {
		select {
		case <-this.local_close_notify:
			this.lock.Lock()
			this.payload -= 1
			this.lock.Unlock()
		case <-ctx.Done():
			panic("recycling sub connection timeout")
		default:
			if this.payload == 0 {
				break recycling
			}
		}
	}
	close(this.local_close_notify)
	close(this.recvChan)

	if util.Verbose_info {
		this.handler.lock.Lock()
		this.handler.connection_count -= 1
		this.handler.lock.Unlock()
		util.Print_verbose("%s closed , payload %d", this.id, this.handler.connection_count)
	}
}

type ConnectionHandler struct {
	full_queue *list.List
	idle_queue *list.List
	rwlock     *sync.RWMutex
	config     *ClientConfig
}

func (this ConnectionHandler) new_connection_handler(conf *ClientConfig) *ConnectionHandler {
	this.rwlock = &sync.RWMutex{}
	this.idle_queue = list.New()
	this.full_queue = list.New()
	this.config = conf
	this.full_queue.Init()
	this.idle_queue.Init()
	return &this
}

type ServerConnectionhandler struct {
	config           *ServConfig
	connection_count int
	lock             *sync.RWMutex
}

func (this ServerConnectionhandler) new_server_connection_handler(config *ServConfig) *ServerConnectionhandler {
	this.lock = &sync.RWMutex{}
	this.config = config
	return &this
}

func CloseTcp(con *net.TCPConn) {
	con.CloseWrite()
	con.CloseRead()
	con.Close()
}

func write_to_remote(remote net.Conn, frame Frame, crypt util.Crypt_interface) error {
	enc_data := crypt.Encrypt(frame.ToBytes())
	data_len := make([]byte, 2)
	binary.BigEndian.PutUint16(data_len, uint16(len(enc_data)))
	_, err := remote.Write(bytes.Join([][]byte{data_len, enc_data}, nil))
	return err
}

func read_from_remote(remote net.Conn, crypt util.Crypt_interface) (Frame, error) {
	buf := make([]byte, 2)
	_, err := io.ReadAtLeast(remote, buf, 2)
	if err != nil {
		return nil, err
	}
	data_len := binary.BigEndian.Uint16(buf)
	buf = make([]byte, data_len)
	_, err = io.ReadAtLeast(remote, buf, int(data_len))
	if err != nil {
		return nil, err
	}
	b, err := crypt.Decrypt(buf)
	if err != nil {
		return nil, err
	}

	return ParseBytesToFrame(b)

}
