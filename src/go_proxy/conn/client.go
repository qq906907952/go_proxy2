package conn

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"go_proxy/util"
	"io"
	"net"
	"sync"
	"time"
	"bytes"
	"encoding/binary"
)

// local connection join to remote dispatch
func (this *ConnectionHandler) Dispatch_client(local net.Conn) (*LocalConnection, error) {
	this.rwlock.Lock()
	defer this.rwlock.Unlock()

	if this.idle_queue.Len() != 0 {
		serv_con := this.idle_queue.Back().Value.(*ServerConnection)

		new_local_connection := &LocalConnection{
			Local: local,
		}
		switch local.(type){
		case *net.TCPConn:
			new_local_connection.Proto=Proto_tcp
		case *net.UDPConn:
			new_local_connection.Proto=Proto_udp
		default:
			return nil,errors.New("unknow connection type")
		}

		serv_con.local_new_notify <- new_local_connection
		select {
		case <-serv_con.ctx.Done():
			return nil, errors.New("remote connection closed")
		case new_local_connection = <-serv_con.local_new_notify:
			return new_local_connection, nil
		}

	} else { // no idle connection in queue
		g := sync.WaitGroup{}
		g.Add(1)

		var (
			serv_con net.Conn
			err      error
		)
		go func() {
			defer g.Done()
			serv_con, err = connection_to_server(this.config)
			return
		}()

		var (
			id_chan                                = make(chan uint16, this.config.Connection_max_payload)
			local_close_notify                     = make(chan uint16, this.config.Connection_max_payload)
			local_new_notify                       = make(chan *LocalConnection)
			serv_recv_chan, local_recv_chan        = make(chan Frame, this.config.Connection_max_payload*50), make(chan Frame, 500)
			connection_id                   uint16 = 0
			sync_map                               = &sync.Map{}
			ctx, cancel                            = context.WithCancel(context.TODO())
		)

		sync_map.Store(connection_id, local_recv_chan)

		for i := 1; i < this.config.Connection_max_payload; i++ {
			id_chan <- uint16(i)
		}

		g.Wait()
		if err != nil {
			close(id_chan)
			close(serv_recv_chan)
			close(local_recv_chan)
			close(local_close_notify)
			return nil, err
		}

		rand_bytes := make([]byte, 16)
		rand.Read(rand_bytes)
		new_serv_con := &ServerConnection{
			remote:               serv_con,
			id_chan:              id_chan,
			local_close_notify:   local_close_notify,
			local_new_notify:     local_new_notify,
			recvChan:             serv_recv_chan,
			sendChan:             sync_map,
			Id:                   fmt.Sprintf("%d:%x", this.config.Id, rand_bytes),
			idel_conn_remain_sec: this.config.Idle_connection_remain_time,
			handler:              this,
			ctx:                  ctx,
		}

		new_local_connection := &LocalConnection{
			Local:                local,
			RecvChan:             local_recv_chan,
			SendChan:             serv_recv_chan,
			connection_map:       sync_map,
			close_nofify:         local_close_notify,
			ConnectionId:         connection_id,
			Ctx:                  ctx,
			remote_connection_id: new_serv_con.Id,
		}

		go new_serv_con.client_loop(cancel)

		if len(id_chan) == 0 {
			new_serv_con.ele = this.full_queue.PushFront(new_serv_con)
			go new_serv_con.dispatcher_in_full_queue()
		} else {
			new_serv_con.ele = this.idle_queue.PushFront(new_serv_con)
			go new_serv_con.dispatcher_in_idle_queue()
		}

		if util.Verbose_info {
			util.Print_verbose("%s new server connection ,payload:%d/%d,idle queue len:%d,full queue len:%d",
				new_serv_con.Id,
				new_serv_con.handler.config.Connection_max_payload-len(new_serv_con.id_chan),
				new_serv_con.handler.config.Connection_max_payload,
				this.idle_queue.Len(),
				this.full_queue.Len())
		}


		return new_local_connection, nil
	}

}

func (this *ServerConnection) client_loop(cancel func()) {

	var err error
	defer func() {
		cancel()
		if util.Verbose_info {
			util.Print_verbose("%s client loop break:%s", this.Id, err.Error())
		}
	}()

	for {
		var frame Frame
		frame, err = this.read_from_remote()
		if err != nil {
			return
		}
		ch, ok := this.sendChan.Load(frame.GetConnectionId())
		if !ok {
			err = errors.New("recv an unknow connection id")
			return
		}
		ch.(chan Frame) <- frame
	}

}

func (this *ServerConnection) dispatcher_in_idle_queue() {

	ctx := context.TODO()

	var remove_and_close = func() {
		this.handler.rwlock.Lock()
		this.handler.idle_queue.Remove(this.ele)
		this.handler.rwlock.Unlock()
		this.close()
		return
	}

	for {
		select {
		case frame := <-this.recvChan:
			if util.Verbose_info {
				if frame.GetFrameType() == Control_frame && frame.(*ControlFrame).Command == Command_close_conn {
					util.Print_verbose("%s (in %s queue) local connection %d send close",
						this.Id,
						"idle",
						frame.GetConnectionId())
				}
			}
			this.write_to_remote(frame)


		case connection_id := <-this.local_close_notify:
			this.id_chan <- connection_id
			if len(this.id_chan) == this.handler.config.Connection_max_payload { // payload 0
				ctx, _ = context.WithTimeout(ctx, time.Duration(this.idel_conn_remain_sec)*time.Second)

				if util.Verbose_info {
					util.Print_verbose("%s (in %s queue) local connection %d remove ,payload:%d/%d,payload is 0,Countdown %d sec to close when no connection regist",
						this.Id,
						"idle",
						connection_id,
						this.handler.config.Connection_max_payload-len(this.id_chan),
						this.handler.config.Connection_max_payload,
						this.idel_conn_remain_sec)

				}

			} else {
				if util.Verbose_info {
					util.Print_verbose("%s (in %s queue) local connection %d remove ,payload:%d/%d",
						this.Id,
						"idle",
						connection_id,
						this.handler.config.Connection_max_payload-len(this.id_chan),
						this.handler.config.Connection_max_payload)
				}
			}
		case local := <-this.local_new_notify:
			var (
				id         = <-this.id_chan
				local_recv = make(chan Frame, 100)
			)

			local.close_nofify = this.local_close_notify
			local.ConnectionId = id
			local.RecvChan = local_recv
			local.SendChan = this.recvChan
			local.connection_map = this.sendChan
			local.Ctx = this.ctx
			local.remote_connection_id = this.Id

			this.sendChan.Store(id, local_recv)
			if len(this.id_chan) == 0 { // full payload
				this.handler.idle_queue.Remove(this.ele)
				this.ele = this.handler.full_queue.PushFront(this)

				if util.Verbose_info {
					util.Print_verbose("%s (in %s queue) local connection %d regist to ,payload:%d/%d,payload is full move to full queue dispatche",
						this.Id,
						"idle",
						id,
						this.handler.config.Connection_max_payload-len(this.id_chan),
						this.handler.config.Connection_max_payload)
				}
				this.local_new_notify <- local

				go this.dispatcher_in_full_queue()

				return
			}
			ctx = context.TODO()
			this.local_new_notify <- local

			if util.Verbose_info {
				util.Print_verbose("%s local connection %d regist ,payload:%d/%d",
					this.Id,
					id,
					this.handler.config.Connection_max_payload-len(this.id_chan),
					this.handler.config.Connection_max_payload)
			}


		case <-ctx.Done():
			remove_and_close()
			return
		case <-this.ctx.Done():
			remove_and_close()
			return
		}
	}
}

func (this *ServerConnection) dispatcher_in_full_queue() {
	var recv_chan <-chan Frame = this.recvChan
	ctx := context.TODO()
	is_full := true

	var remove_and_close = func() {
		this.handler.rwlock.Lock()
		this.handler.full_queue.Remove(this.ele)
		this.handler.rwlock.Unlock()
		this.close()
		return
	}

	for {
		select {
		case frame := <-recv_chan:
			if util.Verbose_info {
				if frame.GetFrameType() == Control_frame && frame.(*ControlFrame).Command == Command_close_conn {
					util.Print_verbose("%s (in %s queue) local connection %d send close",
						this.Id,
						"idle",
						frame.GetConnectionId())
				}
			}
			this.write_to_remote(frame)

		case connection_id := <-this.local_close_notify:
			this.id_chan <- connection_id
			if len(this.id_chan) == this.handler.config.Connection_max_payload {
				remove_and_close()
				return
			}
			if is_full {
				ctx, _ = context.WithTimeout(ctx, time.Duration(this.idel_conn_remain_sec/2)*time.Second)
				is_full = false

				if util.Verbose_info {
					util.Print_verbose("%s (in %s queue) local connection %d remove from ,payload:%d/%d,payload is not full ,if local connection all remove during %d sec,it will close else it will dispatch to idle queue",
						this.Id,
						"full",
						connection_id,
						this.handler.config.Connection_max_payload-len(this.id_chan),
						this.handler.config.Connection_max_payload,
						this.idel_conn_remain_sec/2)
				}

			} else {
				if util.Verbose_info {
					util.Print_verbose(" %s (in %s queue) local connection %d remove ,payload:%d/%d",
						this.Id,
						"full",
						connection_id,
						this.handler.config.Connection_max_payload-len(this.id_chan),
						this.handler.config.Connection_max_payload)
				}
			}
		case <-ctx.Done():
			this.handler.rwlock.Lock()
			this.handler.full_queue.Remove(this.ele)
			this.ele = this.handler.idle_queue.PushBack(this)
			this.handler.rwlock.Unlock()
			if util.Verbose_info {
				util.Print_verbose("%s (in %s queue) server connection  ,payload:%d/%d,dispatch to idle queue",
					this.Id,
					"full",
					this.handler.config.Connection_max_payload-len(this.id_chan),
					this.handler.config.Connection_max_payload)
			}
			go this.dispatcher_in_idle_queue()
			return

		case <-this.ctx.Done():
			remove_and_close()
			return
		}
	}
}

func NewClientConnectionHandler(conf *ClientConfig) *ConnectionHandler {
	return ConnectionHandler{}.new_connection_handler(conf)
}

func connection_to_server(conf *ClientConfig) (net.Conn, error) {

	c, err := net.Dial("tcp", conf.Server_addr)
	if err != nil {
		return nil, err
	}

	close := true
	defer func() {
		if close {
			c.Close()
		}
	}()

	c.(*net.TCPConn).SetKeepAlive(true)
	c.(*net.TCPConn).SetKeepAlivePeriod(10 * time.Second)
	c.(*net.TCPConn).SetNoDelay(true)

	if conf.Tls_conf != nil {

		tls_conf := *conf.Tls_conf
		tls_conf.Certificates = []tls.Certificate{conf.Client_cert[time.Now().UnixNano()%int64(len(conf.Client_cert))]}
		serv_con := tls.Client(c, &tls_conf)
		if err := serv_con.Handshake(); err != nil {
			return nil, err
		}
		c = serv_con

		h:=Handshake_info{
			Rand_byte:      []byte{},
			Max_payload:   uint16(conf.Connection_max_payload),
			Dns_addr:conf.Remoted_dns,

		}

		d:=conf.Crypt.Encrypt(h.ToBytes())
		l:=make([]byte,2)
		binary.BigEndian.PutUint16(l,uint16(len(d)))
		c.SetWriteDeadline(time.Now().Add(time.Duration(util.Tcp_timeout)*time.Second))

		if _,err:=c.Write(bytes.Join([][]byte{l,d},nil));err!=nil{
			return nil,err
		}
		c.SetWriteDeadline(time.Time{})

	} else {

		c.SetDeadline(time.Now().Add(time.Duration(util.Tcp_timeout) * time.Second))
		b := make([]byte, int(conf.Crypt.Get_passwd()[0]))
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}

		if _, err := c.Write(b); err != nil {
			return nil, err
		}

		b = make([]byte, int(conf.Crypt.Get_passwd()[1]))
		if _, err := io.ReadAtLeast(c, b, len(b)); err != nil {
			return nil, err
		}

		h:=Handshake_info{
			Rand_byte:      b,
			Max_payload:   uint16(conf.Connection_max_payload),
			Dns_addr:conf.Remoted_dns,

		}

		ed:=conf.Crypt.Encrypt(h.ToBytes())
		l:=make([]byte,2)
		binary.BigEndian.PutUint16(l,uint16(len(ed)))


		if _, err := c.Write(bytes.Join([][]byte{l,ed},nil)); err != nil {
			return nil, err
		}

		c.SetDeadline(time.Time{})
	}
	close = false
	return c, nil

}
