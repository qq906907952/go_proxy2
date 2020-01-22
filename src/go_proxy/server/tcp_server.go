package server

import (
	"crypto/tls"
	"fmt"
	"go_proxy/conn"
	"go_proxy/util"
	"net"
	"os"
	"time"
	"sync"
)

func Start_tcp_server(config *conn.ServConfig,g *sync.WaitGroup){
	listen,err:=net.ListenTCP("tcp",&net.TCPAddr{
		Port: config.Tcp_listen_port,
	})
	if err!=nil{
		fmt.Fprintf(os.Stderr,err.Error()+"\r\n")
		os.Exit(1)
	}
	g.Done()
	for{
		con,err:=listen.AcceptTCP()
		if err!=nil{
			util.Print_log(config.Id,"server: accept tcp error:"+err.Error())
			continue
		}
		go handle_connection(con,config)
	}

}


func handle_connection(con *net.TCPConn,config *conn.ServConfig){
	con.SetKeepAlive(true)
	con.SetKeepAlivePeriod(10*time.Second)
	con.SetNoDelay(true)
	var conn net.Conn = con
	if config.Tls_conf!=nil{
		conn=tls.Server(con,config.Tls_conf)
	}

	config.ServConnectionHandler.Dispatch_serv(conn)

}