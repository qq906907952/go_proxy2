package main

import (
	"fmt"
	"go_proxy/conn"
	"go_proxy/local_proxy"
	"go_proxy/server"
	"go_proxy/util"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"sync"
	"time"
)

func main() {

	util.Check_pid_file()

	syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{
		Cur: util.Config.Ulimit,
		Max: util.Config.Ulimit,
	})

	if len(util.Config.Clients) > 65535 {
		fmt.Fprintf(os.Stderr, "client too more\r\n")
		os.Exit(1)
	}
	if len(util.Config.Servers) > 65535 {
		fmt.Fprintf(os.Stderr, "server too more\r\n")
		os.Exit(1)
	}

	g := &sync.WaitGroup{}
	s:=[]string{}
	for i, v := range util.Config.Clients {
		g.Add(1)
		s=append(s,"#########################################")
		s=append(s,fmt.Sprintf("configing client %d \r\n", uint16(i)))
		conf, info,err := conn.LoadClientConfig(&v, uint16(i))
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}
		go local_proxy.StartLocalproxy(conf, g)
		s=append(s,append(info,"#########################################")...)

	}

	for i, v := range util.Config.Servers {
		g.Add(2)
		s=append(s,"#########################################")
		s=append(s,fmt.Sprintf("configing server %d \r\n", uint16(i)))
		conf,info, err := conn.LoadServerConfig(&v, uint16(i))
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
			os.Exit(1)
		}
		go server.Start_tcp_server(conf, g)
		go server.Start_udp_serv(conf, g)
		s=append(s,append(info,"#########################################")...)
	}

	g.Wait()

	if runtime.GOOS=="linux"{
		f, err := os.Create(util.Pid_file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create pid file fail: %s\r\n", err.Error())
			os.Exit(1)
		}
		if _, err := f.WriteString(strconv.FormatInt(int64(os.Getpid()), 10)); err != nil {
			fmt.Fprintf(os.Stderr, "write pid file fail: %s\r\n", err.Error())
			os.Exit(1)
		}
	}
	for _,v:=range s{
		fmt.Println(v)
	}
	fmt.Println()
	fmt.Println("run successful まいにちにミクミクしてあげるよ~~")
	signal_notify := make(chan os.Signal, 1)
	ignore_signal:=make(chan os.Signal, 1)
	signal.Notify(signal_notify,syscall.SIGINT, syscall.SIGKILL, syscall.SIGSTOP, syscall.SIGABRT, syscall.SIGTERM, syscall.SIGUSR1)
	signal.Notify(ignore_signal,syscall.SIGPIPE)

	go func() {
		for{
			<-ignore_signal
			util.Print_log_without_id("recv broken piple signal,ignored.\r\n")
			time.Sleep(10*time.Second)
		}

	}()

	<-signal_notify
	util.Print_log_without_id("recv notify signal, proxy exit.")

	if runtime.GOOS=="linux"{
		if err := os.Remove(util.Pid_file); err != nil {
			util.Print_log_without_id("delete pid fail fail: %s\r\n", err.Error())
		}
	}

	return

}
