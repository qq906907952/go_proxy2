package util

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	Config config

	China_ipv4    = map[uint]int{}
	Cn_domain_map = map[string]interface{}{}
	Local_ipv6    = map[string]int{}

	Verbose_info              bool
	Resource_recycle_time_out = 600
	Tcp_timeout               = 30
)

const Pid_file = "/var/run/go_proxy.pid"

const (
	Enc_aes_256_cfb = "aes-256-cfb"
	Enc_chacha20    = "chacha20"
	Enc_none        = "none"
)

const (
	Socks5   = "socks5"
	Http     = "http"
	Iptables = "iptables"
)

type Client struct {
	Mode        string
	Front_proxy string
	Tls         struct {
		On             bool
		Server_name    string
		Tcp_encrypt    bool
		Root_cert_path string
		Private_key    string
		Certificate    string
	}
	Ipv6                   bool
	Connection_max_payload int
	Local_addr             string
	Local_Port             int
	Interface              string
	Tcp_server_addr        string
	Udp_server_addr        string
	Enc_method             string
	Password               string
	Remote_dns_addr        string
	Local_dns_addr         string
	Domain_cache_time      int64
	Udp_in_tcp             bool
}

type Serve struct {
	Tls struct {
		On                 bool
		Tcp_encrypt        bool
		Server_private_key string
		Server_cert        string
		Client_certs       []string
	}
	Tcp_listen_port int
	Udp_listen_port int
	Enc_method      string
	Password        string
}

type config struct {
	Ulimit      uint64
	Udp_timeout int64
	Clients     []Client
	Servers     []Serve
}

func init() {
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")

	state := flag.String("s", "", "{ start | restart | stop }")
	config := flag.String("c", "", "json config file location")
	cn_ipv4 := flag.String("china-ipv4", "", "china ipv4 file")
	cn_domain := flag.String("china-domain", "", "china domain file")
	ipv6_white_list := flag.String("ipv6-white-list", "", "ipv6 white list addr list file")
	verbose_info := flag.Bool("verbose", false, "print more info to stdout")
	daemon := flag.Bool("daemon", false, "run background,only implement in linux")
	wd := flag.String("work-dir", "", "")

	flag.Parse()

	Verbose_info = *verbose_info

	var print_help = func() {
		fmt.Fprintln(os.Stderr, `useage: go_proxy -s {start|restart|stop} -c config-file [--china-ipv4="china ipv4 file"] [--china-domain="china domain file"] [--ipv6-white-list="ipv6 white list"] [--verbose]`)
	}

	var check_system = func() {
		if runtime.GOOS != "linux" {
			fmt.Fprintf(os.Stderr, "daemon just implement in linux\r\n")
			os.Exit(1)
		}

	}

	var getpid = func() int {
		check_system()
		f, err := os.Open(Pid_file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open pid file fail:%s\r\n", err.Error())
			os.Exit(1)
		}
		defer f.Close()
		_pid, _, err := bufio.NewReader(f).ReadLine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "open pid file fail:%s\r\n", err.Error())
			os.Exit(1)
		}
		pid, err := strconv.Atoi(string(_pid))
		if err != nil {
			print_help()
			os.Exit(1)
		}
		return pid
	}

	var stop = func(pid int) {
		check_system()
		fmt.Println("stoping process...\r\n")
		p := fmt.Sprintf("/proc/%d", pid)
		if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil {
			fmt.Fprintf(os.Stderr, "stop fail: %s\r\n", err.Error())
			os.Exit(1)
		}

		for i := 0; i < 10; i++ {
			_, err1 := os.Stat(Pid_file)
			_, err2 := os.Stat(p)

			if os.IsNotExist(err1) && os.IsNotExist(err2) {
				return
			}
			time.Sleep(1 * time.Second)
		}
		fmt.Fprintf(os.Stderr, "stop fail\r\n")
		os.Exit(1)

	}

	var daemon_run = func(exe string, args []string) {
		check_system()
		Check_pid_file()
		if config == nil {
			print_help()
			os.Exit(1)
		}

		cmd := exec.Command(exe, args...)
		var (
			stdout bytes.Buffer
			stderr bytes.Buffer
		)

		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}

		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "start fail: %s\r\n", err.Error())
			os.Exit(1)
		}

		ctx, cancel := context.WithCancel(context.TODO())
		timeout_ctx, _ := context.WithTimeout(context.TODO(), 10*time.Second)

		go func() {
			defer cancel()

			if err := cmd.Wait(); err == nil {
				fmt.Fprintf(os.Stderr, "start fail with unknow error\r\n")
				os.Exit(1)
			}

		}()
		pid := cmd.Process.Pid
		for {
			select {
			case <-ctx.Done():
				buf := make([]byte, 4096)
				i, err := stderr.Read(buf)
				if i > 0 {
					fmt.Fprintf(os.Stderr, "start fail \r\n"+string(buf[:i]))
				} else {
					fmt.Fprintf(os.Stderr, "get stderr fail: %s\r\n", err.Error())
				}

				os.Exit(1)
			case <-timeout_ctx.Done():
				fmt.Fprintf(os.Stderr, "wait daemon start time out\r\n")
				os.Exit(1)
			default:
				_, err1 := os.Stat(Pid_file)
				_, err2 := os.Stat(fmt.Sprintf("/proc/%d", pid))
				if os.IsNotExist(err1) || os.IsNotExist(err2) {
					continue
				} else {
					time.Sleep(1 * time.Second)
					buf := make([]byte, 10240)
					i, err := stdout.Read(buf)
					if i > 0 {
						fmt.Println(string(buf[:i]))
					} else {
						fmt.Fprintf(os.Stderr, "read stdout fail: %s\r\n", err.Error())
						os.Exit(1)
					}

					return
				}

				time.Sleep(500 * time.Millisecond)

			}
		}

	}

	if !*daemon {
		switch *state {
		case "start":
			break
		case "stop":
			stop(getpid())
			os.Exit(0)
		case "restart":
			check_system()
			pid := getpid()
			exe_path := fmt.Sprintf("/proc/%d/exe", pid)
			exe, err := os.Readlink(exe_path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "get execution from %s fail: %s\r\n", exe_path, err.Error())
				os.Exit(1)
			}
			args_path := fmt.Sprintf("/proc/%d/cmdline", pid)
			f, err := os.Open(args_path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "get args from %s fail: %s\r\n", args_path, err.Error())
				os.Exit(1)
			}
			_args, err := ioutil.ReadAll(f)
			if err != nil {
				fmt.Fprintf(os.Stderr, "get args from %s fail: %s\r\n", args_path, err.Error())
				os.Exit(1)
			}
			args := strings.Split(string(_args), string([]byte{0}))

			if len(args) == 1 {
				fmt.Fprintf(os.Stderr, "restart fail\r\n")
				os.Exit(1)
			}

			stop(pid)
			daemon_run(exe, args[1:])
			os.Exit(0)

		default:
			print_help()
			os.Exit(1)
		}
	} else {
		if state != nil && *state != "" {
			fmt.Fprintf(os.Stderr, "-s and -daemon ambiguous\r\n")
			os.Exit(1)
		}
		args := []string{}
		for _, v := range os.Args[1:] {
			if v == "--daemon" || v == "-daemon" || v == "--verbose" || v == "-verbose" {
				continue
			}
			args = append(args, v)
		}
		pwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "get pwd fail: %s\r\n", err.Error())
			os.Exit(1)
		}
		args = append(args, "-s", "start", "--work-dir", pwd)
		*wd = pwd
		daemon_run(os.Args[0], args)
		os.Exit(0)
	}

	if *wd != "" {
		os.Chdir(*wd)
	}

	if config == nil || *config == "" {
		print_help()
		os.Exit(1)
	}

	file, err := os.Open(*config)

	if err != nil {
		fmt.Fprintf(os.Stderr, "open config file fail: %s\r\n", err.Error())
		os.Exit(1)
	}

	b, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open config file fail: %s\r\n", err.Error())
		os.Exit(1)
	}

	if err := json.Unmarshal(b, &Config); err != nil {
		fmt.Fprintf(os.Stderr, "marshal config file fail: %s\r\n", err.Error())
		os.Exit(1)
	}

	if Config.Ulimit < 1024 {
		Config.Ulimit = 1024
	}

	if Config.Udp_timeout > 120 {
		Config.Udp_timeout = 120
	} else if Config.Udp_timeout < 10 {
		Config.Udp_timeout = 10
	}

	if cn_ipv4 != nil && *cn_ipv4 != "" {
		china_ipv4_list, err := os.Open(*cn_ipv4)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open china_ipv4 file fail: %s\r\n", err.Error())
			os.Exit(1)
		}
		defer china_ipv4_list.Close()
		reader := bufio.NewReader(china_ipv4_list)
		for {
			line, _, err := reader.ReadLine()
			if err != nil {
				if err == io.EOF {
					break
				} else {
					fmt.Fprintf(os.Stderr, "open china_ipv4 file fail: %s\r\n", err.Error())
					os.Exit(1)
				}
			} else {
				if len(line) == 0 {
					continue
				}
				ip_mask := strings.Split(string(line), "/")
				if len(ip_mask) != 2 {
					fmt.Printf("warnning : china_ipv4 format incorrect at %s , ignore \r\n", string(line))
					continue
				}
				ip := net.ParseIP(ip_mask[0]).To4()
				if ip == nil {
					fmt.Printf("warnning : china_ipv4 format incorrect at %s , ignore \r\n", string(line))
					continue
				}

				mask, err := strconv.Atoi(ip_mask[1])
				if err != nil || mask > 32 || mask <= 0 {
					fmt.Printf("warnning : china_ipv4 format incorrect at %s , ignore \r\n", string(line))
					continue
				}

				var ip_int uint = 0
				for i := 0; i < len(ip); i++ {
					ip_int += uint(ip[i]) << uint(((len(ip) - i - 1) * 8))
				}

				China_ipv4[ip_int] = mask
			}
		}
	}

	if cn_domain != nil && *cn_domain != "" {
		cn_domain, err := os.Open(*cn_domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open cn domain file fail: %s\r\n", err.Error())
			os.Exit(1)
		}
		defer cn_domain.Close()
		r := bufio.NewReader(cn_domain)
		for {
			line, _, err := r.ReadLine()
			if err != nil {
				if err == io.EOF {
					break
				} else {
					fmt.Fprintf(os.Stderr, "open cn domain file fail: %s\r\n", err.Error())
					os.Exit(1)
				}
			} else {
				if len(line) == 0 {
					continue
				}

				//if len(line) < 3 || line[0] == '.' || line[len(line)-1] == '.' || len(strings.Split(string(line), ".")) < 2 {
				//	fmt.Printf("warnning : china domain format incorrect at %s , ignore \r\n", string(line))
				//}

				Cn_domain_map[string(line)] = nil
			}
		}
	}

	if ipv6_white_list != nil && *ipv6_white_list != "" {
		f, err := os.Open(*ipv6_white_list)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open ipv6 white list file fail: %s\r\n", err.Error())
			os.Exit(1)
		}
		defer f.Close()
		r := bufio.NewReader(f)
		for {
			line, _, err := r.ReadLine()
			if err != nil {
				if err == io.EOF {
					break
				} else {
					fmt.Fprintf(os.Stderr, "open ipv6 black list file fail: %s\r\n", err.Error())
					os.Exit(1)
				}
			} else {
				if len(line) == 0 {
					continue
				}

				ip_mask := strings.Split(string(line), "/")
				if len(ip_mask) != 2 {
					fmt.Printf("warnning : ipv6 black list format incorrect at %s , ignore \r\n", string(line))
					continue
				}
				ip := net.ParseIP(ip_mask[0]).To16()
				if ip.To16() == nil {
					fmt.Printf("warnning : ipv6 black list format incorrect at %s , ignore \r\n", string(line))
					continue
				}

				mask, err := strconv.Atoi(ip_mask[1])
				if err != nil || mask <= 0 || mask > 128 {
					fmt.Printf("warnning : ipv6 black list format incorrect at %s , ignore \r\n", string(line))
					continue
				}
				Local_ipv6[ip.To16().String()] = mask

			}
		}
	}

}

func Check_pid_file() {
	_, err := os.Stat(Pid_file)
	if !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "pid file is exist(in %s) , does the program run ? if you sure the program not run,delete the file and run again\r\n", Pid_file)
		os.Exit(1)
	}
}
