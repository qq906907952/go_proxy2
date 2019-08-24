package server

import (
	"fmt"
	"go_proxy/conn"
	"go_proxy/util"
	"net"
	"os"
	"sync"
	"time"
)

var route = &sync.Map{}

func Start_udp_serv(config *conn.ServConfig, g *sync.WaitGroup) {
	ul, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: config.Listen_port,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error()+"\r\n")
		os.Exit(1)
	}
	g.Done()

	var concatnate_addr = func (lan_addr conn.Addr,recv_from net.Addr) string{
		return lan_addr.StringWithPort()+"|"+recv_from.String()
	}

	for {
		buf := make([]byte, conn.Udp_buf_size)
		i, addr, err := ul.ReadFrom(buf)
		if err!=nil{
			util.Print_log(config.Id,"recv udp data fail: %s",err.Error())
			continue
		}

		go func(recv_from_addr net.Addr,data []byte) {
			dec_data,err:=config.Udp_crypt.Decrypt(data)
			if err!=nil{
				util.Print_log(config.Id,"udp data decrypt fail: %s",err.Error())
				return
			}
			frame,err:=conn.ParseBytesToFrame(dec_data)
			if err!=nil{
				util.Print_log(config.Id,err.Error())
				return
			}
			if frame.GetFrameType()!=conn.Udp_Frame || frame.(*conn.UdpFrame).Dest_addr==nil ||frame.(*conn.UdpFrame).Local_addr==nil {
				util.Print_log(config.Id,"udp server recv an unexpect frame")
				return
			}

			udp_frame:=frame.(*conn.UdpFrame)
			key:=concatnate_addr(udp_frame.Local_addr,addr)
			con,ok:=route.Load(key)
			if ok{
				con.(*net.UDPConn).WriteTo(udp_frame.Data,&net.UDPAddr{
					IP:   udp_frame.Dest_addr.ToHostBytes(),
					Port: udp_frame.Dest_addr.ToPortInt(),
				})
			}else{
				con,err:=net.ListenUDP("udp",nil)
				if err!=nil{
					util.Print_log(config.Id,"listen udp fail: %s",err.Error())
					return
				}
				route.Store(key,con)
				defer func() {
					con.Close()
					route.Delete(key)
				}()

				con.WriteTo(udp_frame.Data,&net.UDPAddr{
					IP:   udp_frame.Dest_addr.ToHostBytes(),
					Port: udp_frame.Dest_addr.ToPortInt(),
				})

				for{
					buf:=make([]byte,conn.Udp_buf_size)
					con.SetReadDeadline(time.Now().Add(time.Duration(util.Config.Udp_timeout)*time.Second))
					i,dest_addr,err:=con.ReadFrom(buf)
					if err!=nil{
						return
					}
					dest,err:=conn.NewAddrFromString(dest_addr.String(),false)
					if err!=nil{
						util.Print_log(config.Id,"parse remote recv addr: %s",err.Error())
						return
					}
					frame:=&conn.UdpFrame{
						Local_addr:   udp_frame.Local_addr,
						Dest_addr:    dest,
						Data:         buf[:i],
					}
					ul.WriteTo(config.Udp_crypt.Encrypt(frame.ToBytes()),recv_from_addr)

				}

			}


		}(addr,buf[:i])

	}
}
