package conn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"go_proxy/exception"
	"syscall"
)

const (
	Verision = 0
)

const (
	Command_new_conn   = 1
	Command_close_conn = 2
	Command_domain_ip  = 3
)

const (
	Addr_type_ipv4       = 4
	Addr_type_ipv6       = 6
	Addr_domain          = 1
	Addr_domain_try_ipv6 = 2
	Addr_none            = 0
)

const (
	Proto_tcp = syscall.IPPROTO_TCP
	Proto_udp = syscall.IPPROTO_UDP
)


//frame type
const (
	Control_frame = 1
	Data_frame    = 2
	Udp_Frame     = 3
)

//
const control_frame_least_header_len = 8
const data_frame_least_header_len = 5
const udp_frame_least_header_len = 8

type Handshake_info struct {
	_const       [2]byte
	Rand_byte     []byte
	Max_payload  uint16
	dns_addr_type byte
	dns_addr_len byte
	Dns_addr     Addr
}
const handshake_info_least_byte = 6
var  handshake_info_const_byte = [2]byte{39,39} // 39 mean miku ~~ ~~

func (this *Handshake_info) ToBytes()[]byte{
	max_payload:=[]byte{0,0}
	binary.BigEndian.PutUint16(max_payload,this.Max_payload)
	var addr  = []byte{}
	if this.Dns_addr==nil{
		this.dns_addr_type=Addr_none
	}else{
		this.dns_addr_type=byte(this.Dns_addr.Type())
		addr=bytes.Join([][]byte{this.Dns_addr.ToHostBytes(),this.Dns_addr.ToPortByte()},nil)
	}
	return bytes.Join([][]byte{
		handshake_info_const_byte[:],
		this.Rand_byte,
		max_payload,
		{this.dns_addr_type},
		{byte(len(addr))},
		addr,
	},nil)
}

func Parse_handshake_info_from_byte(rand_enc_len int,d []byte)(*Handshake_info,error){

	if len(d)<rand_enc_len+handshake_info_least_byte{
		return nil,exception.FrameErr{}.New("handshake info too short")
	}
	if !bytes.Equal(d[:2],handshake_info_const_byte[:]){
		return nil,exception.FrameErr{}.New("recv an unknow handshake info,maybe tls or encrypt config not relate")
	}

	l:=rand_enc_len+2
	handshake:=&Handshake_info{
		_const:[2]byte{d[0],d[1]},
		Rand_byte:      d[2:l],
		Max_payload:   binary.BigEndian.Uint16(d[l:l+2]),
		dns_addr_type: d[l+2],
		dns_addr_len:  d[l+3],
	}
	remain:=d[l+4:]

	if len(remain)!=int(handshake.dns_addr_len){
		return nil, exception.FrameErr{}.New("handshake frame recv an unexpect frame")
	}
	switch handshake.dns_addr_type{
	case Addr_none:
		//doing nothing
	default:
		if handshake.dns_addr_len<3{
			return nil,exception.AddrErr{}.New("handshake info too short")
		}
		addr,err:=NewAddrFromByte(remain[:handshake.dns_addr_len-2],remain[handshake.dns_addr_len-2:],int(handshake.dns_addr_type))
		if err!=nil{
			return nil,err
		}
		handshake.Dns_addr=addr
	}
	return handshake,nil


}

type Frame interface {
	ToBytes() []byte
	GetFrameType() byte
	GetConnectionId() uint16
	String() string
}

type ControlFrame struct {
	Version      byte
	frameType    byte
	ConnectionId uint16
	Command      byte
	Protocol     byte
	addrType     byte
	addrLen      byte
	Addr         Addr
	Data         []byte
}

func (this *ControlFrame) String() string {
	s := fmt.Sprintf("control frame , version:%d , ", this.Version) +
		fmt.Sprintf("connectionId:%d , ", this.ConnectionId)
	switch this.Command {
	case Command_close_conn:
		s += fmt.Sprintf("command:close connection , ")
	case Command_new_conn:
		s += fmt.Sprintf("command:new connection , ")
	case Command_domain_ip:
		s += fmt.Sprintf("command:domain ip , ")
	default:
		s += fmt.Sprintf("command:unknow command , ")
	}
	switch this.Protocol {
	case Proto_tcp:
		s += fmt.Sprintf("proto:tcp , ")
	case Proto_udp:
		s += fmt.Sprintf("proto:udp , ")
	default:
		s += fmt.Sprintf("proto:unknow proto , ")
	}

	if this.addrType != Addr_none {
		switch this.addrType {
		case Addr_type_ipv4:
			s += fmt.Sprintf("addr type:ipv4 , ")

		case Addr_type_ipv6:
			s += fmt.Sprintf("addr type:ipv6 , ")
		case Addr_domain:
			s += fmt.Sprintf("addr type:domain4 , ")
		case Addr_domain_try_ipv6:
			s += fmt.Sprintf("addr type:domain6 , ")
		default:
			s += fmt.Sprintf("addr type:unknow , ")
			break
		}
		s += fmt.Sprintf("addr len:%d , addr:%s , ", this.addrLen, this.Addr.StringWithPort())

	} else {
		s += fmt.Sprintf("addr type:none , ")
	}

	s += fmt.Sprintf("data len:%d", len(this.Data))
	return s
}

func (this *ControlFrame) GetConnectionId() uint16 {
	return this.ConnectionId
}

func (this *ControlFrame) ToBytes() []byte {
	con_id := [2]byte{}
	binary.BigEndian.PutUint16(con_id[:], this.ConnectionId)

	var (
		addr_bytes []byte
		addr_type  byte
	)
	if this.Addr != nil {
		addr_bytes = bytes.Join([][]byte{this.Addr.ToHostBytes(), this.Addr.ToPortByte()}, nil)
		addr_type = byte(this.Addr.Type())
	} else {
		addr_type = Addr_none
	}
	return bytes.Join([][]byte{
		{this.Version},
		{byte(Control_frame)},
		con_id[:],
		{this.Command},
		{this.Protocol},
		{addr_type},
		{byte(len(addr_bytes))},
		addr_bytes,
		this.Data,
	}, nil)

}

func (this *ControlFrame) GetFrameType() byte {
	return Control_frame
}

type DataFrame struct {
	Version      byte
	frameType    byte
	ConnectionId uint16
	Data         []byte
}

func (this *DataFrame) String() string {
	return fmt.Sprintf("frame type:data frame , version:%d , connectionId:%d , data len:%d", this.Version, this.ConnectionId, len(this.Data))
}

func (this *DataFrame) GetConnectionId() uint16 {
	return this.ConnectionId
}

func (this *DataFrame) ToBytes() []byte {
	con_id := [2]byte{}
	binary.BigEndian.PutUint16(con_id[:], this.ConnectionId)

	return bytes.Join([][]byte{
		{this.Version},
		{byte(Data_frame)},
		con_id[:],
		this.Data,
	}, nil)

}

func (this *DataFrame) GetFrameType() byte {
	return Data_frame
}

func ParseBytesToFrame(b []byte) (Frame, error) {
	if len(b) < data_frame_least_header_len {
		return nil, exception.FrameErr{}.New("len too short")
	}

	switch b[0] {
	case Verision:

		switch b[1] {
		case Control_frame:
			if len(b) < control_frame_least_header_len {
				return nil, exception.FrameErr{}.New("control frame data too short")
			}
			frame := &ControlFrame{
				Version:      b[0],
				frameType:    b[1],
				ConnectionId: binary.BigEndian.Uint16(b[2:4]),
				Command:      b[4],
				Protocol:     b[5],
				addrType:     b[6],
				addrLen:      b[7],
			}

			remain := b[8:]
			if len(remain)<int(frame.addrLen){
				return nil, exception.FrameErr{}.New("control frame addr len too short")
			}


			frame.Data = remain[frame.addrLen:]
			_addr := remain[:frame.addrLen]

			switch frame.addrType {

			case Addr_none:
				frame.Addr = nil

			default:
				if frame.addrLen < 3 {
					return nil, exception.FrameErr{}.New("control frame addr len too short")
				}
				addr, err := NewAddrFromByte(_addr[:frame.addrLen-2], _addr[frame.addrLen-2:frame.addrLen], int(frame.addrType))
				if err != nil {
					return nil, err
				}
				frame.Addr = addr

			}

			return frame, nil

		case Data_frame:
			frame := &DataFrame{
				Version:      b[0],
				frameType:    b[1],
				ConnectionId: binary.BigEndian.Uint16(b[2:4]),
				Data:         b[4:],
			}
			return frame, nil

		case Udp_Frame:
			if len(b)<udp_frame_least_header_len{
				return nil, exception.FrameErr{}.New("control frame data too short")
			}
			frame := &UdpFrame{
				Version:         b[0],
				frameType:       b[1],
				ConnectionId:    binary.BigEndian.Uint16(b[2:4]),
				local_addr_type: b[4],
				local_addr_len:  b[5],
				dest_addr_type:  b[6],
				dest_addr_len:   b[7],
			}
			remain:=b[8:]

			if len(remain)<int(frame.dest_addr_len)+int(frame.local_addr_len){
				return nil, exception.FrameErr{}.New("udp addr len too short")
			}
			local_addr:=remain[:frame.local_addr_len]
			dest_addr:=remain[frame.local_addr_len:frame.dest_addr_len+frame.local_addr_len]
			frame.Data=remain[frame.dest_addr_len+frame.local_addr_len:]
			if len(frame.Data)==0{
				return nil, exception.FrameErr{}.New("udp frame recv data with nil")
			}
			switch frame.local_addr_type{
			case Addr_none:
				frame.Local_addr=nil
			default:
				if len(local_addr)<3{
					return nil, exception.FrameErr{}.New("udp frame local addr len too short")
				}
				addr, err := NewAddrFromByte(local_addr[:frame.local_addr_len-2], local_addr[frame.local_addr_len-2:frame.local_addr_len], int(frame.local_addr_type))
				if err != nil {
					return nil, err
				}
				frame.Local_addr= addr
			}

			switch frame.dest_addr_type{
			case Addr_none:
				frame.Dest_addr=nil
			default:
				if len(dest_addr)<3{
					return nil, exception.FrameErr{}.New("udp frame dest addr len too short")
				}
				addr, err := NewAddrFromByte(dest_addr[:frame.dest_addr_len-2], dest_addr[frame.dest_addr_len-2:frame.dest_addr_len], int(frame.dest_addr_type))
				if err != nil {
					return nil, err
				}
				frame.Dest_addr= addr
			}

			return frame,nil


		default:
			return nil, exception.FrameErr{}.New("unkbow frame type")
		}

	default:
		return nil, exception.FrameErr{}.New("unknow version")
	}

}

type UdpFrame struct {
	Version         byte
	frameType       byte
	ConnectionId    uint16

	local_addr_type byte
	local_addr_len  byte
	dest_addr_type  byte
	dest_addr_len   byte

	Local_addr      Addr
	Dest_addr       Addr
	Data            []byte
}

func (this *UdpFrame) ToBytes() []byte {
	ld,dd:=[]byte{},[]byte{}
	if this.Local_addr==nil{
		this.local_addr_type=Addr_none
		this.local_addr_len=0
	}else{
		this.local_addr_type=byte(this.Local_addr.Type())
		ld=bytes.Join([][]byte{this.Local_addr.ToHostBytes(),this.Local_addr.ToPortByte()},nil)
		this.local_addr_len=byte(len(ld))
	}
	if this.Dest_addr==nil{
		this.dest_addr_type=Addr_none
		this.dest_addr_len=0
	}else{
		this.dest_addr_type=byte(this.Dest_addr.Type())
		dd=bytes.Join([][]byte{this.Dest_addr.ToHostBytes(),this.Dest_addr.ToPortByte()},nil)
		this.dest_addr_len=byte(len(dd))
	}

	con_id:=[]byte{0,0}
	binary.BigEndian.PutUint16(con_id,this.ConnectionId)

	return bytes.Join([][]byte{
		{this.Version},
		{Udp_Frame},
		con_id,
		{this.local_addr_type},
		{this.local_addr_len},
		{this.dest_addr_type},
		{this.dest_addr_len},
		ld,
		dd,
		this.Data,
	},nil)
}

func (*UdpFrame) GetFrameType() byte {
	return Udp_Frame
}

func (this *UdpFrame) GetConnectionId() uint16 {
	return this.ConnectionId
}

func (this *UdpFrame) String() string {
	dest:=""
	if this.Dest_addr!=nil{
		dest=this.Dest_addr.StringWithPort()
	}
	return fmt.Sprintf(
		"frame type:udp frame , "+
			"version:%d , "+
			"connectionId:%d , "+
			"local_addr: %s , "+
			"dest_addr: %s , "+
			"data len:%d , ",
		this.Version, this.ConnectionId, this.Local_addr.StringWithPort(), dest, len(this.Data))
}
