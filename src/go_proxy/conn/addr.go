package conn

import (
	"encoding/binary"
	"fmt"
	"go_proxy/exception"
	"go_proxy/util"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
)

var (
	rlock = &sync.RWMutex{}
)

type Addr interface {
	String() string
	StringWithPort() string
	ToHostBytes() []byte
	ToPortByte() []byte
	Type() int
	IsChinaAddr() bool
	IsDomain() bool
	ToPortInt()  int
}

type AddrIPPort struct {
	ip          []byte
	port        [2]byte
	_type       int
	is_cn       bool
	is_cn_check bool
}



func (this *AddrIPPort) parseFromString(s string, _type int) (Addr, error) {
	var (
		sp []string
		ip []byte
	)
	ip_len := 0
	switch _type {
	case Addr_type_ipv4:
		sp = strings.Split(s, ":")
		ip = net.ParseIP(sp[0]).To4()
		if ip == nil {
			return nil, (&exception.AddrErr{}).New("ipv4 ip format illegal")
		}
		ip_len = 4

	case Addr_type_ipv6:
		sp = strings.Split(s, "]:")
		if len(sp[0])<1{
			return nil, (&exception.AddrErr{}).New("ipv6 ip format illegal")
		}
		sp[0]=sp[0][1:]
		ip = net.ParseIP(sp[0]).To16()
		if ip == nil {
			return nil, (&exception.AddrErr{}).New("ipv6 ip format illegal")
		}
		ip_len = 16
	default:
		panic("unknow error")
	}

	port, err := strconv.Atoi(sp[1])
	if err != nil || port > 65535 {
		return nil, (&exception.AddrErr{}).New("ipv4 port illegal")
	}
	this.ip = make([]byte, ip_len)
	for i := 0; i < ip_len; i++ {
		this.ip[i] = ip[i]
	}
	binary.BigEndian.PutUint16(this.port[:], uint16(port))
	this._type = _type
	return this, nil
}

func (this *AddrIPPort) Type() int {
	return this._type
}

func (this *AddrIPPort) String() string {
	return net.IP(this.ip).String()
}

func (this *AddrIPPort) StringWithPort() string {
	if this._type == Addr_type_ipv6 {
		return fmt.Sprintf("[%s]:%d", net.IP(this.ip).String(), this.ToPortInt())
	} else {
		return net.IP(this.ip).String() + ":" + strconv.Itoa(this.ToPortInt())
	}

}

func (this *AddrIPPort) ToHostBytes() []byte {
	return this.ip
}

func (this *AddrIPPort) ToPortByte() []byte {
	return this.port[:]
}

func (this *AddrIPPort) ToPortInt() int {
	return (int(this.port[0])<<8)+int(this.port[1])
}

func (this *AddrIPPort) IsDomain() bool {
	return false
}

func (this *AddrIPPort) IsChinaAddr() bool {
	if this.is_cn_check {
		return this.is_cn
	}
	defer func() {
		this.is_cn_check = true
	}()
	if this._type == Addr_type_ipv6 {
		for mask := 1; mask <= 128; mask++ {
			i := mask / 8
			j := mask % 8
			m := make([]byte, 16)
			k := 0
			for ; k < i; k++ {
				m[k] = 255
			}
			if j != 0 {
				m[k] = byte(math.Pow(2, float64(j))) - 1
			}

			ip := make([]byte, 16)
			copy(ip, this.ip)
			for l := 0; l < 16; l++ {
				ip[l] = this.ip[l] & m[l]
			}

			rlock.RLock()
			__mask, ok := util.Local_ipv6[net.IP(ip).To16().String()]
			rlock.RUnlock()
			if ok && __mask == mask {
				this.is_cn = true
				return true
			}

		}
		this.is_cn = false
		return false
	} else {
		l := uint(len(this.ip))
		var dest_ipint uint = 0
		var i uint = 0
		for ; i < l; i++ {
			dest_ipint += uint(this.ip[i]) << uint(((l - i - 1) * 8))
		}
		for mask := 1; mask <= 32; mask++ {
			rlock.RLock()
			v, ok := util.China_ipv4[dest_ipint&(uint((math.Pow(2, float64(mask)))-1)<<uint(32-mask))]
			rlock.RUnlock()
			if ok && v == mask {
				this.is_cn = true
				return true

			}
		}

		this.is_cn = false
		return false
	}

}

type Domain struct {
	domain      string
	port        uint16
	_type       int
	is_cn       bool
	is_cn_check bool
}



func (this *Domain) parseFromString(s string, try6 bool) (Addr, error) {
	sp := strings.Split(s, ":")

	d := sp[0]
	//if len(d) < 3 || d[0] == '.' || d[len(d)-1] == '.' || len(strings.Split(d, ".")) < 2 {
	//	return nil, (&exception.AddrErr{}).New("domain format illegal")
	//}
	if len(d) > 255 {
		return nil, (&exception.AddrErr{}).New("domain format illegal")
	}

	this.domain = d

	port, err := strconv.Atoi(sp[1])
	if err != nil || port > 65535 || port <= 0 {
		return nil, (&exception.AddrErr{}).New("port illegal")
	}

	this.port = uint16(port)

	if try6 {
		this._type = Addr_domain_try_ipv6
	} else {
		this._type = Addr_domain
	}

	return this, nil
}

func (this *Domain) Type() int {
	return this._type
}

func (this *Domain) String() string {
	return this.domain
}

func (this *Domain) StringWithPort() string {
	return this.domain + ":" + strconv.Itoa(int(this.port))
}

func (this *Domain) ToHostBytes() []byte {
	return []byte(this.domain)
}

func (this *Domain) ToPortByte() []byte {
	b := [2]byte{}
	binary.BigEndian.PutUint16(b[:], this.port)
	return b[:]
}
func (this *Domain) ToPortInt() int {
	return int(this.port)
}


func (this *Domain) IsChinaAddr() bool {
	if this.is_cn_check {
		return this.is_cn
	}
	defer func() {
		this.is_cn_check = true
	}()

	if this.domain == "" {
		this.is_cn=true
		return true
	}

	rlock.RLock()
	if _, ok := util.Cn_domain_map[this.String()];ok{
		this.is_cn=true
		return true
	}
	rlock.RUnlock()

	_domain := strings.Split(this.domain, ".")
	if _domain[len(_domain)-1] == "cn" {
		this.is_cn=true
		return true
	}

	d := ""
	if len(_domain) == 1 {
		this.is_cn=true
		return true
	} else {
		d = strings.Join(_domain[len(_domain)-2:], ".")
	}
	rlock.RLock()
	_, ok := util.Cn_domain_map[d]
	rlock.RUnlock()

	this.is_cn = ok
	return ok
}

func (this *Domain) IsDomain() bool {
	return true
}

func NewAddrFromString(addr string, domain_try_ipv6 bool) (Addr, error) {
	if len(addr) < 4 {
		return nil, exception.AddrErr{}.New("addr format illegal")
	}

	var sp []string
	if addr[0] == '[' {
		sp = strings.Split(addr, "]:")
		if len(sp[0])<1{
			return nil, exception.AddrErr{}.New("addr format illegal")
		}else{
			sp[0]=sp[0][1:]
		}

	} else {
		sp = strings.Split(addr, ":")
	}

	if len(sp) != 2 {
		return nil, exception.AddrErr{}.New("addr format illegal")
	}

	if len(sp[0]) > 255 {
		return nil, exception.AddrErr{}.New("addr too long")
	}
	if net.ParseIP(sp[0]).To4() != nil {
		return (&AddrIPPort{}).parseFromString(addr, Addr_type_ipv4)
	}
	if net.ParseIP(sp[0]).To16() != nil {
		return (&AddrIPPort{}).parseFromString(addr, Addr_type_ipv6)
	}
	return (&Domain{}).parseFromString(addr, domain_try_ipv6)

}

func NewAddrFromByte(d, port []byte, _type int) (Addr, error) {

	var addr Addr
	if len(port) != 2 {
		return nil, exception.AddrErr{}.New(" port bytes len illegal")
	}
	switch _type {
	case Addr_type_ipv6:
		if len(d) != 16 {
			return nil, exception.AddrErr{}.New("ip bytes len illegal")
		}
		addr = &AddrIPPort{
			ip:    d,
			port:  [2]byte{port[0], port[1]},
			_type: _type,
		}

	case Addr_type_ipv4:
		if len(d) != 4 {
			return nil, exception.AddrErr{}.New("ip bytes len illegal")
		}
		addr = &AddrIPPort{
			ip:    d,
			port:  [2]byte{port[0], port[1]},
			_type: _type,
		}
	case Addr_domain_try_ipv6, Addr_domain:
		if len(d) > 255 {
			return nil, exception.AddrErr{}.New("domain len too long")
		}
		addr = &Domain{
			domain: string(d),
			port:   (uint16(port[0]) << 8) + uint16(port[1]),
			_type:  _type,
		}

	default:
		return nil, exception.AddrErr{}.New("addr type illegal")
	}

	return addr, nil
}

