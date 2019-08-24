package exception


type AddrErr struct {
	err string
}

func (this *AddrErr) Error() string {
	return "addr error : "+this.err
}

func (this AddrErr) New(err string) *AddrErr{
	this.err=err
	return &this
}


type CryptErr struct {
	err string
}

func (this *CryptErr) Error() string {
	return "crypt error : "+this.err
}

func (this CryptErr) New(err string) *CryptErr{
	this.err=err
	return &this
}



type FrameErr struct {
	err string
}
func (this *FrameErr) Error() string {
	return "frame error : "+this.err
}

func (this FrameErr) New(err string) *FrameErr{
	this.err=err
	return &this
}





type DnsError struct{
	err string
}

func (this *DnsError) Error() string {
	return "dns error : "+this.err
}

func (this DnsError) New(err string) *DnsError{
	this.err=err
	return &this
}
