package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"go_proxy/exception"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
)

var Crypt Crypt_interface

type Crypt_interface interface {
	Encrypt([]byte) ([]byte)
	Decrypt([]byte) ([]byte, error)
	Get_passwd() ([]byte)
	String() string
	Get_enc_len_increase() int
}

type Chacha20 struct {
	Aead     cipher.AEAD
	password []byte
}

func (cha *Chacha20) Get_enc_len_increase() int {
	return 36
}

func (cha *Chacha20) Get_passwd() []byte {
	return cha.password

}

func (cha *Chacha20) Encrypt(data []byte) []byte {

	nonce ,addition_data:= make([]byte, 12),make([]byte, 8)
	rand.Read(nonce)
	rand.Read(addition_data)
	dst := cha.Aead.Seal(nil, nonce, data, addition_data)
	return bytes.Join([][]byte{nonce,addition_data, dst}, nil)

}

func (cha *Chacha20) Decrypt(data []byte) ( []byte,  error) {
	if len(data)<12+8{
		return nil,exception.CryptErr{}.New("chacha20 recv too short data len,may be crypt method not relate or password incorrect")
	}
	dst, err := cha.Aead.Open(nil, data[:12], data[12+8:], data[12:12+8])
	if err!=nil{
		return nil,exception.CryptErr{}.New("chacha20 can not decrypt data")
	}
	return dst,nil
}

func (cha *Chacha20)String() string{
	return Enc_chacha20
}
//==========================================

type Aes256cfb struct {
	Block    cipher.Block
	password []byte
}

func (aes256 *Aes256cfb) Get_enc_len_increase() int {
	return aes.BlockSize
}

func (aes256 *Aes256cfb) Get_passwd() []byte {
	return aes256.password

}

func (aes256 *Aes256cfb) Encrypt(data []byte) ([]byte) {
	iv := make([]byte, aes.BlockSize)

	rand.Read(iv)

	encrypt := cipher.NewCFBEncrypter(aes256.Block, iv)
	enc_data := make([]byte, len(data))
	encrypt.XORKeyStream(enc_data, data)
	return bytes.Join([][]byte{iv, enc_data}, nil)
}

func (aes256 *Aes256cfb) Decrypt(data []byte) ([]byte, error) {
	if len(data)<aes.BlockSize{
		return nil,exception.CryptErr{}.New("aes-256-cfb recv too short data len,may be crypt method not relate or password incorrect")
	}
	iv := data[:aes.BlockSize]
	decrypt := cipher.NewCFBDecrypter(aes256.Block, iv)
	dec_data := make([]byte, len(data)-aes.BlockSize)
	decrypt.XORKeyStream(dec_data, data[aes.BlockSize:])
	return dec_data, nil
}



func (*Aes256cfb)String() string{
	return Enc_aes_256_cfb
}

//===============================================================

type None struct{

}

func (*None) Get_enc_len_increase() int {
	return 0
}

func (*None) Encrypt(b []byte) ([]byte) {
	return b
}

func (*None) Decrypt(b []byte) ([]byte, error) {
	return b ,nil
}

func (*None) Get_passwd() ([]byte) {
	return []byte{}
}


func ( *None)String()string {
	return Enc_none
}
//===============================================================
func Get_none_crypt()Crypt_interface{
	return &None{}
}

func Get_crypt(method, password string) (Crypt_interface,error) {
	switch method{
	case Enc_chacha20:
		aead, err := chacha20poly1305.New([]byte(password))
		if err != nil {
			return nil,err
		}
		return &Chacha20{
			Aead:     aead,
			password: []byte(password),
		},nil

	case Enc_aes_256_cfb:
		block, err := aes.NewCipher([]byte(password))
		if err != nil {
			log.Fatal(err)
		}

		return &Aes256cfb{
			Block:    block,
			password: []byte(password),
		},nil



	default:
		return nil,errors.New("unsupport encrypt method")

	}

}

