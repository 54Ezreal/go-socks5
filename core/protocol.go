package core

import (
	"io"
)

type AuthMethodReq struct {
	Ver byte // SOCKS 的版本

	NMethods byte // METHODS的长度

	Methods []byte // 客户端支持的验证方式
}

// 获取客户端所支持的验证方式
func getAuthMethods(r io.Reader) (*AuthMethodReq, error) {
	b := make([]byte, 2)
	_, err := io.ReadFull(r, b)

	if err != nil {
		return nil, err
	}

	nMethod := int(b[1])

	methods := make([]byte, nMethod)

	_, err = io.ReadFull(r, methods)

	if err != nil {
		return nil, err
	}

	return &AuthMethodReq{
		Ver:      b[0],
		NMethods: b[1],
		Methods:  methods,
	}, nil
}

func ReplyAuthMethod(method byte) []byte {
	return []byte{VerSocks5, method}
}

type UserPassAuthReq struct {
	Ver      byte
	ULen     byte
	UserName []byte
	PLen     byte
	Password []byte
}

// 获取用户名密码
func getAuthInfo(r io.Reader) (*UserPassAuthReq, error) {
	b := make([]byte, 1)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}

	ver := b[0]

	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}

	uLen := int(b[0])
	userName := make([]byte, uLen)
	_, err = io.ReadFull(r, userName)
	if err != nil {
		return nil, err
	}

	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}

	pLen := int(b[0])
	password := make([]byte, pLen)
	_, err = io.ReadFull(r, password)
	if err != nil {
		return nil, err
	}

	return &UserPassAuthReq{
		Ver:      ver,
		ULen:     byte(uLen),
		UserName: userName,
		PLen:     byte(pLen),
		Password: password,
	}, nil
}

func ReplyAuthResult(status byte) []byte {
	return []byte{VerAuthUserPass, status}
}

type Request struct {
	Ver     byte
	Cmd     byte
	Rsv     byte //0x00
	Atyp    byte
	DstAddr []byte
	DstPort []byte //2 bytes
}

func (req *Request) ToBytes() []byte {
	ret := []byte{req.Ver, req.Cmd, req.Rsv, req.Atyp}
	ret = append(ret, req.DstAddr...)
	ret = append(ret, req.DstPort...)
	return ret
}

//  获取客户端想要访问的真实地址
func getRequest(r io.Reader) (*Request, error) {
	// extract socks5 request
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	b := []byte{0, 0, 0}
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}

	addrByte, err := GetAddrByteFromReader(r)
	if err != nil {
		return nil, err
	}

	aType, addr, port := addrByte.Split()

	return &Request{
		Ver:     b[0],
		Cmd:     b[1],
		Rsv:     b[2],
		Atyp:    aType,
		DstAddr: addr,
		DstPort: port,
	}, nil
}

func (req *Request) getAddress() string {
	var bAddr []byte
	bAddr = append(bAddr, req.Atyp)
	bAddr = append(bAddr, req.DstAddr...)
	bAddr = append(bAddr, req.DstPort...)
	return AddrByte(bAddr).String()
}

func NewReply(rep byte, addrByte AddrByte) []byte {
	aType, addr, port := addrByte.Split()

	ret := []byte{VerSocks5, rep, 0, aType}

	ret = append(ret, addr...)
	ret = append(ret, port...)

	return ret
}
