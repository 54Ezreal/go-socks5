package core

import (
	"errors"
	"fmt"
)

const socketBufSize = 64 * 1024

const (
	VerSocks5  = 0x05
	MethodNone = 0x00

	MethodUserPass     = 0x02
	MethodNoAcceptable = 0xff

	VerAuthUserPass   = 0x01
	AuthStatusSuccess = 0x00
	AuthStatusFailure = 0x01

	CmdConnect     = 0x01
	CmdBind        = 0x02
	CmdUDP         = 0x03
	ATypIPV4       = 0x01
	ATypDomainName = 0x03
	ATypIPV6       = 0x04

	RepSuccess              = 0x00
	RepServerFailure        = 0x01
	RepRuleFailure          = 0x02
	RepNetworkUnreachable   = 0x03
	RepHostUnreachable      = 0x04
	RepConnectionRefused    = 0x05
	RepTTLExpired           = 0x06
	RepCmdNotSupported      = 0x07
	RepAddrTypeNotSupported = 0x08
)

var (
	ErrMethodNoAcceptable = errors.New("no acceptable method")
	ErrAuthFailed         = errors.New("user authentication failed")
	NoSupportedAuth       = errors.New("no supported auth")
	ErrAuthUserPassVer    = errors.New("auth user pass version")
	ErrCmdNotSupport      = errors.New("cmd not support")
	ErrAcceptHost         = errors.New("host not allow accept")

	ErrConnectFailed = errors.New("connect failed")
	ErrReply         = errors.New("reply error")

	ErrAddrType     = fmt.Errorf("unrecognized address type")
	ErrSocksVersion = fmt.Errorf("not socks version 5")
	ErrMethod       = fmt.Errorf("unsupport method")
	ErrBadRequest   = fmt.Errorf("bad request")
	ErrUDPFrag      = fmt.Errorf("frag !=0 not supported")
)
