package core

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type Socks5Conn struct {
	conn net.Conn
}

func (s *Socks5Conn) Handle() error {
	defer s.conn.Close()

	method, err := s.selectAuthMethod()
	if err != nil {
		return fmt.Errorf("selectAuthMethod:%w", err)
	}

	err = s.auth(method)
	if err != nil {
		return fmt.Errorf("auth:%w", err)
	}

	return s.handleRequest()
}

// 选择验证方式
func (s *Socks5Conn) selectAuthMethod() (byte, error) {
	req, err := getAuthMethods(s.conn)
	if err != nil {
		return 0, fmt.Errorf("getAuthMethods:%w", err)
	}

	if req.Ver != VerSocks5 {
		return 0, ErrSocksVersion
	}

	fmt.Printf("客户端支持验证方式:%+v \n", req.Methods)

	// 默认使用用户名密码验证身份
	_, err = s.conn.Write(
		ReplyAuthMethod(MethodUserPass),
	)

	if err != nil {
		return 0, fmt.Errorf("reply:%w", err)
	}

	return MethodUserPass, nil
}

func (s *Socks5Conn) auth(method byte) error {
	switch method {
	case MethodNone:
		return nil

	case MethodUserPass:
		auth, err := getAuthInfo(s.conn)
		if err != nil {
			return fmt.Errorf("getAuthInfo:%w", err)
		}

		var authStatus byte = AuthStatusFailure
		if string(auth.UserName) == "test" &&
			string(auth.Password) == "test" {
			// 此处验证方式可重新扩展
			authStatus = AuthStatusSuccess
		}

		_, err = s.conn.Write(
			ReplyAuthResult(authStatus))

		if err != nil {
			return fmt.Errorf("reply error:%w", err)
		}

		if authStatus != AuthStatusSuccess {
			return ErrAuthFailed
		}
		return nil
	default:
		return ErrMethod
	}
}

func (s *Socks5Conn) handleRequest() error {
	req, err := getRequest(s.conn)
	if err != nil {
		return err
	}

	switch req.Cmd {
	case CmdConnect:
		return s.connect(req)
	case CmdUDP:
		// todo
		return nil
	case CmdBind:
		// todo
		return nil
	default:
		_, _ = s.conn.Write(NewReply(RepCmdNotSupported, nil))
		return ErrCmdNotSupport
	}
}

func (s *Socks5Conn) connect(req *Request) error {
	addr := req.getAddress()

	dstConn, err := net.DialTimeout("tcp", addr, time.Second*10)

	if err != nil {
		msg := err.Error()
		var rep byte = RepHostUnreachable
		if strings.Contains(msg, "refused") {
			rep = RepConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			rep = RepNetworkUnreachable
		}
		s.conn.Write(NewReply(rep, nil))

		return fmt.Errorf("connect to %v failed: %w", req.getAddress(), err)
	}
	defer dstConn.Close()

	bAddr, err := GetAddrByteFromString(dstConn.LocalAddr().(*net.TCPAddr).String())
	if err != nil {
		_, _ = s.conn.Write(NewReply(RepServerFailure, nil))
		return err
	}

	_, err = s.conn.Write(NewReply(RepSuccess, bAddr))
	if err != nil {
		return err
	}

	timeout := 30 * time.Second

	go func() {
		forward(s.conn, dstConn, timeout)
	}()

	return forward(dstConn, s.conn, timeout)
}

func (s *Socks5Conn) checkAllow(fAddr string) bool {
	// 此处可添加转发规则
	return true
}

// 转发流量
func forward(dst net.Conn, src net.Conn, timeout time.Duration) error {
	buffer := make([]byte, socketBufSize)
	for {
		if timeout != 0 {
			err := src.SetReadDeadline(time.Now().Add(timeout))
			if err != nil {
				return err
			}

			err = dst.SetWriteDeadline(time.Now().Add(timeout))
			if err != nil {
				return err
			}
		}
		n, err := src.Read(buffer)
		if err != nil {
			return fmt.Errorf("copy read:%w", err)
		}
		wn, err := dst.Write(buffer[0:n])

		if err != nil {
			return fmt.Errorf("copy write:%w", err)
		}
		if wn != n {
			return fmt.Errorf("copy write not full")
		}
	}
}
