package core

import (
	"fmt"
	"net"
)

type Server interface {
	Run() error
}

type server struct {
	listenAddr string
}

func NewServer(addr string) Server {
	s := &server{
		listenAddr: addr,
	}
	return s
}

func (s *server) Run() error {
	l, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handler(conn)
	}
}

func (s *server) handler(conn net.Conn) {
	sockConn := &Socks5Conn{
		conn: conn,
	}

	err := sockConn.Handle()
	if err != nil {
		fmt.Printf("handle error , %+v \n", err)
	}
}
