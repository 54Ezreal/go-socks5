package main

import (
	"fmt"
	"go-socks5/core"
	"os"
	"os/signal"
)

func main() {
	server := core.NewServer(":4040")
	server.Run()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	s := <-c
	fmt.Println("quit,Got signal:", s)
}
