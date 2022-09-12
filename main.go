package main

import (
	"fmt"
	"log"
	"os"

	"github.com/OmarTariq612/socks2conn/server"
)

func main() {
	lenArgs := len(os.Args)
	if lenArgs == 1 || lenArgs > 3 {
		fmt.Printf("usage %s [bind_addr:bind_port] server_addr:server_port\n", os.Args[0])
		return
	}

	var bindAddr, serverAddr string
	if lenArgs == 2 {
		bindAddr = ":5555"
		serverAddr = os.Args[1]
	} else {
		bindAddr = os.Args[1]
		serverAddr = os.Args[2]
	}

	r := server.NewRelayer(bindAddr, serverAddr)
	err := r.ListenAndServe()
	if err != nil {
		log.Println(err)
	}
}
