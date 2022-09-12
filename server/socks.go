package server

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/OmarTariq612/socks2conn/server/socks4a"
	"github.com/OmarTariq612/socks2conn/server/socks5"
)

const (
	socksVersion4 byte = 4
	socksVersion5 byte = 5
)

type Relayer struct {
	bindAddr   string // socks
	serverAddr string // proxy server
}

func NewRelayer(bindAddr, serverAddr string) *Relayer {
	return &Relayer{bindAddr: bindAddr, serverAddr: serverAddr}
}

func (s *Relayer) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.bindAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Println("Serving on", s.bindAddr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			var buf [1]byte
			_, err := io.ReadFull(conn, buf[:])
			if err != nil {
				log.Println(err)
				return
			}
			var addr string
			switch buf[0] {
			case socksVersion4:
				addr, err = socks4a.HandleConnection(conn)
			case socksVersion5:
				addr, err = socks5.HandleConnection(conn)
			default:
				log.Printf("unacceptable socks version -> (%d) <-", buf[0])
				return
			}

			if err != nil {
				log.Println(err)
				return
			}

			serverConn, err := net.DialTimeout("tcp", s.serverAddr, 7*time.Second)
			if err != nil {
				log.Printf("could not establish connection to the server: %v", err)
				return
			}
			defer serverConn.Close()

			req, err := http.NewRequest(http.MethodConnect, "", nil)
			if err != nil {
				log.Printf("could not create connect request: %v", err)
				return
			}
			req.Host = addr
			req.Header.Set("Proxy-Connection", "keep-alive")

			err = req.Write(serverConn)
			if err != nil {
				log.Printf("could not write the request: %v", err)
				return
			}

			resp, err := http.ReadResponse(bufio.NewReader(serverConn), req)
			if err != nil {
				log.Printf("could not read the response: %v", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				log.Printf("not ok, %v, %v\n", resp.StatusCode, req.Host)
				return
			}

			// io.Copy(io.Discard, resp.Body)

			errc := make(chan error, 2)
			go func() {
				_, err = io.Copy(serverConn, conn)
				if err != nil {
					err = fmt.Errorf("could not copy from client to server: %v", err)
				}
				errc <- err
			}()

			go func() {
				_, err = io.Copy(conn, serverConn)
				if err != nil {
					err = fmt.Errorf("could not copy from server to client: %v", err)
				}
				errc <- err
			}()

			err = <-errc

			// serverConn, err := net.DialTimeout("tcp", addr, 7*time.Second)
			// if err != nil {
			// 	log.Println(err)
			// 	return
			// }
			// defer serverConn.Close()

			// errc := make(chan error, 2)
			// go func() {
			// 	_, err = io.Copy(serverConn, conn)
			// 	if err != nil {
			// 		err = fmt.Errorf("could not copy from client to server: %v", err)
			// 	}
			// 	errc <- err
			// }()
			// go func() {
			// 	_, err = io.Copy(conn, serverConn)
			// 	if err != nil {
			// 		err = fmt.Errorf("could not copy from server to client: %v", err)
			// 	}
			// 	errc <- err
			// }()
			// err = <-errc

			if err != nil {
				log.Println(err)
			}
		}()
	}
}
