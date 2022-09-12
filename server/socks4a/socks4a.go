package socks4a

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

type command byte

const (
	connect command = 1
	bind    command = 2
)

type resultCode byte

// 90: request granted
// 91: request rejected or failed
// 92: request rejected becasue SOCKS server cannot connect to identd on the client
// 93: request rejected because the client program and identd report different user-ids.
const (
	requestGranted               resultCode = 90
	requestRejectedOrFailed      resultCode = 91
	requestRejectedCannotConnect resultCode = 92
	requestRejectedDiffUserIds   resultCode = 93
)

// const timeoutDuration time.Duration = 5 * time.Second

func HandleConnection(conn net.Conn) (string, error) {
	c := newClient(conn)
	return c.handle()
}

type client struct {
	conn net.Conn
	req  *request
}

func newClient(conn net.Conn) *client {
	return &client{conn: conn}
}

func (c *client) handle() (string, error) {
	req, err := parseRequest(c.conn)
	if err != nil {
		return "", err
	}
	c.req = req

	if err != nil {
		c.sendFailure(requestRejectedOrFailed)
		return "", err
	}

	if c.req.cmd != connect {
		c.sendFailure(requestRejectedCannotConnect)
		return "", err
	}

	rep := &reply{resCode: requestGranted, bindAddr: "0.0.0.0", bindPort: 0}
	buf, err := rep.marshal()
	if err != nil {
		c.sendFailure(requestRejectedOrFailed)
		return "", err
	}

	_, err = c.conn.Write(buf)
	if err != nil {
		return "", err
	}

	return net.JoinHostPort(c.req.destHost, strconv.Itoa(int(c.req.destPort))), nil
}

func (c *client) sendFailure(code resultCode) error {
	rep := &reply{resCode: code, bindAddr: "0.0.0.0", bindPort: 0}
	buf, _ := rep.marshal()
	_, err := c.conn.Write(buf)
	return err
}

// +----+----+----+----+----+----+----+----+----+----+....+----+
// | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
// +----+----+----+----+----+----+----+----+----+----+....+----+
//    1    1      2              4           variable       1
type request struct {
	cmd      command
	destHost string
	destPort uint16
}

func parseRequest(conn net.Conn) (*request, error) {
	var buf [7]byte
	_, err := io.ReadFull(conn, buf[:])
	if err != nil {
		return nil, fmt.Errorf("could not read request header")
	}
	var oneByteBuf [1]byte
	for {
		_, err = io.ReadFull(conn, oneByteBuf[:])
		if err != nil {
			return nil, fmt.Errorf("could not read (a byte) from the userid")
		}
		if oneByteBuf[0] == 0 {
			break
		}
	}
	cmd := command(buf[0])
	destPort := binary.BigEndian.Uint16(buf[1:3])
	var destHost string
	if isDomainUnresolved(buf[3:7]) {
		domainName := make([]byte, 0, 20) // this is an estimate of the domain name length
		for {
			_, err = io.ReadFull(conn, oneByteBuf[:])
			if err != nil {
				return nil, fmt.Errorf("could not read (a byte) from the domain name")
			}
			if oneByteBuf[0] == 0 {
				break
			}
			domainName = append(domainName, oneByteBuf[0])
		}
		destHost = string(domainName)
	} else {
		destHost = net.IP(buf[3:7]).String()
	}
	return &request{cmd: cmd, destHost: destHost, destPort: destPort}, nil
}

func isDomainUnresolved(ip []byte) bool {
	return bytes.Equal(ip[:3], []byte{0, 0, 0}) && ip[3] != 0 // IP address 0.0.0.x
}

// +----+----+----+----+----+----+----+----+
// | VN | CD | DSTPORT |      DSTIP        |
// +----+----+----+----+----+----+----+----+
//    1    1      2              4
type reply struct {
	resCode  resultCode
	bindAddr string
	bindPort uint16
}

func (r *reply) marshal() ([]byte, error) {
	buf := make([]byte, 2, 8)
	buf[0] = 0
	buf[1] = byte(r.resCode)
	var bindPortBinary [2]byte
	binary.BigEndian.PutUint16(bindPortBinary[:], r.bindPort)
	bindAddrBinary := net.ParseIP(r.bindAddr).To4()
	if bindAddrBinary == nil {
		return nil, fmt.Errorf("invalid IPv4 address (in reply header)")
	}
	buf = append(buf, bindPortBinary[:]...)
	buf = append(buf, bindAddrBinary...)
	return buf, nil
}
