package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const socksServerVersion byte = 5

// o  X'00' NO AUTHENTICATION REQUIRED
// o  X'01' GSSAPI
// o  X'02' USERNAME/PASSWORD
// o  X'03' to X'7F' IANA ASSIGNED
// o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
// o  X'FF' NO ACCEPTABLE METHODS
const (
	noAuthMethodRequired byte = 0x00
	noAcceptableMethod   byte = 0xFF
)

type command byte

const (
	connect      command = 1
	bind         command = 2
	udpAssociate command = 3
)

type addrType byte

const (
	ipv4       addrType = 1
	domainname addrType = 3
	ipv6       addrType = 4
)

type resultCode byte

const (
	succeeded               resultCode = 0
	generalSocksFailure     resultCode = 1
	connectionNotAllowed    resultCode = 2
	networkUnreachable      resultCode = 3
	hostUnreachable         resultCode = 4
	connectionRefused       resultCode = 5
	ttlExpired              resultCode = 6
	commandNotSupported     resultCode = 7
	addressTypeNotSupported resultCode = 8
)

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
	err := handleHandshake(c.conn)
	if err != nil {
		return "", err
	}

	req, err := parseRequest(c.conn)
	if err != nil {
		c.sendFailure(generalSocksFailure)
		return "", err
	}
	c.req = req

	if c.req.cmd != connect {
		c.sendFailure(commandNotSupported)
		return "", fmt.Errorf("inacceptable command: %v", c.req.cmd)
	}

	rep := &reply{resCode: succeeded, addressType: ipv4, bindAddr: "0.0.0.0", bindPort: 0}
	buf, err := rep.marshal()
	if err != nil {
		c.sendFailure(generalSocksFailure)
		return "", err
	}

	_, err = c.conn.Write(buf)
	if err != nil {
		return "", err
	}

	return net.JoinHostPort(c.req.destHost, strconv.Itoa(int(c.req.destPort))), nil
}

func (c *client) sendFailure(code resultCode) error {
	// rep := &reply{resCode: code}
	rep := &reply{resCode: code, addressType: ipv4, bindAddr: "0.0.0.0", bindPort: 0}
	buf, _ := rep.marshal()
	_, err := c.conn.Write(buf)
	return err
}

func handleHandshake(conn net.Conn) error {
	var nAuthMethods [1]byte
	_, err := io.ReadFull(conn, nAuthMethods[:])
	if err != nil {
		return fmt.Errorf("could not read len of methods (handshake)")
	}
	authMethods := make([]byte, nAuthMethods[0])
	_, err = io.ReadFull(conn, authMethods)
	if err != nil {
		return fmt.Errorf("could not read the list of auth methods (handshake)")
	}
	for _, method := range authMethods {
		if method == noAuthMethodRequired {
			_, err = conn.Write([]byte{socksServerVersion, noAuthMethodRequired})
			if err != nil {
				return fmt.Errorf("could not write handshake reply (nnoAuthMethodRequired): %v", err)
			}
			return nil
		}
	}

	_, err = conn.Write([]byte{socksServerVersion, noAcceptableMethod})
	if err != nil {
		return fmt.Errorf("could not write handshake reply (noAcceptableMethod): %v", err)
	}
	return fmt.Errorf("no auth method is accepted")
}

// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
type request struct {
	cmd         command
	addressType addrType
	destHost    string
	destPort    uint16
}

func parseRequest(conn net.Conn) (*request, error) {
	var buf [4]byte
	_, err := io.ReadFull(conn, buf[:])
	if err != nil {
		return nil, fmt.Errorf("could not read request header")
	}
	cmd := command(buf[1])
	addressType := addrType(buf[3])
	var destHost string
	switch addressType {
	case ipv4:
		var addr [4]byte
		_, err = io.ReadFull(conn, addr[:])
		if err != nil {
			return nil, fmt.Errorf("could not read dest IPv4 address (in request header)")
		}
		destHost = net.IP(addr[:]).String()
	case domainname:
		var length [1]byte
		_, err = io.ReadFull(conn, length[:])
		if err != nil {
			return nil, fmt.Errorf("could not read dest domain name length (in request header)")
		}
		buf := make([]byte, length[0])
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			return nil, fmt.Errorf("could not read the dest domain name (in request header)")
		}
		destHost = string(buf)
	case ipv6:
		var addr [16]byte
		_, err = io.ReadFull(conn, addr[:])
		if err != nil {
			return nil, fmt.Errorf("could not read dest IPv6 address (in request header)")
		}
		destHost = net.IP(addr[:]).String()
	default:
		return nil, fmt.Errorf("invalid address type code -> (%v) <-", addressType)
	}
	var portBuf [2]byte
	_, err = io.ReadFull(conn, portBuf[:])
	if err != nil {
		return nil, fmt.Errorf("could not read dest port (in request header)")
	}
	destPort := binary.BigEndian.Uint16(portBuf[:])
	return &request{cmd: cmd, addressType: addressType, destHost: destHost, destPort: destPort}, nil
}

// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
type reply struct {
	resCode     resultCode
	addressType addrType
	bindAddr    string
	bindPort    uint16
}

func (r *reply) marshal() ([]byte, error) {
	buf := []byte{
		socksServerVersion,
		byte(r.resCode),
		0,
		byte(r.addressType),
	}
	var bindAddrBinary []byte
	switch r.addressType {
	case ipv4:
		bindAddrBinary = net.ParseIP(r.bindAddr).To4()
		if bindAddrBinary == nil {
			return nil, fmt.Errorf("invalid IPv4 address (in reply header)")
		}
	case domainname:
		if len(r.bindAddr) > 255 {
			return nil, fmt.Errorf("invalid domain name (in reply header)")
		}
		bindAddrBinary = make([]byte, 0, len(r.bindAddr)+1)
		bindAddrBinary = append(bindAddrBinary, byte(len(r.bindAddr)))
		bindAddrBinary = append(bindAddrBinary, []byte(r.bindAddr)...)
	case ipv6:
		bindAddrBinary = net.ParseIP(r.bindAddr).To16()
		if bindAddrBinary == nil {
			return nil, fmt.Errorf("invalid IPv6 address (in replyl header)")
		}
	default:
		return nil, fmt.Errorf("invalid address type code -> (%v) <- (in reply header)", r.addressType)
	}
	var bindPortBinary [2]byte
	binary.BigEndian.PutUint16(bindPortBinary[:], r.bindPort)
	buf = append(buf, bindAddrBinary...)
	buf = append(buf, bindPortBinary[:]...)
	return buf, nil
}
