package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip addres start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenIPv4   = 1 + net.IPv4len + 2 // 1addrType + ipv4 + 2port
	lenIPv6   = 1 + net.IPv6len + 2 // 1addrType + ipv6 + 2port
	lenDmBase = 1 + 1 + 2           // 1addrType + 1addrLen + 2port, plus addrLen
)

type Conn struct {
	net.Conn
	*Cipher
}

type UDP interface {
	ReadFromUDP(b []byte) (n int, src *net.UDPAddr, err error)
	Read(b []byte) (n int, err error)
	WriteToUDP(b []byte, src *net.UDPAddr) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	LocalAddr() net.Addr
	SetWriteDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
}

func NewConn(cn net.Conn, cipher *Cipher) *Conn {
	return &Conn{cn, cipher}
}

type UDPConn struct {
	UDP
	*Cipher
}

func NewUDPConn(cn UDP, cipher *Cipher) *UDPConn {
	return &UDPConn{cn, cipher}
}

type CachedUDPConn struct {
	Expired bool
	timer   *time.Timer
	UDP
}

func NewCachedUDPConn(cn UDP) *CachedUDPConn {
	return &CachedUDPConn{false, nil, cn}
}

func (c *CachedUDPConn) Check() {
	if !c.Expired {
		c.Close()
	}
}

func (c *CachedUDPConn) Close() error {
	c.Expired = true
	return c.UDP.Close()
}

func (c *CachedUDPConn) SetTimer() {
	c.timer = time.AfterFunc(readTimeout, c.Check)
}

func (c *CachedUDPConn) Refresh() bool {
	return c.timer.Reset(readTimeout)
}

type NATlist struct {
	sync.Mutex
	Conns map[string]*CachedUDPConn
}

func (nl *NATlist) Get(srcaddr, dstaddr *net.UDPAddr, cn *UDPConn, header []byte) (c *CachedUDPConn, ok bool, err error) {
	nl.Lock()
	defer nl.Unlock()
	index := srcaddr.String() + dstaddr.String()
	_, ok = nl.Conns[index]
	if !ok || nl.Conns[index].Expired {
		//NAT not exists or expired
		delete(nl.Conns, index)
		ok = false
		conn, err := net.DialUDP("udp", nil, dstaddr)
		if err != nil {
			return nil, false, err
		}
		nl.Conns[index] = NewCachedUDPConn(conn)
		c, _ = nl.Conns[index]
		c.SetTimer()
		go Pipeloop(cn, srcaddr, c, header)
	} else {
		//NAT exists
		c, _ = nl.Conns[index]
		c.Refresh()
	}
	err = nil
	return
}

func Pipeloop(c *UDPConn, srcaddr *net.UDPAddr, remote UDP, header []byte) {
	buf := udpBuf.Get()
	defer udpBuf.Put(buf)
	l := len(header)
	copy(buf, header)
	for {
		remote.SetReadDeadline(time.Now().Add(readTimeout))
		n, err := remote.Read(buf[l:])
		if err != nil {
			if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
				// log too many open file error
				// EMFILE is process reaches open file limits, ENFILE is system limit
				fmt.Println("[udp]read error:", err)
			} else {
				fmt.Println("[udp]error connecting to:", srcaddr, err)
			}
			return
		}
		_, err = c.WriteToUDP(buf[:l+n], srcaddr)
		if err != nil {
			return
		}
	}
}

func (nl *NATlist) Checkall() {
	nl.Lock()
	closed := 0
	total := 0
	for k, v := range nl.Conns {
		if v.Expired {
			closed += 1
			delete(nl.Conns, k)
		} else {
			total += 1
		}
	}
	nl.Unlock()
	time.AfterFunc(readTimeout, nl.Checkall)
	if total == 0 && closed == 0 {
		return
	}
	fmt.Println("[udp]Alive Connections:", total, "Closed Connections:", closed)

	return
}

func InitNAT() {
	time.AfterFunc(readTimeout, nl.Checkall)
}

var nl = NATlist{Conns: map[string]*CachedUDPConn{}}

var udpBuf = NewLeakyBuf(nBuf, bufSize)

func (c *UDPConn) handleUDPConnection(n int, src *net.UDPAddr, receive []byte) {
	var dstIP net.IP
	var reqLen int
	defer udpBuf.Put(receive)

	switch receive[idType] {
	case typeIPv4:
		reqLen = lenIPv4
		dstIP = net.IP(receive[idIP0 : idIP0+net.IPv4len])
	case typeIPv6:
		reqLen = lenIPv6
		dstIP = net.IP(receive[idIP0 : idIP0+net.IPv6len])
	case typeDm:
		reqLen = int(receive[idDmLen]) + lenDmBase
		dIP, err := net.ResolveIPAddr("ip", string(receive[idDm0:idDm0+receive[idDmLen]]))
		if err != nil {
			fmt.Sprintf("[udp]failed to resolve domain name: %s\n", string(receive[idDm0:idDm0+receive[idDmLen]]))
			return
		}
		dstIP = dIP.IP
	default:
		fmt.Sprintf("[udp]addr type %d not supported", receive[idType])
		return
	}
	req := make([]byte, reqLen)
	for i := 0; i < reqLen; i++ {
		req[i] = receive[i]
	}
	dst := &net.UDPAddr{
		IP:   dstIP,
		Port: int(binary.BigEndian.Uint16(receive[reqLen-2 : reqLen])),
	}
	remote, _, err := nl.Get(src, dst, c, req)
	if err != nil {
		return
	}
	remote.SetWriteDeadline(time.Now().Add(readTimeout))
	_, err = remote.Write(receive[reqLen:n])
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			fmt.Println("[udp]write error:", err)
		} else {
			fmt.Println("[udp]error connecting to:", dst, err)
		}
		return
	}
	// Pipeloop
	return
}

func (c *UDPConn) ReadAndHandleUDPReq() {
	buf := udpBuf.Get()
	n, src, err := c.ReadFromUDP(buf[0:])
	if err != nil {
		return
	}
	go c.handleUDPConnection(n, src, buf)
}

func RawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: address error %s %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: invalid port %s", addr)
	}

	hostLen := len(host)
	l := 1 + 1 + hostLen + 2 // addrType + lenByte + address + port
	buf = make([]byte, l)
	buf[0] = 3             // 3 means the address is domain name
	buf[1] = byte(hostLen) // host address length  followed by host address
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+hostLen:2+hostLen+2], uint16(port))
	return
}

// This is intended for use by users implementing a local socks proxy.
// rawaddr shoud contain part of the data in socks request, starting from the
// ATYP field. (Refer to rfc1928 for more information.)
func DialWithRawAddr(rawaddr []byte, server string, cipher *Cipher) (c *Conn, err error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}
	c = NewConn(conn, cipher)
	if _, err = c.Write(rawaddr); err != nil {
		c.Close()
		return nil, err
	}
	return
}

// addr should be in the form of host:port
func Dial(addr, server string, cipher *Cipher) (c *Conn, err error) {
	ra, err := RawAddr(addr)
	if err != nil {
		return
	}
	return DialWithRawAddr(ra, server, cipher)
}

//n is the size of the payload
func (c *UDPConn) ReadFromUDP(b []byte) (n int, src *net.UDPAddr, err error) {
	buf := udpBuf.Get()
	n, src, err = c.UDP.ReadFromUDP(buf[0:])
	if err != nil {
		return
	}
	defer udpBuf.Put(buf)

	iv := buf[:c.info.ivLen]
	if err = c.initDecrypt(iv); err != nil {
		return
	}
	c.decrypt(b[0:n-c.info.ivLen], buf[c.info.ivLen:n])
	n = n - c.info.ivLen
	return
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	buf := udpBuf.Get()
	n, err = c.UDP.Read(buf[0:])
	if err != nil {
		return
	}
	defer udpBuf.Put(buf)

	iv := buf[:c.info.ivLen]
	if err = c.initDecrypt(iv); err != nil {
		return
	}
	c.decrypt(b[0:n-c.info.ivLen], buf[c.info.ivLen:n])
	n = n - c.info.ivLen
	return
}

//n = iv + payload
func (c *UDPConn) WriteToUDP(b []byte, src *net.UDPAddr) (n int, err error) {
	var cipherData []byte
	dataStart := 0

	var iv []byte
	iv, err = c.initEncrypt()
	if err != nil {
		return
	}
	// Put initialization vector in buffer, do a single write to send both
	// iv and data.
	cipherData = make([]byte, len(b)+len(iv))
	copy(cipherData, iv)
	dataStart = len(iv)

	c.encrypt(cipherData[dataStart:], b)
	n, err = c.UDP.WriteToUDP(cipherData, src)
	return
}

func (c *UDPConn) Write(b []byte) (n int, err error) {
	var cipherData []byte
	dataStart := 0

	var iv []byte
	iv, err = c.initEncrypt()
	if err != nil {
		return
	}
	// Put initialization vector in buffer, do a single write to send both
	// iv and data.
	cipherData = make([]byte, len(b)+len(iv))
	copy(cipherData, iv)
	dataStart = len(iv)

	c.encrypt(cipherData[dataStart:], b)
	n, err = c.UDP.Write(cipherData)
	return
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.dec == nil {
		iv := make([]byte, c.info.ivLen)
		if _, err = io.ReadFull(c.Conn, iv); err != nil {
			return
		}
		if err = c.initDecrypt(iv); err != nil {
			return
		}
	}
	cipherData := make([]byte, len(b))
	n, err = c.Conn.Read(cipherData)
	if n > 0 {
		c.decrypt(b[0:n], cipherData[0:n])
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	var cipherData []byte
	dataStart := 0
	if c.enc == nil {
		var iv []byte
		iv, err = c.initEncrypt()
		if err != nil {
			return
		}
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		cipherData = make([]byte, len(b)+len(iv))
		copy(cipherData, iv)
		dataStart = len(iv)
	} else {
		cipherData = make([]byte, len(b))
	}
	c.encrypt(cipherData[dataStart:], b)
	n, err = c.Conn.Write(cipherData)
	return
}
