package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"flow"
	"fmt"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var debug ss.DebugLog

const dnsGoroutineNum = 64

func getRequest(conn *ss.Conn) (host string, extra []byte, err error) {
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

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port)
	buf := make([]byte, 260)

	var n int
	// read till we get possible domain length field
	ss.SetReadTimeout(conn)
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}

	//fmt.Println(buf)

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = fmt.Errorf("addr type %d not supported", buf[idType])
		return
	}

	if n < reqLen { // rare case
		ss.SetReadTimeout(conn)
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else if n > reqLen {
		// it's possible to read more than just the request head
		extra = buf[reqLen:n]
	}

	tp := strings.Split(conn.LocalAddr().String(), ":")
	if len(tp) == 2 {
		p := tp[1]
		now := time.Now().Format("2006-01-02 15:04:05")
		if len(flowData.Usage[p]) == 0 {
			flowData.Usage[p] = []string{"0", now}
		}

		used, _ := strconv.ParseUint(flowData.Usage[p][0], 10, 64)
		used += uint64(n - reqLen)
		flowData.Usage[p][0] = strconv.FormatUint(used, 10)
		flowData.Usage[p][1] = now
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch buf[idType] {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	// parse port
	port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])

	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

const logCntDelta = 100

var connCnt int
var nextLogConnCnt int = logCntDelta

func handleConnection(conn *ss.Conn, port string) {
	var host string

	//fmt.Println(strings.Split(conn.LocalAddr().String(), ":")[1])

	connCnt++ // this maybe not accurate, but should be enough
	if connCnt-nextLogConnCnt >= 0 {
		// XXX There's no xadd in the atomic package, so it's difficult to log
		// the message only once with low cost. Also note nextLogConnCnt maybe
		// added twice for current peak connection number level.
		log.Printf("Number of client connections reaches %d\n", nextLogConnCnt)
		nextLogConnCnt += logCntDelta
	}

	// function arguments are always evaluated, so surround debug statement
	// with if statement
	if debug {
		debug.Printf("new client %s->%s\n", conn.RemoteAddr().String(), conn.LocalAddr())
	}
	closed := false
	defer func() {
		if debug {
			debug.Printf("closed pipe %s<->%s\n", conn.RemoteAddr(), host)
		}
		connCnt--
		if !closed {
			conn.Close()
		}
	}()

	host, extra, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	debug.Println("connecting", host)
	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("dial error:", err)
		} else {
			log.Println("error connecting to:", host, err)
		}
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()
	// write extra bytes read from
	if extra != nil {
		// debug.Println("getRequest read extra data, writing to remote, len", len(extra))
		if _, err = remote.Write(extra); err != nil {
			debug.Println("write request extra error:", err)
			return
		}
	}
	if debug {
		debug.Printf("piping %s<->%s", conn.RemoteAddr(), host)
	}
	go ss.PipeThenClose(conn, remote, ss.SET_TIMEOUT, flowData, port)
	ss.PipeThenClose(remote, conn, ss.NO_TIMEOUT, flowData, port)
	closed = true
	return
}

type PortListener struct {
	password string
	listener net.Listener
}

type PasswdManager struct {
	sync.Mutex
	portListener map[string]*PortListener
}

func (pm *PasswdManager) add(port, password string, listener net.Listener) {
	pm.Lock()
	pm.portListener[port] = &PortListener{password, listener}
	pm.Unlock()
}

func (pm *PasswdManager) get(port string) (pl *PortListener, ok bool) {
	pm.Lock()
	pl, ok = pm.portListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) del(port string) {
	pl, ok := pm.get(port)
	if !ok {
		return
	}
	pl.listener.Close()
	pm.Lock()
	delete(pm.portListener, port)
	pm.Unlock()
}

// Update port password would first close a port and restart listening on that
// port. A different approach would be directly change the password used by
// that port, but that requires **sharing** password between the port listener
// and password manager.
func (pm *PasswdManager) updatePortPasswd(port, password, limit string) {
	pl, ok := pm.get(port)
	if !ok {
		log.Printf("new port %s added\n", port)
	} else {
		if pl.password == password {
			return
		}
		log.Printf("closing port %s to update password\n", port)
		pl.listener.Close()
	}
	// run will add the new port listener to passwdManager.
	// So there maybe concurrent access to passwdManager and we need lock to protect it.
	go run(port, password, limit)
}

var passwdManager = PasswdManager{portListener: map[string]*PortListener{}}

func updatePasswd() {
	log.Println("updating password")
	newconfig, err := ss.ParseConfig(configFile)
	if err != nil {
		log.Printf("error parsing config file %s to update password: %v\n", configFile, err)
		return
	}
	oldconfig := config
	config = newconfig

	if err = unifyPortPassword(config); err != nil {
		return
	}
	for port, psw_limit := range config.PortPasswordLimit {
		passwdManager.updatePortPasswd(port, psw_limit[0], psw_limit[1])
		if oldconfig.PortPasswordLimit != nil {
			delete(oldconfig.PortPasswordLimit, port)
		}
	}
	// port password still left in the old config should be closed
	for port, _ := range oldconfig.PortPasswordLimit {
		log.Printf("closing port %s as it's deleted\n", port)
		passwdManager.del(port)
	}
	log.Println("password updated")
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			updatePasswd()
		} else {
			// is this going to happen?
			log.Printf("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}

func runUDP(port, password string) {
	var cipher *ss.Cipher
	port_i, _ := strconv.Atoi(port)
	log.Printf("listening udp port %v\n", port)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv6zero,
		Port: port_i,
	})
	if err != nil {
		log.Printf("error listening udp port %v: %v\n", port, err)
		return
	}
	defer conn.Close()
	cipher, err = ss.NewCipher(config.Method, password)
	if err != nil {
		log.Printf("Error generating cipher for udp port: %s %v\n", port, err)
		conn.Close()
	}
	UDPConn := ss.NewUDPConn(*conn, cipher.Copy())
	for {
		UDPConn.HandleUDPConnection()
	}
}

func isOverFlow(port string) bool {
	//日期判断
	create, _ := time.Parse("2006-01-02 15:04:05", flowData.CreateTime)
	if now := time.Now(); now.Month() != create.Month() {
		flowData = &flow.Info{now.Format("2006-01-02 15:04:05"), map[string][]string{}}
	}

	if limit := config.PortPasswordLimit[port][1]; limit != "" && len(flowData.Usage[port]) != 0 {
		used := flowData.Usage[port][0]
		used2uint, _ := strconv.ParseUint(used, 10, 64)
		limit2uint, _ := strconv.ParseUint(limit, 10, 64)
		return used2uint >= limit2uint
	}
	return false
}

func run(port, password, limit string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Printf("error listening port %v: %v\n", port, err)
		return
	}
	passwdManager.add(port, password, ln)
	var cipher *ss.Cipher
	log.Printf("server listening port %v with limit %v...\n", port, limit)
	for {
		if isOverFlow(port) {
			//fmt.Println(port, "流量超了！！")
			continue
		}
		conn, err := ln.Accept()
		if err != nil {
			// listener maybe closed to update password
			debug.Printf("accept error: %v\n", err)
			return
		}
		// Creating cipher upon first connection.
		if cipher == nil {
			log.Println("creating cipher for port:", port)
			cipher, err = ss.NewCipher(config.Method, password)

			if err != nil {
				log.Printf("Error generating cipher for port: %s %v\n", port, err)
				conn.Close()
				continue
			}
		}
		go handleConnection(ss.NewConn(conn, cipher.Copy()), port)
	}
}

func enoughOptions(config *ss.Config) bool {
	return config.ServerPort != 0 && config.Password != ""
}

func unifyPortPassword(config *ss.Config) (err error) {
	if len(config.PortPasswordLimit) == 0 { // this handles both nil PortPasswordLimit and empty one
		if !enoughOptions(config) {
			fmt.Fprintln(os.Stderr, "must specify both port and password")
			return errors.New("not enough options")
		}
		port := strconv.Itoa(config.ServerPort)
		config.PortPasswordLimit = map[string][]string{port: []string{config.Password, ""}} //todo unify的部分流量留空
	} else {
		if config.Password != "" || config.ServerPort != 0 {
			fmt.Fprintln(os.Stderr, "given port_password, ignore server_port and password option")
		}
	}
	return
}

var configFile string
var config *ss.Config
var flowData *flow.Info

type result struct {
	Id         string
	P          string
	Use        string
	UpdateTime string
}

type results struct {
	Result []result
}

type ById []result

func (s ById) Len() int {
	return len(s)
}

func (s ById) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s ById) Less(i, j int) bool {
	return s[i].Id < s[j].Id
}

func status(w http.ResponseWriter, r *http.Request) {

	re := result{}
	res := []result{}
	for port, _ := range flowData.Usage {
		usedUint, _ := strconv.ParseUint(flowData.Usage[port][0], 10, 64)
		if config.PortPasswordLimit[port] == nil {
			continue
		}
		limitUint, _ := strconv.ParseUint(config.PortPasswordLimit[port][1], 10, 64)
		usedFloat := float64(usedUint) / 1073741824 //1024^3
		usedStr := fmt.Sprintf("%.2f", usedFloat)
		p := usedUint * 100 / limitUint
		re = result{Id: port, P: strconv.Itoa(int(p)), Use: usedStr, UpdateTime: flowData.Usage[port][1]}
		res = append(res, re)
	}
	//fmt.Println("before", res)
	sort.Sort(ById(res))
	//fmt.Println("after", res)

	t, _ := template.ParseFiles("status.html")

	//template.HTMLEscape(w, ) //输出到客户端
	t.Execute(w, results{res}) //解析参数，默认是不会解析的
}

func main() {
	log.SetOutput(os.Stdout)

	var cmdConfig ss.Config
	var printVer bool
	var core int
	var udp bool

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 60, "connection timeout (in seconds)")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")
	flag.BoolVar(&udp, "u", false, "UDP Relay")

	flag.Parse()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	ss.SetDebug(debug)

	var err error
	config, err = ss.ParseConfig(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
		config = &cmdConfig
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}
	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}
	if err = ss.CheckCipherMethod(config.Method); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = unifyPortPassword(config); err != nil {
		os.Exit(1)
	}
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}

	//read from file
	flowData, err = flow.ParseConfig("flowInfo.json")
	if err != nil {
		now := time.Now().Format("2006-01-02 15:04:05")
		flowData = &flow.Info{now, map[string][]string{}}
		flow.SaveConfig("flowInfo.json", flowData)
	}

	for port, pass_limit := range config.PortPasswordLimit {
		go run(port, pass_limit[0], pass_limit[1])
		if udp == true {
			go runUDP(port, pass_limit[0])
		}
	}

	//url
	http.HandleFunc("/", status)            //设置访问的路由
	err = http.ListenAndServe(":9000", nil) //设置监听的端口
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

	waitSignal()
}
