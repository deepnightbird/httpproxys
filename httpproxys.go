package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"io/fs"

	"github.com/BurntSushi/toml"
	dns "github.com/Focinfi/go-dns-resolver"
	"github.com/magisterquis/connectproxy"
	"golang.org/x/net/proxy"
)

var (
	hosts_list       map[string]bool
	hosts_list_mutex = &sync.RWMutex{}

	//block_list map[uint64]struct{}
	block_list []uint32

	adblock_list       map[string]int
	adblock_list_mutex = &sync.RWMutex{}

	resolve_list       map[string]string
	resolve_list_mutex = &sync.RWMutex{}

	myClient *http.Client
	conf     Config
	ini_file string
	dialer   proxy.Dialer

	hash_func hash.Hash64
)

const version = "0.2.2.1"

func mylog(text string) {
	log.Println(text)
}

func getTimestamp() int64 {
	return time.Now().UnixNano() / 1e6
}

func load_lists(file_name string, mode bool) {
	file, _ := os.Open(file_name)
	if file == nil {
		return
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		t := scanner.Text()
		if t[0:1] == "#" || len(t) == 0 {
			continue
		}
		if strings.Contains(t, "#") {
			t = strings.Split(t, "#")[0]
		}
		t = strings.TrimSpace(t)
		hosts_list[t] = mode
		if mode {
			mylog("added proxy " + t)
		} else {
			mylog("added direct " + t)
		}
	}
	file.Close()
	scanner = nil
}

func save_state(file_name string) {

	for {
		hosts_list_mutex.RLock()
		buf, _ := json.MarshalIndent(&hosts_list, "", "    ")
		hosts_list_mutex.RUnlock()

		_ = os.WriteFile(file_name, buf, fs.FileMode(0666))

		time.Sleep(time.Minute * time.Duration(10))
	}
}

func load_state(file_name string) {
	rd, err := os.ReadFile(file_name)
	if err == nil {
		temp_hosts_list := make(map[string]bool)
		_ = json.Unmarshal(rd, &temp_hosts_list)
		for k, v := range temp_hosts_list {
			hosts_list[k] = v
		}
	}
}

func load_from_backup() {
	if len(conf.BlockListBackup) == 0 {
		return
	}
	jsonfile, err := os.Open(conf.BlockListBackup)
	if err != nil {
		return
	}
	defer jsonfile.Close()
	jsonbytes, _ := io.ReadAll(jsonfile)
	_ = json.Unmarshal(jsonbytes, &block_list)
}

func save_to_backup() {
	if len(conf.BlockListBackup) == 0 {
		return
	}
	// jsonbytes, _ := json.Marshal(&block_list)
	jsonbytes, _ := json.MarshalIndent(&block_list, "", "    ")
	_ = os.WriteFile(conf.BlockListBackup, jsonbytes, 0644)
}

func make_hash(s string) uint32 {
	hash_func.Reset()
	hash_func.Write([]byte(s))
	return uint32(hash_func.Sum64())
}

func load_block_list() {
	// https://reestr.rublacklist.net/api/v2/domains/json/
	mylog("Start load block list")
	req, _ := http.NewRequest(http.MethodGet, conf.BlockListPath, nil)
	resp, err := myClient.Do(req)
	if err != nil {
		mylog("No block list loaded, error " + err.Error())
		load_from_backup()
	} else {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var temp_block_list []string
		err = json.Unmarshal(body, &temp_block_list)
		if err != nil {
			load_from_backup()
		} else {
			for _, v := range temp_block_list {
				h := make_hash(v)
				block_list = append(block_list, h)
			}
			temp_block_list = nil
			save_to_backup()
		}
	}
	if len(block_list) > 0 {
		mylog("Block list loaded, items " + strconv.Itoa(len(block_list)))
	} else {
		mylog("No block list loaded")
	}
}

func wordcontains(pstr string, plist []string) bool {
	for _, v := range plist {
		if strings.Contains(pstr, v) {
			return true
		}
	}
	return false
}

func check_direct(phost string) bool {
	// var res *http.Response
	//var err error
	//var header string
	var cont_len int = conf.MinDirectLength
	var content []byte

	req, _ := http.NewRequest(http.MethodGet, phost, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml")
	req.Header.Set("Accept-Charset", "ISO-8859-1,utf-8")
	req.Header.Set("Accept-Encoding", "none")
	req.Header.Set("Accept-Language", "ru-RU,ru;en-US,en;q=0.8")
	req.Header.Set("cache-control", "max-age=0")
	req.Header.Set("dnt", "1")
	req.Header.Set("pragma", "no-cache")

	var connStart = getTimestamp()

	res, err := myClient.Do(req)
	_ = err
	//res, _ = http.Get(phost)
	var connTime = getTimestamp() - connStart
	if res != nil {
		// mylog(phost + " code " + strconv.Itoa(res.StatusCode))
		if res.StatusCode == 307 && wordcontains(res.Request.Host, conf.BlockWords) {
			cont_len = 0
		} else if res.StatusCode == 403 {
			cont_len = int(res.ContentLength)
			if cont_len >= conf.MinDirectLength {
				content, _ = io.ReadAll(res.Body)
				scontent := string(content)
				if wordcontains(scontent, conf.BlockWords) {
					cont_len = 0
				} else {
					cont_len = len(scontent)
				}
			}
		}
		res.Body.Close()
	} else {
		// mylog(phost + " res is nil " + err.Error())
		if connTime >= int64(conf.Timeout)*1000 {
			cont_len = 0
		} else {
			cont_len = conf.MinDirectLength
		}
	}
	return cont_len >= conf.MinDirectLength
}

func resolve(phost string) string {
	var record string
	if results, err := dns.Exchange(phost, conf.DNSresolver, dns.TypeA); err == nil {
		for _, r := range results {
			// mylog(r.Record, r.Type, r.Ttl, r.Priority, r.Content)
			//if r.Ttl > 0 {
			if len(r.Content) > 0 {
				record = r.Content
				if len(record) > 0 {
					break
				}
			}
		}
	} else {
		mylog(err.Error())
	}
	return record
}

func check_block_list(phost string) bool {
	in_block_list := slices.Contains(block_list, make_hash(phost))
	/*h := make_hash(phost)
	_, in_block_list := block_list[h]*/
	if !in_block_list {
		i := strings.Count(phost, ".")
		if i == 2 {
			i := strings.Index(phost, ".")
			in_block_list = slices.Contains(block_list, make_hash("*"+phost[i:]))
			/*h := make_hash("*" + phost[i:])
			_, in_block_list = block_list[h]*/
		} else if i == 1 {
			in_block_list = slices.Contains(block_list, make_hash("*."+phost))
			/*h := make_hash("*." + phost)
			_, in_block_list = block_list[h]*/
		}
	}
	return in_block_list
}

func check_host_list(phost string, pport string) (bool, bool) {
	var in_host_list bool = false
	var use_proxy bool = false
	use_proxy, in_host_list = hosts_list[phost]
	if !in_host_list {
		i := strings.Count(phost, ".")
		if i == 2 {
			i := strings.Index(phost, ".")
			hostmask := "*" + phost[i:]
			use_proxy, in_host_list = hosts_list[hostmask]
		} else if i == 1 {
			use_proxy, in_host_list = hosts_list["*."+phost]
		}
	}
	return in_host_list, use_proxy
}

func add_to_host_list(phost string, pport string, use_proxy int) bool {
	var proto string
	var buse_proxy bool = false

	if pport == ":80" || pport == ":8080" {
		proto = "http://"
	} else {
		proto = "https://"
	}
	switch use_proxy {
	case -1:
		buse_proxy = !check_direct(proto + phost + pport)
	case 0:
		buse_proxy = false
	case 1:
		buse_proxy = true
	}
	hosts_list_mutex.Lock()
	hosts_list[phost] = buse_proxy
	hosts_list_mutex.Unlock()
	return buse_proxy
}

func is_use_proxy(phost string, pport string, premote string, pipaddr *string) int {

	_, in := adblock_list[phost]
	if in {
		// go mylog(CL_YELLOW + premote + CL_RESET + " adblock " + CL_RED + phost + CL_RESET)
		return -1
	}

	*pipaddr, in = resolve_list[phost]
	if !in {
		*pipaddr = resolve(phost)
		if strings.Contains(*pipaddr, "0.0.0.0") || strings.Contains(*pipaddr, "127.0.0.") {
			adblock_list_mutex.Lock()
			adblock_list[phost] = 1
			adblock_list_mutex.Unlock()
			return -1
		}
		resolve_list_mutex.Lock()
		resolve_list[phost] = *pipaddr
		resolve_list_mutex.Unlock()
	}

	var in_block_list bool = false

	in_host_list, use_proxy := check_host_list(phost, pport)

	if !in_host_list {
		if len(block_list) > 0 {
			in_block_list = check_block_list(phost)
			if in_block_list {
				use_proxy = true
			}
		}
	}

	if !in_host_list && !in_block_list {
		if conf.CheckDirect {
			use_proxy = add_to_host_list(phost, pport, -1)
		} else {
			use_proxy = add_to_host_list(phost, pport, 0)
		}
	}

	if use_proxy {
		mylog(premote + " proxy " + phost)
		return 1
	} else {
		mylog(premote + " direct " + phost)
		return 0
	}
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	var use_proxy int
	var ipaddr string

	host, port, _ := net.SplitHostPort(r.Host)

	if len(port) > 0 {
		port = ":" + port
	}

	use_proxy = is_use_proxy(host, port, r.RemoteAddr, &ipaddr)

	if use_proxy < 0 /*|| len(ipaddr) < 7 || strings.Contains(ipaddr, "0.0.0.0") || strings.Contains(ipaddr, "127.0.0.")*/ {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(port) > 0 {
		ipaddr += port
	}
	r.Host = ipaddr
	r.URL.Host = ipaddr
	r.RequestURI = ipaddr

	var destConn net.Conn
	var err error
	switch use_proxy {
	case 0:
		destConn, err = net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	case 1:
		destConn, _ = dialer.Dial("tcp", r.RequestURI) //net.Dial( "tcp" , address)
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	if destConn != nil && clientConn != nil {
		go transfer(destConn, clientConn)
		go transfer(clientConn, destConn)
	} else {
		if destConn != nil {
			destConn.Close()
		}
		if clientConn != nil {
			clientConn.Close()
		}
	}
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {

	var fs os.FileInfo
	var err error

	if len(os.Args) == 2 {
		ini_file = os.Args[1]
	} else {
		os.Exit(-1)
	}
	if fs, err = os.Stat(ini_file); fs == nil || err != nil && errors.Is(err, os.ErrNotExist) {
		mylog("Error open file " + ini_file)
		os.Exit(1)
	}
	//work_dir = filepath.Dir(os.Args[0])
	_, err = toml.DecodeFile(ini_file, &conf)
	if err != nil {
		log.Panic(err)
		os.Exit(1)
	}

	var time_out time.Duration = time.Duration(conf.Timeout) * time.Second

	if conf.DNSresolver != "" {
		if !strings.Contains(conf.DNSresolver, ":") {
			conf.DNSresolver = conf.DNSresolver + ":53"
		}
		dns.Config.SetTimeout(uint(time.Second))
		dns.Config.RetryTimes = uint(4)
	} else {
		conf.DNSresolver = "8.8.4.4:53"
	}

	if len(conf.LogFile) > 0 {
		if conf.LogFile != "con" && conf.LogFile != "ansicon" {
			var logfile *os.File
			logfile, err = os.OpenFile(conf.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			defer logfile.Close()
			log.SetOutput(logfile)
		}
	} else {
		log.SetOutput(io.Discard)
	}

	var proxy_type string = conf.Proxy
	var proxy_path string = proxy_type
	var http_url url.URL

	if strings.Contains(proxy_type, "://") {
		proxy_path = strings.Split(proxy_type, "://")[1]
	}

	if strings.Contains(proxy_type, "http://") {
		proxy_type = "http"
		http_url.Scheme = "http"
		http_url.Host = proxy_path
	} else {
		proxy_type = "socks"
	}
	switch proxy_type {
	case "socks":
		dialer, err = proxy.SOCKS5("tcp", proxy_path, nil, nil)
	case "http":
		dialer, err = connectproxy.New(&http_url, proxy.Direct)
	}
	if err != nil {
		log.Println(proxy_type + " " + err.Error())
		//http.Error(err.Error(), http.StatusServiceUnavailable)
		os.Exit(1)
	}

	hosts_list = map[string]bool{}
	adblock_list = make(map[string]int)
	resolve_list = make(map[string]string)
	//block_list = make(map[uint64]struct{})
	hash_func = fnv.New64a()

	if conf.DirectFile != "" {
		load_lists(conf.DirectFile, false)
	}

	if conf.ProxyFile != "" {
		load_lists(conf.ProxyFile, true)
	}

	if conf.SaveFile != "" {
		load_state(conf.SaveFile)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	myClient = &http.Client{
		Transport: tr,
		Timeout:   time_out,
	}
	time.Sleep(time.Second * time.Duration(1))

	// _ = check_direct("https://sun7-3.userapi.com:443")
	// _ = is_use_proxy("tsn.ua", "_debug")
	// _ = is_use_proxy("obozrevatel.com:443", "_debug")
	// _ = is_use_proxy("maps.obozrevatel.com", "_debug")

	if conf.SaveFile != "" {
		go save_state(conf.SaveFile)
	}
	if len(conf.BlockListPath) > 0 {
		load_block_list()
	}
	runtime.GC()
	// debug.FreeOSMemory()
	mylog("Version " + version)
	mylog("Listen at " + conf.Listenaddr + ":" + strconv.Itoa(conf.Listenport))
	server := &http.Server{
		Addr: conf.Listenaddr + ":" + strconv.Itoa(conf.Listenport),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Fatal(server.ListenAndServe())
}
