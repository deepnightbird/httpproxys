package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/magisterquis/connectproxy"
	"golang.org/x/net/proxy"
)

var (
	hosts_list       map[string]bool
	hosts_list_mutex = &sync.RWMutex{}
	myClient         *http.Client
	conf             Config
	ini_file         string
	dialer           proxy.Dialer
)

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

func check_direct(phost string) bool {
	// var res *http.Response
	//var err error
	//var header string
	var cont_len int = 0
	//var content []byte = nil

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
		if res.StatusCode == 307 && res.Request.Host == "blocked.mts.ru" {
			cont_len = 0
		} else /*if res.StatusCode != 403*/ {
			/*header = res.Header.Get("Content-Length")
			  cont_len, err = strconv.Atoi(header)
			  if err != nil {
			      content, _ = io.ReadAll(res.Body)
			      if strings.Contains(string(content), "blocked.mts.ru") {
			          cont_len = 0
			      } else {
			          cont_len = len(string(content))
			      }
			  }*/
			cont_len = 200
		}
		res.Body.Close()
	} else {
		// mylog(phost + " res is nil " + err.Error())
		if connTime >= int64(conf.Timeout)*1000 {
			cont_len = 0
		} else {
			cont_len = 200
		}
		cont_len = 0
	}
	return cont_len > 10
}

func is_use_proxy(phost string, premote string) bool {

	phost1 := phost

	if strings.Contains(phost1, "http://") {
		phost1 = strings.Replace(phost, "http://", "", -1)
	}
	if strings.Contains(phost1, "https://") {
		phost1 = strings.Replace(phost, "https://", "", -1)
	}
	if strings.Contains(phost1, ":") {
		phost2 := strings.Split(phost1, ":")
		phost1 = phost2[0]
	}

	hosts := strings.Split(phost1, ".")
	var mainhost string = ""
	if len(hosts) > 1 {
		mainhost = hosts[len(hosts)-2] + "." + hosts[len(hosts)-1]
	} else {
		mainhost = phost1
	}

	var in_phost bool
	var in_mainhost bool
	var p bool

	p, in_phost = hosts_list[phost1]

	if in_phost {
		return p
	}

	p, in_mainhost = hosts_list[mainhost]

	if in_mainhost {
		return p
	}

	var use_proxy = !check_direct("https://" + phost)

	hosts_list_mutex.Lock()
	hosts_list[phost1] = use_proxy
	hosts_list_mutex.Unlock()

	if use_proxy {
		mylog(premote + " proxy " + phost)
		return true
	} else {
		mylog(premote + " direct " + phost)
		return false
	}
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	var use_proxy bool = false

	use_proxy = is_use_proxy(r.Host, r.RemoteAddr)

	var destConn net.Conn
	var err error
	switch use_proxy {
	case false:
		destConn, err = net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	case true:
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

	if conf.DirectFile != "" {
		load_lists(conf.DirectFile, false)
	}

	if conf.ProxyFile != "" {
		load_lists(conf.ProxyFile, true)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	myClient = &http.Client{
		Transport: tr,
		Timeout:   time_out,
	}
	// _ = check_direct("https://sun7-3.userapi.com:443")
	// _ = is_use_proxy("tsn.ua", "_debug")
	_ = is_use_proxy("obozrevatel.com:443", "_debug")
	_ = is_use_proxy("maps.obozrevatel.com", "_debug")

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
