package main

type (
	Proxy struct {
		Name string `toml:"name"`
		Url  string `toml:"url"`
	}

	Config struct {
		Listenaddr string `toml:"listenaddr"`
		Listenport int    `toml:"listenport"`
		Timeout    int    `toml:"timeout"`
		Proxy      string `toml:"proxy"`
		LogFile    string `toml:"logfile"`
		DirectFile string `toml:"directfile"`
		ProxyFile  string `toml:"proxyfile"`
	}
)
