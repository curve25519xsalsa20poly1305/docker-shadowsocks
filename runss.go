package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type ssconf struct {
	Server     string   `json:"server"`
	ServerPort string   `json:"server_port,omitempty"`
	Password   string   `json:"password,omitempty"`
	Timeout    string   `json:"timeout,omitempty"`
	Method     string   `json:"method,omitempty"`
	Plugin     string   `json:"plugin,omitempty"`
	PluginOpts string   `json:"plugin_opts,omitempty"`
	Key        string   `json:"key,omitempty"`
	User       string   `json:"user,omitempty"`
	FastOpen   *bool    `json:"fast_open,omitempty"`
	ReusePort  *bool    `json:"reuse_port,omitempty"`
	NoFile     *int     `json:"nofile,omitempty"`
	DSCP       []string `json:"dscp,omitempty"`
	Mode       string   `json:"mode,omitempty"`
	MTU        *int     `json:"mtu,omitempty"`
	MPTCP      *bool    `json:"mptcp,omitempty"`
	IPv6First  *bool    `json:"ipv6_first,omitempty"`
	UseSyslog  *bool    `json:"use_syslog,omitempty"`
	NoDelay    *bool    `json:"no_delay,omitempty"`
	LocalAddr  string   `json:"local_address,omitempty"`
	LocalPort  string   `json:"local_port,omitempty"`
}

type ssrconf struct {
	Server        string `json:"server"`
	ServerPort    *int   `json:"server_port,omitempty"`
	Password      string `json:"password,omitempty"`
	Timeout       string `json:"timeout,omitempty"`
	Method        string `json:"method,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	ProtocolParam string `json:"protocol_param,omitempty"`
	OBFS          string `json:"obfs,omitempty"`
	OBFSParam     string `json:"obfs_param,omitempty"`
	User          string `json:"user,omitempty"`
	FastOpen      *bool  `json:"fast_open,omitempty"`
	NoFile        *int   `json:"nofile,omitempty"`
	Mode          string `json:"mode,omitempty"`
	MTU           *int   `json:"mtu,omitempty"`
	MPTCP         *bool  `json:"mptcp,omitempty"`
	IPv6First     *bool  `json:"ipv6_first,omitempty"`
	LocalAddr     string `json:"local_address,omitempty"`
	LocalPort     string `json:"local_port,omitempty"`
}

func newInt(v int) (r *int) {
	r = new(int)
	*r = v
	return
}

func newBool(v bool) (r *bool) {
	r = new(bool)
	*r = v
	return
}

func parseURI(str string) (conf interface{}, err error) {
	u, err := url.Parse(str)
	if err != nil {
		return
	}
	switch u.Scheme {
	case "ss":
		return parseSSURI(u)
	case "ssr":
		return parseSSRURI(u)
	default:
		err = fmt.Errorf("unsupported URI scheme: %s", u.Scheme)
		return
	}
}

func parseSSURI(u *url.URL) (conf *ssconf, err error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(u.User.Username())
	if err != nil {
		err = fmt.Errorf("failed to parse SS URI user info Base64: %w", err)
		return
	}
	userinfo := strings.SplitN(string(b), ":", 2)
	if len(userinfo) != 2 {
		err = fmt.Errorf("invalid SS URI user info: %s", string(b))
		return
	}
	if conf, err = parseSSEnv(); err != nil {
		return
	}
	conf.Server = u.Hostname()
	conf.ServerPort = u.Port()
	conf.Method = userinfo[0]
	conf.Password = userinfo[1]
	q := u.Query()
	pluginQ := q.Get("plugin")
	if pluginQ != "" {
		pluginParts := strings.SplitN(pluginQ, ";", 2)
		if len(pluginParts) != 2 {
			err = fmt.Errorf("invalid SS URI plugin query parameter: %s", pluginQ)
			return
		}
		conf.Plugin = pluginParts[0]
		conf.PluginOpts = pluginParts[1]
	}
	return
}

func parseSSRURI(u *url.URL) (conf *ssrconf, err error) {
	var q url.Values
	b, err := base64.RawURLEncoding.Strict().DecodeString(u.Host)
	if err != nil {
		err = fmt.Errorf("failed to parse SSR URI outer Base64: %w", err)
		return
	}
	parts := strings.SplitN(string(b), "/?", 2)
	firstPart := strings.Split(parts[0], ":")
	if len(firstPart) != 6 {
		err = fmt.Errorf("SSR URI first inner part not invalid: %s", parts[0])
		return
	}
	port, err := strconv.Atoi(firstPart[1])
	if err != nil {
		err = fmt.Errorf("SSR URI invalid port: %s", firstPart[1])
		return
	}
	b, err = base64.RawStdEncoding.DecodeString(firstPart[5])
	if err != nil {
		err = fmt.Errorf("failed to decode SSR password Base64: %w", err)
		return
	}
	if conf, err = parseSSREnv(); err != nil {
		return
	}
	conf.Server = firstPart[0]
	conf.ServerPort = newInt(port)
	conf.Protocol = firstPart[2]
	conf.Method = firstPart[3]
	conf.OBFS = firstPart[4]
	conf.Password = string(b)
	if len(parts) == 2 && parts[1] != "" {
		if q, err = url.ParseQuery(parts[1]); err != nil {
			err = fmt.Errorf("failed to parse SSR URI query part: %w", err)
			return
		}
		if q.Get("obfsparam") != "" {
			if b, err = base64.RawStdEncoding.DecodeString(q.Get("obfsparam")); err != nil {
				err = fmt.Errorf("failed to decode SSR OBFS param Base64: %w", err)
				return
			}
			conf.OBFSParam = string(b)
		}
		if q.Get("protoparam") != "" {
			if b, err = base64.RawStdEncoding.DecodeString(q.Get("protoparam")); err != nil {
				err = fmt.Errorf("failed to decode SSR protocol param Base64: %w", err)
				return
			}
			conf.ProtocolParam = string(b)
		}
	}
	return
}

func getEnvInt(name string) (v *int, err error) {
	var vint int
	str := os.Getenv(name)
	if str != "" {
		if vint, err = strconv.Atoi(str); err != nil {
			return
		}
		v = newInt(vint)
	}
	return
}

func getEnvBool(name string) (v *bool, err error) {
	vbool := false
	str := os.Getenv(name)
	if str != "" {
		if str == "true" {
			vbool = true
		}
		v = newBool(vbool)
	}
	return
}

func parseEnv() (conf interface{}, err error) {
	ssType := os.Getenv("SS_VARIANT")
	switch strings.ToLower(ssType) {
	case "ss":
		return parseSSEnv()
	case "ssr":
		return parseSSREnv()
	default:
		err = fmt.Errorf("unsupported SS_VARIANT: %s", ssType)
		return
	}
}

func parseSSEnv() (conf *ssconf, err error) {
	fastOpen, err := getEnvBool("SS_FAST_OPEN")
	if err != nil {
		err = fmt.Errorf("invalid SS_FAST_OPEN: %w", err)
		return
	}
	noFile, err := getEnvInt("SS_NOFILE")
	if err != nil {
		err = fmt.Errorf("invalid SS_NOFILE: %w", err)
		return
	}
	mtu, err := getEnvInt("SS_MTU")
	if err != nil {
		err = fmt.Errorf("invalid SS_MTU: %w", err)
		return
	}
	mptcp, err := getEnvBool("SS_MPTCP")
	if err != nil {
		err = fmt.Errorf("invalid SS_MPTCP: %w", err)
		return
	}
	ipv6First, err := getEnvBool("SS_IPV6_FIRST")
	if err != nil {
		err = fmt.Errorf("invalid SS_IPV6_FIRST: %w", err)
		return
	}
	reusePort, err := getEnvBool("SS_REUSE_PORT")
	if err != nil {
		err = fmt.Errorf("invalid SS_REUSE_PORT: %w", err)
		return
	}
	useSyslog, err := getEnvBool("SS_USE_SYSLOG")
	if err != nil {
		err = fmt.Errorf("invalid SS_USE_SYSLOG: %w", err)
		return
	}
	noDelay, err := getEnvBool("SS_NO_DELAY")
	if err != nil {
		err = fmt.Errorf("invalid SS_NO_DELAY: %w", err)
		return
	}
	conf = &ssconf{
		Server:     os.Getenv("SS_SERVER_ADDR"),
		ServerPort: os.Getenv("SS_SERVER_PORT"),
		Password:   os.Getenv("SS_SERVER_PASS"),
		Method:     os.Getenv("SS_METHOD"),
		Plugin:     os.Getenv("SS_PLUGIN"),
		PluginOpts: os.Getenv("SS_PLUGIN_OPTS"),
		Key:        os.Getenv("SS_KEY"),
		Timeout:    os.Getenv("SS_TIMEOUT"),
		LocalAddr:  os.Getenv("SS_LOCAL_ADDR"),
		LocalPort:  os.Getenv("SS_LOCAL_PORT"),
		User:       os.Getenv("SS_USER"),
		FastOpen:   fastOpen,
		Mode:       os.Getenv("SS_MODE"),
		NoFile:     noFile,
		MTU:        mtu,
		MPTCP:      mptcp,
		IPv6First:  ipv6First,
		ReusePort:  reusePort,
		UseSyslog:  useSyslog,
		NoDelay:    noDelay,
	}
	dscpStr := os.Getenv("SS_DSCP")
	if dscpStr != "" {
		if err = json.Unmarshal([]byte(dscpStr), &conf.DSCP); err != nil {
			err = fmt.Errorf("failed to decode SS_DSCP as JSON array: %s: %w", dscpStr, err)
			return
		}
	}
	return
}

func parseSSREnv() (conf *ssrconf, err error) {
	port, err := getEnvInt("SS_SERVER_PORT")
	if err != nil {
		err = fmt.Errorf("invalid SS_SERVER_PORT: %w", err)
		return
	}
	fastOpen, err := getEnvBool("SS_FAST_OPEN")
	if err != nil {
		err = fmt.Errorf("invalid SS_FAST_OPEN: %w", err)
		return
	}
	noFile, err := getEnvInt("SS_NOFILE")
	if err != nil {
		err = fmt.Errorf("invalid SS_NOFILE: %w", err)
		return
	}
	mtu, err := getEnvInt("SS_MTU")
	if err != nil {
		err = fmt.Errorf("invalid SS_MTU: %w", err)
		return
	}
	mptcp, err := getEnvBool("SS_MPTCP")
	if err != nil {
		err = fmt.Errorf("invalid SS_MPTCP: %w", err)
		return
	}
	ipv6First, err := getEnvBool("SS_IPV6_FIRST")
	if err != nil {
		err = fmt.Errorf("invalid SS_IPV6_FIRST: %w", err)
		return
	}
	conf = &ssrconf{
		Server:        os.Getenv("SS_SERVER_ADDR"),
		ServerPort:    port,
		Password:      os.Getenv("SS_SERVER_PASS"),
		Method:        os.Getenv("SS_METHOD"),
		Protocol:      os.Getenv("SS_PROTO"),
		ProtocolParam: os.Getenv("SS_PROTO_PARAM"),
		OBFS:          os.Getenv("SS_OBFS"),
		OBFSParam:     os.Getenv("SS_OBFS_PARAM"),
		Timeout:       os.Getenv("SS_TIMEOUT"),
		LocalAddr:     os.Getenv("SS_LOCAL_ADDR"),
		LocalPort:     os.Getenv("SS_LOCAL_PORT"),
		User:          os.Getenv("SS_USER"),
		FastOpen:      fastOpen,
		Mode:          os.Getenv("SS_MODE"),
		NoFile:        noFile,
		MTU:           mtu,
		MPTCP:         mptcp,
		IPv6First:     ipv6First,
	}
	return
}

func main() {
	var err error
	var conf interface{}
	var exe string

	confPath := "/etc/shadowsocks/config.json"

	if os.Getenv("SS_URI") != "" {
		if conf, err = parseURI(os.Getenv("SS_URI")); err != nil {
			panic(err)
		}
	} else {
		if conf, err = parseEnv(); err != nil {
			panic(err)
		}
	}

	w, err := os.OpenFile(confPath, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}

	e := json.NewEncoder(w)
	e.SetIndent("", "    ")
	if err = e.Encode(conf); err != nil {
		panic(err)
	}

	if err = w.Close(); err != nil {
		panic(err)
	}

	switch conf.(type) {
	case *ssconf:
		exe = "ss-redir"
	case *ssrconf:
		exe = "ssr-redir"
	}

	cmd := exec.Command(exe, "-c", confPath, "--up", "shadowsocks-up.sh")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
}
