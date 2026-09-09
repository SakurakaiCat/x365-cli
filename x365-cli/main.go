// Command x365 authenticates against the 365VPN API, downloads the node
// configuration and extracts x365:// node links.
//
// Protocol:
//
//	x-sig  = base64( RSA-2048/PKCS1v15 encrypt(deviceJSON, serverPubKey), chunked at 245 bytes )
//	login  = POST {api}/v1/auth/login  {email,password,reg:false} -> {access_token}
//	config = GET  {api}/v1/app?flag=wassvpn  (authorization: <jwt>) -> {proxy, servers, ...}
//	proxy  = base64( RSA-2048 blocks ); private-decrypt each 256B block, concat,
//	         zlib-decompress -> YAML containing x365:// links
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	defaultAPI    = "https://d2hh0svl8tdgyk.cloudfront.net"
	appVersion    = "26.7.17"
	configVersion = "25.11.20"
	coreVersion   = "26.1.30"
)

// Embedded RSA key pair, required to speak the API
// (public key builds x-sig, private key decodes the server config payload).
//
//go:embed server_pubkey.pem
var serverPubKeyPEM []byte

//go:embed rsa_private_key.pem
var serverPrivKeyPEM []byte

var (
	serverPubKey  *rsa.PublicKey
	serverPrivKey *rsa.PrivateKey
)

func init() {
	blk, _ := pem.Decode(serverPubKeyPEM)
	if blk == nil {
		panic("bad server_pubkey.pem")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		panic(err)
	}
	serverPubKey = pub.(*rsa.PublicKey)

	blk, _ = pem.Decode(serverPrivKeyPEM)
	if blk == nil {
		panic("bad rsa_private_key.pem")
	}
	k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		panic(err)
	}
	serverPrivKey = k
}

// ---------- device identity / x-sig ----------

type deviceInfo struct {
	AppName       string `json:"app_name"`
	DeviceName    string `json:"device_name"`
	Fit           int    `json:"fit"`
	OS            string `json:"os"`
	OSVersion     string `json:"os_version"`
	AppVersion    string `json:"app_version"`
	OSArch        string `json:"os_arch"`
	ClientIP      string `json:"client_ip"`
	API           string `json:"api"`
	Proxy         bool   `json:"proxy"`
	DID           string `json:"did"`
	DNS           string `json:"dns"`
	ConfigVersion string `json:"config_version"`
	CoreVersion   string `json:"core_version"`
	ScreenWidth   string `json:"screen_width"`
	ScreenHeight  string `json:"screen_height"`
	Language      string `json:"language"`
	FP            string `json:"fp"`
	FCMToken      string `json:"fcm_token"`
	BuildID       string `json:"build_id"`
	IsEmulator    bool   `json:"is_emulator"`
	BuildNumber   string `json:"build_number"`
	PackageName   string `json:"package_name"`
}

func goOS() string {
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		return runtime.GOOS
	default:
		return "linux"
	}
}

func egressIP() string {
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me"} {
		cl := &http.Client{Timeout: 8 * time.Second}
		resp, err := cl.Get(u)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if err == nil && resp.StatusCode == 200 {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	return "0.0.0.0"
}

// makeXSig encrypts the device JSON in 245-byte PKCS#1 v1.5 chunks with the
// server public key and returns the base64 blob sent as the x-sig header.
func makeXSig(did, api string, dev deviceInfo) (string, error) {
	dev.AppName = "365VPN"
	dev.Fit = 0
	dev.OS = goOS()
	dev.OSVersion = osRelease()
	dev.AppVersion = appVersion
	dev.OSArch = "amd64"
	dev.API = api
	dev.Proxy = false
	dev.DID = did
	dev.DNS = "tls://223.5.5.5"
	dev.ConfigVersion = configVersion
	dev.CoreVersion = coreVersion
	if dev.ClientIP == "" {
		dev.ClientIP = egressIP()
	}
	if dev.Language == "" {
		dev.Language = "en"
	}
	blob, err := json.Marshal(dev)
	if err != nil {
		return "", err
	}
	const chunk = 245 // 256-byte modulus - 11 bytes PKCS#1 v1.5 overhead
	var out bytes.Buffer
	for i := 0; i < len(blob); i += chunk {
		end := i + chunk
		if end > len(blob) {
			end = len(blob)
		}
		enc, err := rsa.EncryptPKCS1v15(rand.Reader, serverPubKey, blob[i:end])
		if err != nil {
			return "", err
		}
		out.Write(enc)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes()), nil
}

func newDID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ---------- API client ----------

type client struct {
	api   string
	did   string
	sig   string
	token string
	hc    *http.Client
}

func newClient(api, did string) (*client, error) {
	c := &client{api: api, did: did, hc: &http.Client{Timeout: 30 * time.Second}}
	sig, err := makeXSig(did, api, deviceInfo{})
	if err != nil {
		return nil, err
	}
	c.sig = sig
	return c, nil
}

func (c *client) do(method, path string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.api+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("user-agent", "365VPN "+appVersion)
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept-language", "en")
	req.Header.Set("content-language", "en")
	req.Header.Set("x-did", c.did)
	req.Header.Set("x-sig", c.sig)
	if c.token != "" {
		req.Header.Set("authorization", c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

func (c *client) login(email, password string) error {
	status, b, err := c.do("POST", "/v1/auth/login", map[string]any{
		"email": email, "password": password, "reg": false,
	})
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("login: HTTP %d: %s", status, truncate(b, 200))
	}
	var r struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	if r.AccessToken == "" {
		return fmt.Errorf("login: empty access_token")
	}
	c.token = r.AccessToken
	return nil
}

type appResponse struct {
	Proxy   string                     `json:"proxy"`
	Servers map[string]json.RawMessage `json:"servers"`
	User    json.RawMessage            `json:"user"`
}

func (c *client) fetchApp() (*appResponse, error) {
	status, b, err := c.do("GET", "/v1/app?flag=wassvpn", nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("/v1/app: HTTP %d: %s", status, truncate(b, 200))
	}
	var r appResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// decryptProxy decodes the response "proxy" field: N*256-byte RSA blocks,
// each PKCS#1 v1.5 decrypted with the embedded private key, concatenated and
// zlib-decompressed into the YAML node config.
func decryptProxy(proxyB64 string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(proxyB64)
	if err != nil {
		return nil, err
	}
	ks := serverPrivKey.Size()
	if len(data)%ks != 0 {
		return nil, fmt.Errorf("proxy field length %d not multiple of %d", len(data), ks)
	}
	var plain bytes.Buffer
	for i := 0; i < len(data); i += ks {
		p, err := rsa.DecryptPKCS1v15(rand.Reader, serverPrivKey, data[i:i+ks])
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i/ks, err)
		}
		plain.Write(p)
	}
	zr, err := zlib.NewReader(bytes.NewReader(plain.Bytes()))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

// extractX365Links pulls x365:// URIs out of the decrypted YAML without
// pulling in a YAML dependency (the links are plain scalar values).
func extractX365Links(yamlText string) []string {
	var out []string
	for _, line := range strings.Split(yamlText, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "- ")
		line = strings.Trim(line, `"'`)
		if strings.HasPrefix(line, "x365://") {
			out = append(out, line)
		}
	}
	return out
}

func main() {
	var (
		email    = flag.String("email", "", "account email")
		password = flag.String("password", "", "account password")
		did      = flag.String("did", "", "device id (default: random)")
		api      = flag.String("api", defaultAPI, "API base URL")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: x365 <login|nodes|config> [flags]\n")
		flag.PrintDefaults()
	}
	// Allow "x365 <cmd> --flags ..." by hoisting a leading subcommand out
	// of the flag parser's way.
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		os.Args = append([]string{os.Args[0]}, append(os.Args[2:], os.Args[1])...)
	}
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	cmd := args[0]

	if *did == "" {
		*did = os.Getenv("X365_DID")
	}
	if *did == "" {
		*did = newDID()
	}
	if *email == "" || *password == "" {
		fatal("--email and --password are required")
	}

	cl, err := newClient(*api, *did)
	if err != nil {
		fatal("init: %v", err)
	}
	if err := cl.login(*email, *password); err != nil {
		fatal("%v", err)
	}

	switch cmd {
	case "login":
		fmt.Println(cl.token)
	case "config", "nodes":
		app, err := cl.fetchApp()
		if err != nil {
			fatal("%v", err)
		}
		raw, err := decryptProxy(app.Proxy)
		if err != nil {
			fatal("decrypt proxy field: %v", err)
		}
		if cmd == "config" {
			fmt.Print(string(raw))
			return
		}
		links := extractX365Links(string(raw))
		if len(links) == 0 {
			fatal("no x365:// links found in config")
		}
		for _, l := range links {
			fmt.Println(l)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		flag.Usage()
		os.Exit(2)
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "x365: "+format+"\n", a...)
	os.Exit(1)
}
