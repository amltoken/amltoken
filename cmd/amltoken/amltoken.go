package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/skycoin/skycoin/src/api/webrpc"
	"github.com/skycoin/skycoin/src/cipher"
	"github.com/skycoin/skycoin/src/coin"
	"github.com/skycoin/skycoin/src/daemon"
	"github.com/skycoin/skycoin/src/gui"
	"github.com/skycoin/skycoin/src/util/browser"
	"github.com/skycoin/skycoin/src/util/cert"
	"github.com/skycoin/skycoin/src/util/file"
	"github.com/skycoin/skycoin/src/util/logging"
)

var (
	// Version node version which will be set when build wallet by LDFLAGS
	Version    = "0.0.0"
	logger     = logging.MustGetLogger("main")
	logFormat  = "[amltoken.%{module}:%{level}] %{message}"
	logModules = []string{
		"main",
		"daemon",
		"coin",
		"gui",
		"file",
		"visor",
		"wallet",
		"gnet",
		"pex",
		"webrpc",
	}

	// GenesisSignatureStr hex string of genesis signature
	GenesisSignatureStr = "1d0666d5b1823b1f021d1a7e15c8c269f18972ed7e222d038089d8206d16e98652cb4e352841599799b14e22b25fc935f18b3153c1e00ab0d397743cbc72439901"
	// GenesisAddressStr genesis address string
	GenesisAddressStr = "2fswcywrjKebTnWpkFpJBAsXipXHrm6zoMo"
	// BlockchainPubkeyStr pubic key string
	BlockchainPubkeyStr = "03c3e8dc5d36220ce8ef5743128fe6459b2e523d3ce75096a72ef19ce3b04b8e4c"
	// BlockchainSeckeyStr empty private key string
	BlockchainSeckeyStr = ""

	// GenesisTimestamp genesis block create unix time
	GenesisTimestamp uint64 = 1506692743
	// GenesisCoinVolume represents the coin capacity
	GenesisCoinVolume uint64 = 200e12

	// DefaultConnections the default trust node addresses
	DefaultConnections = []string{
		"35.164.14.172:7900",
		"52.32.47.193:7900",
		"52.40.213.149:7900",
		"34.209.186.208:7900",
	}
)

// Command line interface arguments

// Config records the node's configuration
type Config struct {
	// Disable peer exchange
	DisablePEX bool
	// Don't make any outgoing connections
	DisableOutgoingConnections bool
	// Don't allowing incoming connections
	DisableIncomingConnections bool
	// Disables networking altogether
	DisableNetworking bool
	// Only run on localhost and only connect to others on localhost
	LocalhostOnly bool
	// Which address to serve on. Leave blank to automatically assign to a
	// public interface
	Address string
	//gnet uses this for TCP incoming and outgoing
	Port int
	//max connections to maintain
	MaxConnections int
	// How often to make outgoing connections
	OutgoingConnectionsRate time.Duration
	// Wallet Address Version
	//AddressVersion string
	// Remote web interface
	WebInterface      bool
	WebInterfacePort  int
	WebInterfaceAddr  string
	WebInterfaceCert  string
	WebInterfaceKey   string
	WebInterfaceHTTPS bool

	RPCInterface     bool
	RPCInterfacePort int
	RPCInterfaceAddr string

	// Launch System Default Browser after client startup
	LaunchBrowser bool

	// If true, print the configured client web interface address and exit
	PrintWebInterfaceAddress bool

	// Data directory holds app data -- defaults to ~/.skycoin
	DataDirectory string
	// GUI directory contains assets for the html gui
	GUIDirectory string

	// Logging
	ColorLog bool
	// This is the value registered with flag, it is converted to LogLevel after parsing
	LogLevel string

	// Wallets
	// Defaults to ${DataDirectory}/wallets/
	WalletDirectory string

	RunMaster bool

	GenesisSignature cipher.Sig
	GenesisTimestamp uint64
	GenesisAddress   cipher.Address

	BlockchainPubkey cipher.PubKey
	BlockchainSeckey cipher.SecKey

	/* Developer options */

	// Enable cpu profiling
	ProfileCPU bool
	// Where the file is written to
	ProfileCPUFile string
	// HTTP profiling interface (see http://golang.org/pkg/net/http/pprof/)
	HTTPProf bool
	// Will force it to connect to this ip:port, instead of waiting for it
	// to show up as a peer
	ConnectTo string

	DBPath       string
	Arbitrating  bool
	RPCThreadNum uint // rpc number
	Logtofile    bool
}

func (c *Config) register() {
	flag.BoolVar(&c.DisablePEX, "disable-pex", c.DisablePEX,
		"disable PEX peer discovery")
	flag.BoolVar(&c.DisableOutgoingConnections, "disable-outgoing",
		c.DisableOutgoingConnections, "Don't make outgoing connections")
	flag.BoolVar(&c.DisableIncomingConnections, "disable-incoming",
		c.DisableIncomingConnections, "Don't make incoming connections")
	flag.BoolVar(&c.DisableNetworking, "disable-networking",
		c.DisableNetworking, "Disable all network activity")
	flag.StringVar(&c.Address, "address", c.Address,
		"IP Address to run application on. Leave empty to default to a public interface")
	flag.IntVar(&c.Port, "port", c.Port, "Port to run application on")
	flag.BoolVar(&c.WebInterface, "web-interface", c.WebInterface,
		"enable the web interface")
	flag.IntVar(&c.WebInterfacePort, "web-interface-port",
		c.WebInterfacePort, "port to serve web interface on")
	flag.StringVar(&c.WebInterfaceAddr, "web-interface-addr",
		c.WebInterfaceAddr, "addr to serve web interface on")
	flag.StringVar(&c.WebInterfaceCert, "web-interface-cert",
		c.WebInterfaceCert, "cert.pem file for web interface HTTPS. "+
			"If not provided, will use cert.pem in -data-directory")
	flag.StringVar(&c.WebInterfaceKey, "web-interface-key",
		c.WebInterfaceKey, "key.pem file for web interface HTTPS. "+
			"If not provided, will use key.pem in -data-directory")
	flag.BoolVar(&c.WebInterfaceHTTPS, "web-interface-https",
		c.WebInterfaceHTTPS, "enable HTTPS for web interface")

	flag.BoolVar(&c.RPCInterface, "rpc-interface", c.RPCInterface,
		"enable the rpc interface")
	flag.IntVar(&c.RPCInterfacePort, "rpc-interface-port", c.RPCInterfacePort,
		"port to serve rpc interface on")
	flag.StringVar(&c.RPCInterfaceAddr, "rpc-interface-addr", c.RPCInterfaceAddr,
		"addr to serve rpc interface on")
	flag.UintVar(&c.RPCThreadNum, "rpc-thread-num", 5, "rpc thread number")

	flag.BoolVar(&c.LaunchBrowser, "launch-browser", c.LaunchBrowser,
		"launch system default webbrowser at client startup")
	flag.BoolVar(&c.PrintWebInterfaceAddress, "print-web-interface-address",
		c.PrintWebInterfaceAddress, "print configured web interface address and exit")
	flag.StringVar(&c.DataDirectory, "data-dir", c.DataDirectory,
		"directory to store app data (defaults to ~/.skycoin)")
	flag.StringVar(&c.ConnectTo, "connect-to", c.ConnectTo,
		"connect to this ip only")
	flag.BoolVar(&c.ProfileCPU, "profile-cpu", c.ProfileCPU,
		"enable cpu profiling")
	flag.StringVar(&c.ProfileCPUFile, "profile-cpu-file",
		c.ProfileCPUFile, "where to write the cpu profile file")
	flag.BoolVar(&c.HTTPProf, "http-prof", c.HTTPProf,
		"Run the http profiling interface")
	flag.StringVar(&c.LogLevel, "log-level", c.LogLevel,
		"Choices are: debug, info, notice, warning, error, critical")
	flag.BoolVar(&c.ColorLog, "color-log", c.ColorLog,
		"Add terminal colors to log output")
	flag.BoolVar(&c.Logtofile, "logtofile", false, "log to file")
	flag.StringVar(&c.GUIDirectory, "gui-dir", c.GUIDirectory,
		"static content directory for the html gui")

	//Key Configuration Data
	flag.BoolVar(&c.RunMaster, "master", c.RunMaster,
		"run the daemon as blockchain master server")

	flag.StringVar(&BlockchainPubkeyStr, "master-public-key", BlockchainPubkeyStr,
		"public key of the master chain")
	flag.StringVar(&BlockchainSeckeyStr, "master-secret-key", BlockchainSeckeyStr,
		"secret key, set for master")

	flag.StringVar(&GenesisAddressStr, "genesis-address", GenesisAddressStr,
		"genesis address")
	flag.StringVar(&GenesisSignatureStr, "genesis-signature", GenesisSignatureStr,
		"genesis block signature")
	flag.Uint64Var(&c.GenesisTimestamp, "genesis-timestamp", c.GenesisTimestamp,
		"genesis block timestamp")

	flag.StringVar(&c.WalletDirectory, "wallet-dir", c.WalletDirectory,
		"location of the wallet files. Defaults to ~/.amltoken/wallet/")

	flag.DurationVar(&c.OutgoingConnectionsRate, "connection-rate",
		c.OutgoingConnectionsRate, "How often to make an outgoing connection")
	flag.BoolVar(&c.LocalhostOnly, "localhost-only", c.LocalhostOnly,
		"Run on localhost and only connect to localhost peers")
	flag.BoolVar(&c.Arbitrating, "arbitrating", c.Arbitrating, "Run node in arbitrating mode")
	//flag.StringVar(&c.AddressVersion, "address-version", c.AddressVersion,
	//	"Wallet address version. Options are 'test' and 'main'")
}

var devConfig = Config{
	// Disable peer exchange
	DisablePEX: false,
	// Don't make any outgoing connections
	DisableOutgoingConnections: false,
	// Don't allowing incoming connections
	DisableIncomingConnections: false,
	// Disables networking altogether
	DisableNetworking: false,
	// Only run on localhost and only connect to others on localhost
	LocalhostOnly: false,
	// Which address to serve on. Leave blank to automatically assign to a
	// public interface
	Address: "",
	//gnet uses this for TCP incoming and outgoing
	Port: 7900,

	MaxConnections: 16,
	// How often to make outgoing connections, in seconds
	OutgoingConnectionsRate: time.Second * 5,
	// Wallet Address Version
	//AddressVersion: "test",
	// Remote web interface
	WebInterface:             true,
	WebInterfacePort:         7920,
	WebInterfaceAddr:         "127.0.0.1",
	WebInterfaceCert:         "",
	WebInterfaceKey:          "",
	WebInterfaceHTTPS:        false,
	PrintWebInterfaceAddress: false,

	RPCInterface:     true,
	RPCInterfacePort: 7930,
	RPCInterfaceAddr: "127.0.0.1",
	RPCThreadNum:     5,

	LaunchBrowser: true,
	// Data directory holds app data -- defaults to ~/.skycoin
	DataDirectory: ".amltoken",
	// Web GUI static resources
	GUIDirectory: "./src/gui/static/",
	// Logging
	ColorLog: true,
	LogLevel: "DEBUG",

	// Wallets
	WalletDirectory: "",

	// Centralized network configuration
	RunMaster:        false,
	BlockchainPubkey: cipher.PubKey{},
	BlockchainSeckey: cipher.SecKey{},

	GenesisAddress:   cipher.Address{},
	GenesisTimestamp: GenesisTimestamp,
	GenesisSignature: cipher.Sig{},

	/* Developer options */

	// Enable cpu profiling
	ProfileCPU: false,
	// Where the file is written to
	ProfileCPUFile: "amltoken.prof",
	// HTTP profiling interface (see http://golang.org/pkg/net/http/pprof/)
	HTTPProf: false,
	// Will force it to connect to this ip:port, instead of waiting for it
	// to show up as a peer
	ConnectTo: "",
}

// Parse prepare the config
func (c *Config) Parse() {
	c.register()
	flag.Parse()
	c.postProcess()
}

func (c *Config) postProcess() {
	var err error
	if GenesisSignatureStr != "" {
		c.GenesisSignature, err = cipher.SigFromHex(GenesisSignatureStr)
		panicIfError(err, "Invalid Signature")
	}
	if GenesisAddressStr != "" {
		c.GenesisAddress, err = cipher.DecodeBase58Address(GenesisAddressStr)
		panicIfError(err, "Invalid Address")
	}
	if BlockchainPubkeyStr != "" {
		c.BlockchainPubkey, err = cipher.PubKeyFromHex(BlockchainPubkeyStr)
		panicIfError(err, "Invalid Pubkey")
	}
	if BlockchainSeckeyStr != "" {
		c.BlockchainSeckey, err = cipher.SecKeyFromHex(BlockchainSeckeyStr)
		panicIfError(err, "Invalid Seckey")
		BlockchainSeckeyStr = ""
	}
	if BlockchainSeckeyStr != "" {
		c.BlockchainSeckey = cipher.SecKey{}
	}

	c.DataDirectory, err = file.InitDataDir(c.DataDirectory)
	panicIfError(err, "Invalid DataDirectory")

	if c.WebInterfaceCert == "" {
		c.WebInterfaceCert = filepath.Join(c.DataDirectory, "cert.pem")
	}
	if c.WebInterfaceKey == "" {
		c.WebInterfaceKey = filepath.Join(c.DataDirectory, "key.pem")
	}

	if c.WalletDirectory == "" {
		c.WalletDirectory = filepath.Join(c.DataDirectory, "wallets/")
	}

	if c.DBPath == "" {
		c.DBPath = filepath.Join(c.DataDirectory, "data.db")
	}
}

func panicIfError(err error, msg string, args ...interface{}) {
	if err != nil {
		log.Panicf(msg+": %v", append(args, err)...)
	}
}

func printProgramStatus() {
	fn := "goroutine.prof"
	logger.Debug("Writing goroutine profile to %s", fn)
	p := pprof.Lookup("goroutine")
	f, err := os.Create(fn)
	defer f.Close()
	if err != nil {
		logger.Error("%v", err)
		return
	}
	err = p.WriteTo(f, 2)
	if err != nil {
		logger.Error("%v", err)
		return
	}
}

func catchInterrupt(quit chan<- struct{}) {
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt)
	<-sigchan
	signal.Stop(sigchan)
	close(quit)
}

// Catches SIGUSR1 and prints internal program state
func catchDebug() {
	sigchan := make(chan os.Signal, 1)
	//signal.Notify(sigchan, syscall.SIGUSR1)
	signal.Notify(sigchan, syscall.Signal(0xa)) // SIGUSR1 = Signal(0xa)
	for {
		select {
		case <-sigchan:
			printProgramStatus()
		}
	}
}

// init logging settings
func initLogging(dataDir string, level string, color, logtofile bool) (func(), error) {
	logCfg := logging.DevLogConfig(logModules)
	logCfg.Format = logFormat
	logCfg.Colors = color
	logCfg.Level = level

	var fd *os.File
	if logtofile {
		logDir := filepath.Join(dataDir, "logs")
		if err := createDirIfNotExist(logDir); err != nil {
			log.Println("initial logs folder failed", err)
			return nil, fmt.Errorf("init log folder fail, %v", err)
		}

		// open log file
		tf := "2006-01-02-030405"
		logfile := filepath.Join(logDir,
			fmt.Sprintf("%s-v%s.log", time.Now().Format(tf), Version))
		var err error
		fd, err = os.OpenFile(logfile, os.O_RDWR|os.O_CREATE, 0666)
		if err != nil {
			return nil, err
		}

		logCfg.Output = io.MultiWriter(os.Stdout, fd)
	}

	logCfg.InitLogger()

	return func() {
		logger.Info("Log file closed")
		if fd != nil {
			fd.Close()
		}
	}, nil
}

func initProfiling(httpProf, profileCPU bool, profileCPUFile string) {
	if profileCPU {
		f, err := os.Create(profileCPUFile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	if httpProf {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}
}

func configureDaemon(c *Config) daemon.Config {
	//cipher.SetAddressVersion(c.AddressVersion)

	dc := daemon.NewConfig()
	dc.Peers.DataDirectory = c.DataDirectory
	dc.Peers.Disabled = c.DisablePEX
	dc.Daemon.DisableOutgoingConnections = c.DisableOutgoingConnections
	dc.Daemon.DisableIncomingConnections = c.DisableIncomingConnections
	dc.Daemon.DisableNetworking = c.DisableNetworking
	dc.Daemon.Port = c.Port
	dc.Daemon.Address = c.Address
	dc.Daemon.LocalhostOnly = c.LocalhostOnly
	dc.Daemon.OutgoingMax = c.MaxConnections

	daemon.DefaultConnections = DefaultConnections

	if c.OutgoingConnectionsRate == 0 {
		c.OutgoingConnectionsRate = time.Millisecond
	}
	dc.Daemon.OutgoingRate = c.OutgoingConnectionsRate

	dc.Visor.Config.IsMaster = c.RunMaster

	dc.Visor.Config.BlockchainPubkey = c.BlockchainPubkey
	dc.Visor.Config.BlockchainSeckey = c.BlockchainSeckey

	dc.Visor.Config.GenesisAddress = c.GenesisAddress
	dc.Visor.Config.GenesisSignature = c.GenesisSignature
	dc.Visor.Config.GenesisTimestamp = c.GenesisTimestamp
	dc.Visor.Config.GenesisCoinVolume = GenesisCoinVolume
	dc.Visor.Config.DBPath = c.DBPath
	dc.Visor.Config.Arbitrating = c.Arbitrating
	return dc
}

// Run starts the skycoin node
func Run(c *Config) {
	defer func() {
		// try catch panic in main thread
		if r := recover(); r != nil {
			logger.Error("recover: %v\nstack:%v", r, string(debug.Stack()))
		}
	}()

	c.GUIDirectory = file.ResolveResourceDirectory(c.GUIDirectory)

	scheme := "http"
	if c.WebInterfaceHTTPS {
		scheme = "https"
	}
	host := fmt.Sprintf("%s:%d", c.WebInterfaceAddr, c.WebInterfacePort)
	fullAddress := fmt.Sprintf("%s://%s", scheme, host)
	logger.Critical("Full address: %s", fullAddress)

	if c.PrintWebInterfaceAddress {
		fmt.Println(fullAddress)
		return
	}

	initProfiling(c.HTTPProf, c.ProfileCPU, c.ProfileCPUFile)

	closelog, err := initLogging(c.DataDirectory, c.LogLevel, c.ColorLog, c.Logtofile)
	if err != nil {
		fmt.Println(err)
		return
	}

	// If the user Ctrl-C's, shutdown properly
	quit := make(chan struct{})

	go catchInterrupt(quit)
	// Watch for SIGUSR1
	go catchDebug()

	gui.InitWalletRPC(c.WalletDirectory)

	dconf := configureDaemon(c)
	d, err := daemon.NewDaemon(dconf)
	if err != nil {
		logger.Error("%v", err)
		return
	}

	errC := make(chan error, 1)

	go func() {
		errC <- d.Run()
	}()

	var rpc *webrpc.WebRPC
	// start the webrpc
	if c.RPCInterface {
		rpc, err = webrpc.New(
			fmt.Sprintf("%v:%v", c.RPCInterfaceAddr, c.RPCInterfacePort),
			webrpc.ChanBuffSize(1000),
			webrpc.ThreadNum(c.RPCThreadNum),
			webrpc.Gateway(d.Gateway))
		if err != nil {
			logger.Error("%v", err)
			return
		}

		go func() {
			errC <- rpc.Run()
		}()
	}

	// Debug only - forces connection on start.  Violates thread safety.
	if c.ConnectTo != "" {
		if err := d.Pool.Pool.Connect(c.ConnectTo); err != nil {
			logger.Error("Force connect %s failed, %v", c.ConnectTo, err)
			return
		}
	}

	if c.WebInterface {
		var err error
		if c.WebInterfaceHTTPS {
			// Verify cert/key parameters, and if neither exist, create them
			errs := cert.CreateCertIfNotExists(host, c.WebInterfaceCert, c.WebInterfaceKey, "Skycoind")
			if len(errs) != 0 {
				for _, err := range errs {
					logger.Error(err.Error())
				}
				logger.Error("gui.CreateCertIfNotExists failure")
				return
			}

			err = gui.LaunchWebInterfaceHTTPS(host, c.GUIDirectory, d, c.WebInterfaceCert, c.WebInterfaceKey)
		} else {
			err = gui.LaunchWebInterface(host, c.GUIDirectory, d)
		}

		if err != nil {
			logger.Error(err.Error())
			logger.Error("Failed to start web GUI")
			return
		}

		if c.LaunchBrowser {
			go func() {
				// Wait a moment just to make sure the http interface is up
				time.Sleep(time.Millisecond * 100)

				logger.Info("Launching System Browser with %s", fullAddress)
				if err := browser.Open(fullAddress); err != nil {
					logger.Error(err.Error())
					return
				}
			}()
		}
	}

	// first transaction
	// if c.RunMaster == true {
	// 	go func() {
	// 		if d.Visor.HeadBkSeq() < 2 {
	// 			time.Sleep(5)
	// 			tx := InitTransaction()
	// 			_, err := d.Visor.InjectTxn(tx)
	// 			if err != nil {
	// 				log.Panic(err)
	// 			}
	// 		}
	// 	}()
	// }

	select {
	case <-quit:
	case err := <-errC:
		logger.Error("%v", err)
	}

	logger.Info("Shutting down...")

	if rpc != nil {
		rpc.Shutdown()
	}

	gui.Shutdown()
	d.Shutdown()
	closelog()
	logger.Info("Goodbye")
}

func main() {
	devConfig.Parse()
	Run(&devConfig)
}

// AddrList for storage of coins
var AddrList = []string{
	"2JJEtAuBUDBJ8xHNskrxuuC2TktUWHQeNA2",
	"2BjdXGuY7LCj8M1JszCoM8trqWirK9f8ofg",
	"29cfZuRsF7bKu197gL6J5dbaxwf83fubZ5C",
	"39QeiLwUop2nXqV8nZoMY8xFTpCH9iuyHM",
	"qoMoYW2ttAvEHVCkdKMceE8wnAssDT2PPF",
	"u77ohGCZ9w8VErvam5aqCffWU57yFqZb5P",
	"23dMCqQipWVXBGe7Y3fP5Uuup2TtQEKW724",
	"2dYKJ1RAcbFbh34ksm8XmQNnj25fhW4mnTZ",
	"GzUFgj9fqMMxFTREa48DontB7abbqfrBC6",
	"2Mamt9DPQd8s9qsSGqKaNhdpqk4hoMpj6Jo",
	"2MXQBaa2pfM3p1c6FXsvx55CHtDR2sA7mUT",
	"L9C9wAij4nGKi4iShKqF6PyfRRHU1JSC2U",
	"2kNnuhJHJsVSD6xWg44kSiMFNfNpqnGHXUx",
	"NGJ2SGW5SgEXGoD5Y43y7Mppg5sN3SN52F",
	"2S6TBN54SoTWNbcPpcvUikUJh2Jd7U9pMLB",
	"3cMne2y7dn26DdBjwvWjtgMJXVNkeMh9kZ",
	"2SVq67bySStCz8pNqUgyHR9aeDpwPxKpjP6",
	"24FjwvFss4Dm1Cq8z4NjycBJns6pAL3rV4S",
	"aggUFSVUkPQ15gb8XPWvrjTsCVeW1hBaG2",
	"2Sfm5yduWFTgaCAkLnJW6HUj5ndB6dVHTJL",
	"2hr8vxn3bW28HpKFedbu38F3YYmm9oXjwHb",
	"2ejik8FyBcmKSKYugz2CNP4GNoLCnzJGSyg",
	"PnrmTEoVPJpJ4GcTjoF8Bw7GWsxdRS9gTa",
	"2X4eHhgJxTWGVKJM4NRoZRprfBap8EDczs2",
	"27SLH5Ne8iiqkjYD3jnLufAG6sZkyWMSN5p",
	"WhAnCQiHh3HheBrQiaSpgaYmtvsmB1y7VP",
	"2iEH4D9wwEpZ62FwyufTKMYmC24s2E9eXNE",
	"2jR5LH5gPKY9T2Bdg3yyyfMonp2YNddgZ52",
	"2kbwLr6YBCPqRUBQNTnVKd9xVLyp1UAEHwv",
	"2aNq6bh1yrRVDobqjyacHCdurwuRqYp5Eut",
	"2Gz9DUUkZUqWZSixvtGKJi8sQkUCh47QayW",
	"3dmvZTAAf3XhYGPwuxuXoZPhukt4gC7XsP",
	"hhSqLT9jerGJQWvHmvXf8HopWcxL4gXMCv",
	"Uy14Zesirps9cwaBnepWEXmWEu79fCc8kx",
	"BBcDkrCt5TLKUvCHwok61T7v3zkVYoTLSx",
	"JJuhZsE5urn7WduHFgf5g8XwvCXfxCrfvV",
	"23sT4AChLHL9kadCFDEG7Lj36pTf3XjLoUm",
	"nAKC8FqwUdj4PKmk3ZFAwGFq2RrkVwvaCH",
	"EJg6wRVoL1hyxTNtttVkhedivAvw1gajHv",
	"cUURiFKpE3qnnoYar3PiTKA2wU9FWofs5U",
	"M6TWCmeJ6sqb6qHiciAofJ7z6m1ZrpwAVX",
	"28JU41aT12JXcb7kHbKBeqbWPfdVq5zAJCV",
	"Aas1kBHPvVmrpXfCJsnvf4fTRi35zFQK6h",
	"y2wcV6vtZCHhjwRddZFbjj2Gmutfs3mWqa",
	"qH17kDsF5qgQBmufygFiup13XN18P6XxCK",
	"2moGwJZkeidsEkWyMevfVc2j8EGQrwheNYt",
	"CvScP6DZYka6Qn7SGRzRhtZZwut1gBZLn1",
	"qSqeLxDRBRd9eFxje5GsHoEvSHdWfkxGtS",
	"2XRHq1BFqDqPKxxup5NGGTbdakD5WYg6rB7",
	"LMXuKJnM86z7guE76e13RMNA9xxRjzcRVQ",
	"FLfwWKmXcXSwLBcL5pub38W8hszUp1UkYP",
	"29dXgiEBqk9jmjjbjWG3veiaGUhe4x4Kxxp",
	"2CGahZJoQWXACD8rVhiAmBqdsia73y3Tt6H",
	"2DjjqCQ9FiXGVNxvn9H3UrVMmTt9qdjExgF",
	"Vc8E6H3dvEgW6fxSwS8dqy7fSyBWieYYkk",
	"2JhRUXYhWBmpJnXtRZbBfMH5fQAKUGkcWuX",
	"yFs1ptqRNDBtEysEC2q2Rs6Y7VoVazevFc",
	"25pLSp1k2ffuYzFkK2vTkV7nsaKPZgsEkcJ",
	"2anhiQddMQ92KKhpNsuxwmdDLd77v7HuMJ",
	"pgd4VkE7xVTWC89A5EemfhbKg23vbomzYB",
	"2iyv3X68Eg33Zbe8AWmv6SBD6F3UgUFw8Pd",
	"sURLj4pe8Doee1Ghms6DEUgmhbuU4KqbBQ",
	"2UoRpd8XqGikyhnRcrV8bhLrn8zbwyQ4cSo",
	"uxhd6fsYBf97otqCEdViVx9AtFLUsTpDbF",
	"e98bRm4Sc7CPSxePwUh9PWqcM64EnXhoKG",
	"2KmWJsD5sNLFaPFHKn4q2SCNQKU8NsFpK1B",
	"TXyS1X3izM8DqYVd61kTVN3LF9HHJcjdAB",
	"DUAXxT4GzZcm7u94w3oNoE3gRyjaMVxkEW",
	"cfAMxg18RBgg7XkoP6kPGhgiiQLEzqct7o",
	"2GsxADgubEXTzieoRkHN3Zq4Uq2Z9DjPgfo",
	"AULy9rP5ySLHCBPDnqu3e1LEa77kCGLEXb",
	"pBunuc34YERVaeY8H4DjpnFnDviQvTtoCP",
	"5VieYZQ245sC7iLRGcsJdajmmG7jc4Y4hd",
	"2abiLVQyM3VaH8Wc3vXs9dAYYkJbRMnz9hL",
	"2BnkGrPo1DGhH9Rp42dHg3BKM2nc29McmXu",
	"2LCUJZMDCnBVyiRBmu64AVhJ8VsJXpHes1k",
	"HGp8mbubmcjoS9xP9TfG43niYht1XkstFn",
	"Jnxrp3fK6kG6oTAcBhTg2Tp7PkzpBveRCo",
	"3GZdt8po1j6LgNMHJdekZcLZzi2RpKjmYZ",
	"JvVWrxH2nRcYagH2LApX8cj1dbaED5dozG",
	"RGcEWu9ryJ5MmsrTFZv7ZU551hKoviAGMf",
	"2YsTfoBUxEuPzWqrpM7VExouSUvEURH1oNv",
	"28Wzos2Ya1JH94T6agVEwKTfQKh8oEcufi4",
	"crkqc88qyYUhvYAyAbVVLTMdTHEKNcemR1",
	"2Qc2JTPbnFP1vfHw1uExcMMok1DwwgK64aa",
	"nVuNAbDzRLwtD4mmNLZcjreF2RHUzYNKLr",
	"Gt8JEfdvxnbh8ChMcjazBwdUckMgigoPLn",
	"2YDnqqAuiF9Nw1JHsdVhx2SzqBc5Upgodfu",
	"2MB7aQ3PJ3YySHbRNFFtiYESpuXkuJ2rzfj",
	"cYW3NpmSQcF91jHsBpphMsPEJRiT25iqVC",
	"Kkpd9AXAtNHLsq6Xa6gw5Ha2Q8RfedLRvN",
	"nYEdPuNCeGeyWxJzcp2grBFTSV891nBigk",
	"9yifSbf2zemFmUQVBgDWaxu8wSYVrBSpSc",
	"2Frw2Je3LwUs8RkCtCprrAXKJBeCFX5fkqm",
	"2UN4vzSgKUvUteWrx6MerJAfLRy6SCQ9ZyL",
	"2BSVbLKLPEPK7arnnFmiQSMTBTNfPSnpNqC",
	"5kF14Mh8BpkRR3mu8tdwKJxnyy5JPjR3WP",
	"vCFsyTQ3bNKafqrMnaJmDVq8tnU56QdAsa",
	"eH6X9wrNeyfy5HEjE2NmKwfaefBF35JWss",
	"9NGErBjwDmBa6UTBbVEGKJ5TSQ8MU3Hr18",
}

// InitTransaction creates the initialize transaction
func InitTransaction() coin.Transaction {
	var tx coin.Transaction

	output := cipher.MustSHA256FromHex("cee4353f4c0fc825d5c34f127d7b7f28c6746189b14a65710e66b5d116778b65")
	tx.PushInput(output)

	for i := 0; i < 100; i++ {
		addr := cipher.MustDecodeBase58Address(AddrList[i])
		tx.PushOutput(addr, 2e12, 1) // 20e6*10e6
	}
	// seckeyStr := ""
	// seckey := cipher.SecKeyFromHex(seckeyStr)
	// tx.SignInputs([]cipher.SecKey{seckey})

	txs := make([]cipher.Sig, 1)
	sig := "82ceab31a8eb9a2faedb52899bf078be07e53e5835f471cb273093d25f20536e58e2856486f52e9b701bb26b8c2de79567c20c04365098a34e55ea76c7bb88e800"
	txs[0] = cipher.MustSigFromHex(sig)
	tx.Sigs = txs

	tx.UpdateHeader()

	err := tx.Verify()

	if err != nil {
		log.Panic(err)
	}

	log.Printf("signature= %s", tx.Sigs[0].Hex())
	return tx
}

func createDirIfNotExist(dir string) error {
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		return nil
	}

	return os.Mkdir(dir, 0777)
}
