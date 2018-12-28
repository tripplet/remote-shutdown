package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type params struct {
	host    string
	port    int
	token   string
	timeout int
	force   bool
	verbose bool
}

var config params

func main() {
	flag.StringVar(&config.token, "token", "", "Shared secret")
	flag.StringVar(&config.host, "host", "", "Adress/IP of windows pc")
	flag.IntVar(&config.port, "port", 10102, "Port")
	flag.IntVar(&config.timeout, "timeout", 3, "Timeout for request in seconds")
	flag.BoolVar(&config.verbose, "verbose", false, "Verbose mode")
	flag.Parse()

	var command string
	if config.force {
		command = "admin_shutdown."
	} else {
		command = "shutdown."
	}

	d := net.Dialer{Timeout: time.Duration(config.timeout) * time.Second}
	conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", config.host, config.port))
	checkError(err)

	_, err = conn.Write([]byte("request_challange\n"))
	checkError(err)

	reader := bufio.NewReader(conn)

	challange, err := reader.ReadString('\n')
	checkError(err)

	challange = strings.Trim(challange, "\n")

	mac := hmac.New(sha256.New, []byte(config.token))
	mac.Write([]byte(command + challange))

	responseMac := hex.EncodeToString(mac.Sum(nil))

	_, err = conn.Write([]byte(command + responseMac + "\n"))

	result, err := reader.ReadString('\n')
	checkError(err)

	result = strings.Trim(result, "\n")
	fmt.Println(result)

	if result == "1" {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
