package main

// collect status from status file and log badly behaved clients

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/kouhin/envflag"
)

var (
	defaultStatusLog = "/tmp/openvpn-status-tcp"
	defaultBanLog    = "/tmp/openvpn-banlist"
	certUndef        = "UNDEF"
	badCipher        = "BF-CBC"
)

var banList = []string{}

func knownIP(ip string) bool {
	for _, i := range banList {
		if ip == i {
			return true
		}
	}
	return false
}

// CLIENT_LIST	UNDEF	5.119.24.29:38511			14	92	2022-10-02 21:34:43	1664746483	UNDEF	559	0	BF-CBC

func collectStatusFromFile(statusPath string, badActorCh chan string) error {
	st, err := os.Open(statusPath)
	defer st.Close()
	if err != nil {
		return err
	}
	return collectServerStatusFromReader(st, badActorCh)
}

func collectServerStatusFromReader(file io.Reader, badActorCh chan string) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		fields = cleanFields(fields)
		if fields[0] != "CLIENT_LIST" {
			continue
		}
		if cert := fields[1]; cert != "UNDEF" {
			continue
		}
		addr := fields[2]
		ip, err := getIP(addr)
		if err != nil {
			log.Println("error parsing", addr)
			continue
		}
		cipher := fields[10]
		if cipher == badCipher {
			badActorCh <- ip
		}
	}
	close(badActorCh)
	return nil
}

// remove double separator in case they alter ordering
func cleanFields(fields []string) []string {
	nf := []string{}
	for _, f := range fields {
		if f == "" {
			continue
		}
		nf = append(nf, f)
	}
	return nf
}

func getIP(addr string) (string, error) {
	p := strings.Split(addr, ":")
	if len(p) != 2 {
		return "", fmt.Errorf("cannot parse %s", addr)
	}
	return p[0], nil
}

func main() {
	var (
		statusLog = flag.String("status-log", defaultStatusLog, "Status log file")
		banLog    = flag.String("ban-log", defaultBanLog, "Ban log file")
	)
	if err := envflag.Parse(); err != nil {
		panic(err)
	}

	log.Println("vpn-watch")

	ban, err := os.OpenFile(*banLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		fmt.Println("Unable to open file:", banLog)
		os.Exit(1)
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()
	// TODO check that file exists
	err = watcher.Add(*statusLog)
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case event := <-watcher.Events:
			ch := make(chan string, 100)
			if event.Op&fsnotify.Write == fsnotify.Write {
				go collectStatusFromFile(*statusLog, ch)
				for ip := range ch {
					if !knownIP(ip) {
						log.Println("bad ip", ip)
						ban.WriteString(fmt.Sprintf("%s\n", ip))
						banList = append(banList, ip)
					}
				}
			}
		case err := <-watcher.Errors:
			log.Println("error:", err)
		}
	}
}
