package main

// collect status from status file and log badly behaved clients

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

var (
	statusLog = "/tmp/openvpn-status-tcp"
	banLog    = "/tmp/openvpn-banlist"
	certUndef = "UNDEF"
	badCipher = "BF-CBC"
)

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
		cert := fields[1]
		addr := fields[2]
		log.Println("cert:", cert)
		if cert != "UNDEF" {
			continue
		}
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
	log.Println("vpn-watch")
	ban, err := os.OpenFile(banLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		fmt.Println("Unable to open file:", banLog)
		os.Exit(1)
	}
	ch := make(chan string, 1000)
	go collectStatusFromFile(statusLog, ch)
	for ip := range ch {
		log.Println("bad ip", ip)
		ban.WriteString(fmt.Sprintf("bad ip: %s\n", ip))
	}
}
