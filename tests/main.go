package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

var UDP_BUFFER_SIZE = 1600

func UDPEchoServer(address string) {
	addr, _ := net.ResolveUDPAddr("udp", address)
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()
	for {
		buffer := make([]byte, UDP_BUFFER_SIZE)
		sz, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			// silently drop the datagram
			log.Println(err.Error())
			return
		}
		log.Printf("Receive a new packet. Size: %d\n", sz)
		go func(_conn *net.UDPConn, _remote *net.UDPAddr, _buffer []byte) {
			if _, err := _conn.WriteToUDP(_buffer, _remote); err != nil {
				log.Println(err.Error())
				return
			}
		}(conn, remote, buffer[0:sz])
	}
}

func UDPEchoClient(address string) {
	scanner := bufio.NewScanner(os.Stdin)
	destination, _ := net.ResolveUDPAddr("udp", address)
	conn, err := net.DialUDP("udp", nil, destination)
	defer conn.Close()
	if err != nil {
		log.Println(err.Error())
		return
	}
	go func(_conn *net.UDPConn) {
		for {
			buffer := make([]byte, UDP_BUFFER_SIZE)
			if sz, err := _conn.Read(buffer); err == nil {
				fmt.Print(string(buffer[0:sz]))
			} else {
				log.Panicln(err.Error())
			}
		}
	}(conn)
	for scanner.Scan() {
		bs := scanner.Bytes()
		bs = append(bs, '\n')
		if _, err := conn.Write(bs); err != nil {
			log.Println(err.Error())
		}
	}
}

func main() {
	mode := flag.String("mode", "", "The mode. Available: UDPEchoServer, UDPEchoClient")
	address := flag.String("addr", "0.0.0.0:7856", "The listening address.")
	flag.Parse()
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Llongfile)
	switch *mode {
	case "UDPEchoServer":
		log.Printf("Starting UDPEcho server at %s...\n", *address)
		UDPEchoServer(*address)
	case "UDPEchoClient":
		log.Printf("Dail %s...\n", *address)
		UDPEchoClient(*address)
	default:
		flag.Usage()
	}
	return
}
