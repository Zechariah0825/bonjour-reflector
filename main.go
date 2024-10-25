package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Read config file and generate mDNS forwarding maps
	configPath := flag.String("config", "", "Config file in TOML format")
	debug := flag.Bool("debug", false, "Enable pprof server on /debug/pprof/")
	flag.Parse()

	// Start debug server
	if *debug {
		go debugServer(6060)
	}

	cfg, err := readConfig(*configPath)
	if err != nil {
		log.Fatalf("Could not read configuration: %v", err)
	}

	// Get a handle on the network interface
	rawTraffic, err := pcap.OpenLive(cfg.NetInterface, 65536, true, time.Second)
	if err != nil {
		log.Fatalf("Could not find network interface: %v", cfg.NetInterface)
	}

	// Get the local MAC address, to filter out Bonjour packet generated locally
	intf, err := net.InterfaceByName(cfg.NetInterface)
	if err != nil {
		log.Fatal(err)
	}
	brMACAddress := intf.HardwareAddr

	// Filter Bonjour traffic
	filterTemplate := "not (ether src %s) and udp dst port 5353"
	err = rawTraffic.SetBPFFilter(fmt.Sprintf(filterTemplate, brMACAddress))
	if err != nil {
		log.Fatalf("Could not apply filter on network interface: %v", err)
	}

	// Get a channel of Bonjour packets to process
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(rawTraffic, decoder)
	bonjourPackets := parsePacketsLazily(source)

	// Process Bonjour packets
	for bonjourPacket := range bonjourPackets {
		fmt.Println(bonjourPacket.packet.String())

		// 直接发送到多播地址，无需根据 VLAN 选择目标
		sendBonjourPacket(rawTraffic, &bonjourPacket)
	}
}

// 新增获取所有目标 MAC 地址的函数
func getAllTargetMACs(devices map[macAddress]bonjourDevice, srcMAC string) []macAddress {
	var targets []macAddress
	for mac := range devices {
		if mac != macAddress(srcMAC) {
			targets = append(targets, mac)
		}
	}
	return targets
}

func debugServer(port int) {
	err := http.ListenAndServe(fmt.Sprintf("localhost:%d", port), nil)
	if err != nil {
		log.Fatalf("The application was started with -debug flag but could not listen on port %v: \n %s", port, err)
	}
}

}

}
