package main

import (
	"net"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type bonjourPacket struct {
	packet     gopacket.Packet
	srcMAC     *net.HardwareAddr
	dstMAC     *net.HardwareAddr
	isIPv6     bool
	isDNSQuery bool
}

func parsePacketsLazily(source *gopacket.PacketSource) chan bonjourPacket {
	source.DecodeOptions = gopacket.DecodeOptions{Lazy: true}
	packetChan := make(chan bonjourPacket, 100)

	go func() {
		for packet := range source.Packets() {
			srcMAC, dstMAC := parseEthernetLayer(packet)
			isIPv6 := parseIPLayer(packet)
			payload := parseUDPLayer(packet)
			isDNSQuery := parseDNSPayload(payload)

			packetChan <- bonjourPacket{
				packet:     packet,
				srcMAC:     srcMAC,
				dstMAC:     dstMAC,
				isIPv6:     isIPv6,
				isDNSQuery: isDNSQuery,
			}
		}
	}()

	return packetChan
}

func parseEthernetLayer(packet gopacket.Packet) (srcMAC, dstMAC *net.HardwareAddr) {
	if parsedEth := packet.Layer(layers.LayerTypeEthernet); parsedEth != nil {
		srcMAC = &parsedEth.(*layers.Ethernet).SrcMAC
		dstMAC = &parsedEth.(*layers.Ethernet).DstMAC
	}
	return
}

func parseIPLayer(packet gopacket.Packet) bool {
	return packet.Layer(layers.LayerTypeIPv6) != nil
}

func parseUDPLayer(packet gopacket.Packet) []byte {
	if parsedUDP := packet.Layer(layers.LayerTypeUDP); parsedUDP != nil {
		return parsedUDP.(*layers.UDP).Payload
	}
	return nil
}

func parseDNSPayload(payload []byte) bool {
	packet := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)
	if parsedDNS := packet.Layer(layers.LayerTypeDNS); parsedDNS != nil {
		return !parsedDNS.(*layers.DNS).QR
	}
	return false
}

func sendBonjourPacket(handle packetWriter, bonjourPacket *bonjourPacket, brMACAddress net.HardwareAddr) {
	*bonjourPacket.srcMAC = brMACAddress
	if bonjourPacket.isIPv6 {
		*bonjourPacket.dstMAC = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0xFB}
	} else {
		*bonjourPacket.dstMAC = net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB}
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializePacket(buf, gopacket.SerializeOptions{}, bonjourPacket.packet)
	handle.WritePacketData(buf.Bytes())
}

