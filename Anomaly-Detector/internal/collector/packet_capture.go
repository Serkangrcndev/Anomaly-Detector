package collector

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"anomaly-detector/internal/models"
)

type PacketCapture struct {
	handle      *pcap.Handle
	packetChan  chan *models.Packet
	ctx         context.Context
	cancel      context.CancelFunc
	interfaceName string
	bpfFilter   string
}

func NewPacketCapture(interfaceName, bpfFilter string) (*PacketCapture, error) {
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w", interfaceName, err)
	}
	
	if bpfFilter != "" {
		err = handle.SetBPFFilter(bpfFilter)
		if err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &PacketCapture{
		handle:        handle,
		packetChan:    make(chan *models.Packet, 1000),
		ctx:           ctx,
		cancel:        cancel,
		interfaceName: interfaceName,
		bpfFilter:     bpfFilter,
	}, nil
}

func (pc *PacketCapture) Start() error {
	log.Printf("[Capture] Starting packet capture on interface: %s", pc.interfaceName)
	if pc.bpfFilter != "" {
		log.Printf("[Capture] BPF Filter: %s", pc.bpfFilter)
	}
	
	packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())
	
	go func() {
		defer close(pc.packetChan)
		
		for {
			select {
			case <-pc.ctx.Done():
				log.Println("[Capture] Stopping packet capture")
				return
			case packet := <-packetSource.Packets():
				if packet == nil {
					continue
				}
				
				parsedPacket := pc.parsePacket(packet)
				if parsedPacket != nil {
					select {
					case pc.packetChan <- parsedPacket:
					case <-pc.ctx.Done():
						return
					}
				}
			}
		}
	}()
	
	return nil
}

func (pc *PacketCapture) Stop() {
	pc.cancel()
	if pc.handle != nil {
		pc.handle.Close()
	}
}

func (pc *PacketCapture) GetPacketChannel() <-chan *models.Packet {
	return pc.packetChan
}

func (pc *PacketCapture) parsePacket(packet gopacket.Packet) *models.Packet {
	parsed := &models.Packet{
		Timestamp: time.Now(),
	}
	
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		switch layer := netLayer.(type) {
		case *layers.IPv4:
			parsed.SrcIP = net.IP(layer.SrcIP)
			parsed.DstIP = net.IP(layer.DstIP)
		case *layers.IPv6:
			parsed.SrcIP = net.IP(layer.SrcIP)
			parsed.DstIP = net.IP(layer.DstIP)
		default:
			return nil
		}
	} else {
		return nil
	}
	
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		switch layer := transportLayer.(type) {
		case *layers.TCP:
			parsed.SrcPort = uint16(layer.SrcPort)
			parsed.DstPort = uint16(layer.DstPort)
			parsed.Protocol = "TCP"
			parsed.IsSYN = layer.SYN && !layer.ACK
			parsed.IsACK = layer.ACK
			
		case *layers.UDP:
			parsed.SrcPort = uint16(layer.SrcPort)
			parsed.DstPort = uint16(layer.DstPort)
			parsed.Protocol = "UDP"
			
		default:
			parsed.Protocol = "OTHER"
		}
	}
	
	if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
		parsed.Protocol = "ICMP"
	}

	if metadata := packet.Metadata(); metadata != nil {
		parsed.Length = metadata.CaptureLength
	} else {
		parsed.Length = len(packet.Data())
	}
	
	return parsed
}

func GetAvailableInterfaces() ([]string, error) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to find interfaces: %w", err)
	}
	
	var names []string
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}
	
	return names, nil
}

func FindDefaultInterface() (string, string, error) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return "", "", fmt.Errorf("pcap arayüzleri alınamadı (Npcap kurulu mu?): %w", err)
	}
	
	if len(interfaces) == 0 {
		return "", "", fmt.Errorf("hiç ağ arayüzü bulunamadı - Npcap/WinPcap kontrol edin")
	}
	
	fmt.Println("[DEBUG] Bulunan ağ arayüzleri:")
	for _, iface := range interfaces {
		hasIP := len(iface.Addresses) > 0
		fmt.Printf("  - %s (Flags: %d, IP var: %v)\n", iface.Name, iface.Flags, hasIP)
	}
	
	for _, iface := range interfaces {
		if strings.Contains(strings.ToLower(iface.Name), "loopback") ||
		   strings.Contains(strings.ToLower(iface.Name), "lo") {
			continue
		}
		
		if len(iface.Addresses) == 0 {
			continue
		}
		
		ipAddr := ""
		for _, addr := range iface.Addresses {
			if addr.IP != nil {
				ipAddr = addr.IP.String()
				break
			}
		}
		
		if ipAddr != "" {
			return iface.Name, ipAddr, nil
		}
	}
	
	for _, iface := range interfaces {
		if !strings.Contains(strings.ToLower(iface.Name), "loopback") {
			return iface.Name, "", nil
		}
	}
	
	return "", "", fmt.Errorf("uygun ağ arayüzü bulunamadı (tüm arayüzler: %d adet)", len(interfaces))
}

func GetAllInterfaces() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}
