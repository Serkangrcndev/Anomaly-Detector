package collector

import (
	"context"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"anomaly-detector/internal/models"
)

type TrafficSimulator struct {
	packetChan   chan *models.Packet
	ctx          context.Context
	cancel       context.CancelFunc
	config       *SimulationConfig
	anomalyIPs   map[string]bool
	mu           sync.RWMutex
}

type SimulationConfig struct {
	NormalIPs           []string
	AnomalyIPs          []string
	PacketsPerSecond    int
	AnomalyProbability  float64
	AnomalyDuration     time.Duration
	SimulationDuration  time.Duration
}

func DefaultSimulationConfig() *SimulationConfig {
	return &SimulationConfig{
		NormalIPs: []string{
			"192.168.1.100",
			"192.168.1.101",
			"192.168.1.102",
			"192.168.1.103",
			"10.0.0.50",
			"10.0.0.51",
		},
		AnomalyIPs: []string{
			"192.168.1.200",
			"10.0.0.99",
			"172.16.0.50",
		},
		PacketsPerSecond:   100,
		AnomalyProbability: 0.05,
		AnomalyDuration:    30 * time.Second,
		SimulationDuration: 0,
	}
}

func NewTrafficSimulator(config *SimulationConfig) *TrafficSimulator {
	if config == nil {
		config = DefaultSimulationConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &TrafficSimulator{
		packetChan: make(chan *models.Packet, 1000),
		ctx:        ctx,
		cancel:     cancel,
		config:     config,
		anomalyIPs: make(map[string]bool),
	}
}

func (ts *TrafficSimulator) Start() error {
	log.Println("[Simulator] Starting traffic simulation")
	log.Printf("[Simulator] Normal IPs: %d, Anomaly IPs: %d",
		len(ts.config.NormalIPs), len(ts.config.AnomalyIPs))
	
	for _, ip := range ts.config.NormalIPs {
		go ts.simulateNormalTraffic(ip)
	}
	
	for _, ip := range ts.config.AnomalyIPs {
		go ts.simulateAnomalyTraffic(ip)
	}
	
	go ts.anomalyTrigger()
	
	if ts.config.SimulationDuration > 0 {
		go func() {
			time.Sleep(ts.config.SimulationDuration)
			ts.Stop()
		}()
	}
	
	return nil
}

func (ts *TrafficSimulator) Stop() {
	log.Println("[Simulator] Stopping traffic simulation")
	ts.cancel()
	close(ts.packetChan)
}

func (ts *TrafficSimulator) GetPacketChannel() <-chan *models.Packet {
	return ts.packetChan
}

func (ts *TrafficSimulator) simulateNormalTraffic(ip string) {
	ticker := time.NewTicker(time.Second / time.Duration(ts.config.PacketsPerSecond/len(ts.config.NormalIPs)))
	defer ticker.Stop()
	
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	
	for {
		select {
		case <-ts.ctx.Done():
			return
		case <-ticker.C:
			packet := ts.generateNormalPacket(ip, rng)
			select {
			case ts.packetChan <- packet:
			case <-ts.ctx.Done():
				return
			}
		}
	}
}

func (ts *TrafficSimulator) simulateAnomalyTraffic(ip string) {
	baseTicker := time.NewTicker(time.Second / time.Duration(ts.config.PacketsPerSecond/len(ts.config.AnomalyIPs)))
	defer baseTicker.Stop()
	
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	
	for {
		select {
		case <-ts.ctx.Done():
			return
		case <-baseTicker.C:
			packet := ts.generateNormalPacket(ip, rng)
			
			ts.mu.RLock()
			isAnomaly := ts.anomalyIPs[ip]
			ts.mu.RUnlock()
			
			if isAnomaly {
				packet = ts.generateAnomalyPacket(ip, rng)
			}
			
			select {
			case ts.packetChan <- packet:
			case <-ts.ctx.Done():
				return
			}
		}
	}
}

func (ts *TrafficSimulator) anomalyTrigger() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ts.ctx.Done():
			return
		case <-ticker.C:
			if rng.Float64() < ts.config.AnomalyProbability {
				ts.triggerRandomAnomaly(rng)
			}
		}
	}
}

func (ts *TrafficSimulator) triggerRandomAnomaly(rng *rand.Rand) {
	if len(ts.config.AnomalyIPs) == 0 {
		return
	}
	
	ip := ts.config.AnomalyIPs[rng.Intn(len(ts.config.AnomalyIPs))]
	
	ts.mu.Lock()
	ts.anomalyIPs[ip] = true
	ts.mu.Unlock()
	
	log.Printf("[Simulator] ANOMALY TRIGGERED for IP: %s (duration: %v)",
		ip, ts.config.AnomalyDuration)
	
	go func() {
		time.Sleep(ts.config.AnomalyDuration)
		ts.mu.Lock()
		delete(ts.anomalyIPs, ip)
		ts.mu.Unlock()
		log.Printf("[Simulator] Anomaly ended for IP: %s", ip)
	}()
}

func (ts *TrafficSimulator) generateNormalPacket(ip string, rng *rand.Rand) *models.Packet {
	commonPorts := []uint16{80, 443, 53, 22, 25, 110, 143, 993, 995, 8080}
	
	return &models.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP(ip),
		DstIP:     net.ParseIP("10.0.0.1"),
		SrcPort:   uint16(10000 + rng.Intn(50000)),
		DstPort:   commonPorts[rng.Intn(len(commonPorts))],
		Protocol:  "TCP",
		Length:    500 + rng.Intn(1000),
		IsSYN:     rng.Float64() < 0.1,
		IsACK:     rng.Float64() < 0.8,
	}
}

func (ts *TrafficSimulator) generateAnomalyPacket(ip string, rng *rand.Rand) *models.Packet {
	anomalyType := rng.Intn(4)
	
	switch anomalyType {
	case 0:
		return &models.Packet{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP(ip),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   uint16(10000 + rng.Intn(50000)),
			DstPort:   uint16(1 + rng.Intn(65535)),
			Protocol:  "TCP",
			Length:    40 + rng.Intn(100),
			IsSYN:     true,
			IsACK:     false,
		}
		
	case 1:
		return &models.Packet{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP(ip),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   uint16(10000 + rng.Intn(50000)),
			DstPort:   80,
			Protocol:  "TCP",
			Length:    60,
			IsSYN:     true,
			IsACK:     false,
		}
		
	case 2:
		return &models.Packet{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP(ip),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   uint16(10000 + rng.Intn(50000)),
			DstPort:   443,
			Protocol:  "TCP",
			Length:    1400 + rng.Intn(200),
			IsSYN:     false,
			IsACK:     true,
		}
		
	case 3:
		return &models.Packet{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP(ip),
			DstIP:     net.ParseIP("10.0.0.1"),
			SrcPort:   uint16(10000 + rng.Intn(50000)),
			DstPort:   uint16(1 + rng.Intn(65535)),
			Protocol:  "UDP",
			Length:    28 + rng.Intn(50),
			IsSYN:     false,
			IsACK:     false,
		}
	}
	
	return ts.generateNormalPacket(ip, rng)
}

func (ts *TrafficSimulator) GetActiveAnomalies() []string {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	
	ips := make([]string, 0, len(ts.anomalyIPs))
	for ip := range ts.anomalyIPs {
		ips = append(ips, ip)
	}
	return ips
}
