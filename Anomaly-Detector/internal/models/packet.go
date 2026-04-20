package models

import (
	"net"
	"time"
)

type Packet struct {
	Timestamp   time.Time     `json:"timestamp"`
	SrcIP       net.IP        `json:"src_ip"`
	DstIP       net.IP        `json:"dst_ip"`
	SrcPort     uint16        `json:"src_port,omitempty"`
	DstPort     uint16        `json:"dst_port,omitempty"`
	Protocol    string        `json:"protocol"`
	Length      int           `json:"length"`
	IsSYN       bool          `json:"is_syn"`
	IsACK       bool          `json:"is_ack"`
	PayloadHash string        `json:"payload_hash,omitempty"`
}

type TrafficSample struct {
	Timestamp      time.Time     `json:"timestamp"`
	IP             string        `json:"ip"`
	RequestCount   int           `json:"request_count"`
	UniquePorts    map[uint16]bool 
	UniquePortCount int          `json:"unique_port_count"`
	SYNCount       int           `json:"syn_count"`
	ACKCount       int           `json:"ack_count"`
	TotalBytes     int64         `json:"total_bytes"`
	AvgPacketSize  float64       `json:"avg_packet_size"`
	Protocols      map[string]int `json:"protocols"`
}

func NewTrafficSample(ip string, timestamp time.Time) *TrafficSample {
	return &TrafficSample{
		Timestamp:   timestamp,
		IP:          ip,
		UniquePorts: make(map[uint16]bool),
		Protocols:   make(map[string]int),
	}
}

func (s *TrafficSample) AddPacket(p *Packet) {
	s.RequestCount++
	s.TotalBytes += int64(p.Length)
	
	if p.DstPort > 0 {
		s.UniquePorts[p.DstPort] = true
	}
	
	if p.IsSYN && !p.IsACK {
		s.SYNCount++
	}
	
	if p.IsACK {
		s.ACKCount++
	}
	
	s.Protocols[p.Protocol]++
}

func (s *TrafficSample) Finalize() {
	s.UniquePortCount = len(s.UniquePorts)
	if s.RequestCount > 0 {
		s.AvgPacketSize = float64(s.TotalBytes) / float64(s.RequestCount)
	}
}

type TrafficMetrics struct {
	RequestRateMean     float64 `json:"request_rate_mean"`
	RequestRateStd      float64 `json:"request_rate_std"`
	PortDiversityMean   float64 `json:"port_diversity_mean"`
	PortDiversityStd    float64 `json:"port_diversity_std"`
	SYNCountMean        float64 `json:"syn_count_mean"`
	SYNCountStd         float64 `json:"syn_count_std"`
	AvgPacketSizeMean   float64 `json:"avg_packet_size_mean"`
	AvgPacketSizeStd    float64 `json:"avg_packet_size_std"`
	SampleCount         int     `json:"sample_count"`
}

type ZScoreResult struct {
	Value   float64 `json:"value"`
	Mean    float64 `json:"mean"`
	StdDev  float64 `json:"std_dev"`
	ZScore  float64 `json:"z_score"`
	IsAnomaly bool  `json:"is_anomaly"`
}

type AnomalyDetails struct {
	RequestRateZScore   *ZScoreResult `json:"request_rate_zscore,omitempty"`
	PortDiversityZScore *ZScoreResult `json:"port_diversity_zscore,omitempty"`
	SYNFloodZScore      *ZScoreResult `json:"syn_flood_zscore,omitempty"`
	PacketSizeZScore    *ZScoreResult `json:"packet_size_zscore,omitempty"`
	ContributingFactors []string      `json:"contributing_factors"`
	Severity            string        `json:"severity"`
	Confidence          float64       `json:"confidence"`
}

type AnomalyResult struct {
	Timestamp      time.Time        `json:"timestamp"`
	IP             string           `json:"ip"`
	Score          float64          `json:"score"`
	IsAnomaly      bool             `json:"is_anomaly"`
	CurrentSample  *TrafficSample   `json:"current_sample"`
	WindowMetrics  *TrafficMetrics  `json:"window_metrics"`
	Details        *AnomalyDetails  `json:"details"`
	Location       *GeoLocation     `json:"location,omitempty"`
}

type GeoLocation struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp,omitempty"`
}

type Alert struct {
	ID          string          `json:"id"`
	Timestamp   time.Time       `json:"timestamp"`
	IP          string          `json:"ip"`
	Score       float64         `json:"score"`
	Severity    string          `json:"severity"`
	Details     *AnomalyDetails `json:"details"`
	Location    *GeoLocation    `json:"location,omitempty"`
	Acknowledged bool           `json:"acknowledged"`
}

type TrafficSubmission struct {
	IP        string    `json:"ip" binding:"required"`
	Timestamp time.Time `json:"timestamp"`
	Packets   []Packet  `json:"packets" binding:"required"`
}

type AnalysisResponse struct {
	Status    string          `json:"status"`
	Timestamp time.Time       `json:"timestamp"`
	Results   []AnomalyResult `json:"results,omitempty"`
	Alerts    []Alert         `json:"alerts,omitempty"`
	Message   string          `json:"message,omitempty"`
}

type WebhookPayload struct {
	Alert     *Alert     `json:"alert"`
	Timestamp time.Time  `json:"timestamp"`
	Type      string     `json:"type"`
}

type ThresholdConfig struct {
	ZScoreThreshold     float64 `json:"z_score_threshold"`
	RequestRateWeight   float64 `json:"request_rate_weight"`
	PortScanWeight      float64 `json:"port_scan_weight"`
	SYNFloodWeight      float64 `json:"syn_flood_weight"`
	PacketSizeWeight    float64 `json:"packet_size_weight"`
	AnomalyThreshold    float64 `json:"anomaly_threshold"`
	WindowSize          int     `json:"window_size"`
}

func DefaultThresholdConfig() *ThresholdConfig {
	return &ThresholdConfig{
		ZScoreThreshold:   2.5,
		RequestRateWeight: 0.30,
		PortScanWeight:    0.30,
		SYNFloodWeight:    0.25,
		PacketSizeWeight:  0.15,
		AnomalyThreshold:  0.70,
		WindowSize:        60,
	}
}
