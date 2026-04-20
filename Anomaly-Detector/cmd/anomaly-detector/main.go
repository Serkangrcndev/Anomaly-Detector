package main

import (
	"flag"
	"log"

	"anomaly-detector/internal/engine"
	"anomaly-detector/internal/models"
	"anomaly-detector/pkg/utils"
)

func main() {
	var (
		interfaceName = flag.String("iface", "", "Network interface (auto-detect if empty)")
		bpfFilter     = flag.String("filter", "", "BPF filter for packet capture")
		geoIPDB       = flag.String("geoip", "", "Path to GeoIP database")
		windowSize    = flag.Int("window", 60, "Sliding window size in seconds")
		threshold     = flag.Float64("threshold", 0.7, "Anomaly detection threshold (0.0-1.0)")
	)
	flag.Parse()

	utils.PrintBanner("🔒  NETWORK ANOMALY DETECTION SYSTEM  🔒", "Real-time Network Traffic Monitoring & Anomaly Detection")
	
	if *interfaceName == "" {
		utils.PrintInfo("🌐 Ağ arayüzü otomatik tespit ediliyor...")
	}
	utils.PrintInfo("Gerçek ağ trafiği izleniyor | Eşik: %.1f", *threshold)

	config := &engine.EngineConfig{
		Interface:           *interfaceName,
		BPFFilter:           *bpfFilter,
		AggregationInterval: 1 * time.Second,
		ThresholdConfig:     nil,
		GeoIPDBPath:         *geoIPDB,
		MaxResults:          1000,
	}

	if *threshold > 0 {
		config.ThresholdConfig = &models.ThresholdConfig{
			ZScoreThreshold:     2.5,
			RequestRateWeight:   0.30,
			PortScanWeight:      0.30,
			SYNFloodWeight:      0.25,
			PacketSizeWeight:    0.15,
			AnomalyThreshold:    *threshold,
			WindowSize:          *windowSize,
		}
	}

	detectionEngine, err := engine.NewDetectionEngine(config)
	if err != nil {
		log.Fatalf("Failed to create detection engine: %v", err)
	}

	detectionEngine.Start()
}
