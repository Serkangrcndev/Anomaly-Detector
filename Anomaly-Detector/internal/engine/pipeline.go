package engine

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"anomaly-detector/internal/analyzer"
	"anomaly-detector/internal/collector"
	"anomaly-detector/internal/extractor"
	"anomaly-detector/internal/models"
	"anomaly-detector/internal/services"
	"anomaly-detector/pkg/utils"
)

type DetectionEngine struct {
	ctx              context.Context
	cancel           context.CancelFunc
	
	collector        Collector
	aggregator       *extractor.TrafficAggregator
	detector         *analyzer.AnomalyDetector
	geoIPService     *services.GeoIPService
	
	packetChan       chan *models.Packet
	sampleChan       <-chan *models.TrafficSample
	resultChan       chan *models.AnomalyResult
	
	running          bool
	mu               sync.RWMutex
	results          []*models.AnomalyResult
	maxResults       int
}

type Collector interface {
	Start() error
	Stop()
	GetPacketChannel() <-chan *models.Packet
}

type EngineConfig struct {
	Interface       string
	BPFFilter       string
	AggregationInterval time.Duration
	ThresholdConfig *models.ThresholdConfig
	GeoIPDBPath     string
	MaxResults      int
}

func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		AggregationInterval: 1 * time.Second,
		ThresholdConfig:     models.DefaultThresholdConfig(),
		MaxResults:          1000,
	}
}

func NewDetectionEngine(config *EngineConfig) (*DetectionEngine, error) {
	if config == nil {
		config = DefaultEngineConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	engine := &DetectionEngine{
		ctx:        ctx,
		cancel:     cancel,
		packetChan: make(chan *models.Packet, 1000),
		resultChan: make(chan *models.AnomalyResult, 100),
		results:    make([]*models.AnomalyResult, 0),
		maxResults: config.MaxResults,
	}
	
	var err error
	err = engine.initLiveCollector(config.Interface, config.BPFFilter)
	
	if err != nil {
		return nil, err
	}
	
	engine.aggregator = extractor.NewTrafficAggregator(engine.packetChan, config.AggregationInterval)
	engine.sampleChan = engine.aggregator.GetOutputChannel()
	
	engine.detector = analyzer.NewAnomalyDetector(config.ThresholdConfig)
	
	if config.GeoIPDBPath != "" {
		engine.geoIPService, err = services.NewGeoIPService(config.GeoIPDBPath)
		if err != nil {
			utils.PrintWarning("[Motor] GeoIP servisi başlatılamadı: %v", err)
			engine.geoIPService = services.NewGeoIPServiceMock()
		}
	} else {
		engine.geoIPService = services.NewGeoIPServiceMock()
	}
	
	return engine, nil
}

func (e *DetectionEngine) initLiveCollector(iface, bpfFilter string) error {
	if iface == "" {
		defaultIface, ipAddr, err := collector.FindDefaultInterface()
		if err != nil {
			return fmt.Errorf("ağ arayüzü bulunamadı: %w", err)
		}
		iface = defaultIface
		utils.PrintSuccess("🌐 Ağ arayüzü otomatik tespit edildi: %s (%s)", iface, ipAddr)
	} else {
		utils.PrintInfo("🌐 Ağ arayüzü manuel seçildi: %s", iface)
	}
	
	pcapCollector, err := collector.NewPacketCapture(iface, bpfFilter)
	if err != nil {
		return fmt.Errorf("paket yakalayıcı başlatılamadı: %w", err)
	}
	
	e.collector = pcapCollector
	
	go func() {
		for packet := range pcapCollector.GetPacketChannel() {
			select {
			case e.packetChan <- packet:
			case <-e.ctx.Done():
				return
			}
		}
	}()
	
	return nil
}


func (e *DetectionEngine) Start() {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	e.mu.Unlock()
	
	fmt.Println(utils.Cyan + "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓" + utils.Reset)
	fmt.Println(utils.Cyan + "┃" + utils.Magenta + " TESPİT MOTORU BAŞLATILIYOR" + utils.Cyan + "┃" + utils.Reset)
	fmt.Println(utils.Cyan + "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛" + utils.Reset)
	
	if e.collector != nil {
		utils.PrintInfo("[Motor] Paket yakalayıcı başlatılıyor...")
		if err := e.collector.Start(); err != nil {
			utils.PrintError("[Motor] Yakalayıcı başlatılamadı: %v", err)
			return
		}
		utils.PrintSuccess("[Motor] Ağ paketleri canlı olarak izleniyor")
	}
	
	e.aggregator.Start()
	utils.PrintSuccess("[Motor] Trafik toplayıcı çalışıyor")
	
	go e.processSamples()
	
	go e.processResults()
	
	go e.maintenanceRoutine()
	
	utils.PrintSuccess("[Motor] Anomali tespiti aktif - Ağınız izleniyor")
	
	e.waitForShutdown()
}

func (e *DetectionEngine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	if !e.running {
		return
	}
	
	e.running = false
	e.cancel()
	
	utils.PrintWarning("[Motor] Sistem kapatılıyor...")
	
	e.aggregator.Stop()
	
	if e.collector != nil {
		e.collector.Stop()
	}
	
	if e.geoIPService != nil {
		e.geoIPService.Close()
	}
	
	close(e.packetChan)
	close(e.resultChan)
	
	utils.PrintSuccess("[Motor] Sistem durduruldu")
}

func (e *DetectionEngine) processSamples() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case sample, ok := <-e.sampleChan:
			if !ok {
				return
			}
			
			result := e.detector.ProcessSample(sample)
			
			if e.geoIPService != nil {
				location, err := e.geoIPService.LookupIP(sample.IP)
				if err == nil {
					result.Location = location
				}
			}
			
			select {
			case e.resultChan <- result:
			case <-e.ctx.Done():
				return
			}
		}
	}
}

func (e *DetectionEngine) processResults() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case result, ok := <-e.resultChan:
			if !ok {
				return
			}
			
			e.mu.Lock()
			e.results = append(e.results, result)
			
			if len(e.results) > e.maxResults {
				e.results = e.results[len(e.results)-e.maxResults:]
			}
			e.mu.Unlock()
			
			if result.IsAnomaly {
				severityColor := utils.Yellow
				if result.Details.Severity == "HIGH" {
					severityColor = utils.Red
				}
				
				fmt.Printf("\n"+utils.Red+"🚨 ANOMALİ TESPİT EDİLDİ "+utils.Gray+"[%s]"+utils.Reset+"\n",
					result.Timestamp.Format("15:04:05"))
				fmt.Printf(utils.Cyan+"   Hedef IP: "+utils.White+"%s"+utils.Reset+"\n", result.IP)
				fmt.Printf(utils.Cyan+"   Skor: "+severityColor+"%.2f"+utils.White+"/1.00"+utils.Reset+" | "+
					utils.Cyan+"Ciddiyet: "+severityColor+"%s"+utils.Reset+"\n\n",
					result.Score, result.Details.Severity)
				
				fmt.Println(analyzer.GenerateSummary(result))
			}
		}
	}
}

func (e *DetectionEngine) maintenanceRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.detector.GetWindowManager().CleanupOldWindows(5 * time.Minute)
		}
	}
}

func (e *DetectionEngine) waitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	<-sigChan
	fmt.Println(utils.Yellow + "\n[Engine] Shutdown signal received" + utils.Reset)
	e.Stop()
}

func (e *DetectionEngine) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

func (e *DetectionEngine) GetDetector() *analyzer.AnomalyDetector {
	return e.detector
}

func (e *DetectionEngine) GetGeoIPService() *services.GeoIPService {
	return e.geoIPService
}

func (e *DetectionEngine) GetRecentResults(limit int) []*models.AnomalyResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	if limit <= 0 || limit > len(e.results) {
		limit = len(e.results)
	}
	
	start := len(e.results) - limit
	if start < 0 {
		start = 0
	}
	
	results := make([]*models.AnomalyResult, limit)
	copy(results, e.results[start:])
	
	return results
}

func (e *DetectionEngine) SubmitTrafficSample(sample *models.TrafficSample) *models.AnomalyResult {
	if sample == nil {
		return nil
	}
	
	result := e.detector.ProcessSample(sample)
	
	if e.geoIPService != nil {
		location, err := e.geoIPService.LookupIP(sample.IP)
		if err == nil {
			result.Location = location
		}
	}
	
	e.mu.Lock()
	e.results = append(e.results, result)
	if len(e.results) > e.maxResults {
		e.results = e.results[len(e.results)-e.maxResults:]
	}
	e.mu.Unlock()
	
	if result.IsAnomaly {
		log.Printf("[ALERT] Anomaly detected from %s (Score: %.2f)",
			result.IP, result.Score)
		log.Println(analyzer.GenerateSummary(result))
	}
	
	return result
}

