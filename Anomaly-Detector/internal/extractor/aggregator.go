package extractor

import (
	"context"
	"log"
	"sync"
	"time"

	"anomaly-detector/internal/models"
)

type TrafficAggregator struct {
	ctx           context.Context
	cancel        context.CancelFunc
	inputChan     <-chan *models.Packet
	outputChan    chan *models.TrafficSample
	buffer        map[string]*models.TrafficSample
	bufferMu      sync.RWMutex
	interval      time.Duration
	ticker        *time.Ticker
}

func NewTrafficAggregator(inputChan <-chan *models.Packet, interval time.Duration) *TrafficAggregator {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &TrafficAggregator{
		ctx:        ctx,
		cancel:     cancel,
		inputChan:  inputChan,
		outputChan: make(chan *models.TrafficSample, 100),
		buffer:     make(map[string]*models.TrafficSample),
		interval:   interval,
		ticker:     time.NewTicker(interval),
	}
}

func (ta *TrafficAggregator) Start() {
	log.Printf("[Aggregator] Starting traffic aggregation (interval: %v)", ta.interval)
	
	go ta.processPackets()
	
	go ta.periodicFlush()
}

func (ta *TrafficAggregator) Stop() {
	log.Println("[Aggregator] Stopping traffic aggregation")
	ta.cancel()
	ta.ticker.Stop()
	
	ta.flushAll()
	
	close(ta.outputChan)
}

func (ta *TrafficAggregator) GetOutputChannel() <-chan *models.TrafficSample {
	return ta.outputChan
}

func (ta *TrafficAggregator) processPackets() {
	for {
		select {
		case <-ta.ctx.Done():
			return
		case packet, ok := <-ta.inputChan:
			if !ok {
				return
			}
			ta.addPacket(packet)
		}
	}
}

func (ta *TrafficAggregator) addPacket(packet *models.Packet) {
	if packet == nil || packet.SrcIP == nil {
		return
	}
	
	ip := packet.SrcIP.String()
	now := time.Now()
	timestamp := now.Truncate(ta.interval)
	
	ta.bufferMu.Lock()
	defer ta.bufferMu.Unlock()
	
	sample, exists := ta.buffer[ip]
	if !exists || sample.Timestamp != timestamp {
		if exists && sample.Timestamp != timestamp {
			ta.finalizeAndSend(sample)
		}
		
		sample = models.NewTrafficSample(ip, timestamp)
		ta.buffer[ip] = sample
	}
	
	sample.AddPacket(packet)
}

func (ta *TrafficAggregator) periodicFlush() {
	for {
		select {
		case <-ta.ctx.Done():
			return
		case <-ta.ticker.C:
			ta.flushCompletedIntervals()
		}
	}
}

func (ta *TrafficAggregator) flushCompletedIntervals() {
	now := time.Now()
	currentInterval := now.Truncate(ta.interval)
	
	ta.bufferMu.Lock()
	defer ta.bufferMu.Unlock()
	
	for ip, sample := range ta.buffer {
		if sample.Timestamp.Before(currentInterval) {
			ta.finalizeAndSend(sample)
			delete(ta.buffer, ip)
		}
	}
}

func (ta *TrafficAggregator) flushAll() {
	ta.bufferMu.Lock()
	defer ta.bufferMu.Unlock()
	
	for _, sample := range ta.buffer {
		ta.finalizeAndSend(sample)
	}
}

func (ta *TrafficAggregator) finalizeAndSend(sample *models.TrafficSample) {
	sample.Finalize()
	
	select {
	case ta.outputChan <- sample:
	case <-time.After(100 * time.Millisecond):
		log.Printf("[Aggregator] Warning: Output channel full, dropping sample for %s", sample.IP)
	case <-ta.ctx.Done():
		return
	}
}

func (ta *TrafficAggregator) GetStats() (bufferSize int, oldestSample time.Time) {
	ta.bufferMu.RLock()
	defer ta.bufferMu.RUnlock()
	
	bufferSize = len(ta.buffer)
	
	now := time.Now()
	oldestSample = now
	
	for _, sample := range ta.buffer {
		if sample.Timestamp.Before(oldestSample) {
			oldestSample = sample.Timestamp
		}
	}
	
	return bufferSize, oldestSample
}

type MultiIPAggregator struct {
	aggregators map[string]*TrafficAggregator
	mu          sync.RWMutex
	interval    time.Duration
	outputChan  chan *models.TrafficSample
}

func NewMultiIPAggregator(interval time.Duration) *MultiIPAggregator {
	return &MultiIPAggregator{
		aggregators: make(map[string]*TrafficAggregator),
		interval:    interval,
		outputChan:  make(chan *models.TrafficSample, 100),
	}
}

func (mia *MultiIPAggregator) RegisterIP(ip string, inputChan <-chan *models.Packet) {
	mia.mu.Lock()
	defer mia.mu.Unlock()
	
	if _, exists := mia.aggregators[ip]; exists {
		return
	}
	
	agg := NewTrafficAggregator(inputChan, mia.interval)
	mia.aggregators[ip] = agg
	
	go mia.forwardSamples(agg)
	agg.Start()
}

func (mia *MultiIPAggregator) forwardSamples(agg *TrafficAggregator) {
	for sample := range agg.GetOutputChannel() {
		select {
		case mia.outputChan <- sample:
		default:
		}
	}
}

func (mia *MultiIPAggregator) GetOutputChannel() <-chan *models.TrafficSample {
	return mia.outputChan
}

func (mia *MultiIPAggregator) StopAll() {
	mia.mu.Lock()
	defer mia.mu.Unlock()
	
	for _, agg := range mia.aggregators {
		agg.Stop()
	}
	
	close(mia.outputChan)
}
