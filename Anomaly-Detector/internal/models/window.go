package models

import (
	"container/ring"
	"math"
	"sync"
	"time"
)

type SlidingWindow struct {
	mu       sync.RWMutex
	ip       string
	samples  *ring.Ring
	size     int
	position int
}

func NewSlidingWindow(ip string, size int) *SlidingWindow {
	return &SlidingWindow{
		ip:      ip,
		samples: ring.New(size),
		size:    size,
	}
}

func (w *SlidingWindow) AddSample(sample *TrafficSample) {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	w.samples.Value = sample
	w.samples = w.samples.Next()
}

func (w *SlidingWindow) GetMetrics() *TrafficMetrics {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	var requestRates, portDiversities, synCounts, packetSizes []float64
	
	w.samples.Do(func(p interface{}) {
		if p == nil {
			return
		}
		sample, ok := p.(*TrafficSample)
		if !ok || sample == nil {
			return
		}
		
		requestRates = append(requestRates, float64(sample.RequestCount))
		portDiversities = append(portDiversities, float64(sample.UniquePortCount))
		synCounts = append(synCounts, float64(sample.SYNCount))
		packetSizes = append(packetSizes, sample.AvgPacketSize)
	})
	
	if len(requestRates) == 0 {
		return &TrafficMetrics{}
	}
	
	return &TrafficMetrics{
		RequestRateMean:   calculateMean(requestRates),
		RequestRateStd:    calculateStdDev(requestRates),
		PortDiversityMean: calculateMean(portDiversities),
		PortDiversityStd:  calculateStdDev(portDiversities),
		SYNCountMean:      calculateMean(synCounts),
		SYNCountStd:       calculateStdDev(synCounts),
		AvgPacketSizeMean: calculateMean(packetSizes),
		AvgPacketSizeStd:  calculateStdDev(packetSizes),
		SampleCount:       len(requestRates),
	}
}

func (w *SlidingWindow) GetSamples() []*TrafficSample {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	var samples []*TrafficSample
	w.samples.Do(func(p interface{}) {
		if p == nil {
			return
		}
		sample, ok := p.(*TrafficSample)
		if ok && sample != nil {
			samples = append(samples, sample)
		}
	})
	
	return samples
}

func (w *SlidingWindow) IsReady(minSamples int) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	count := 0
	w.samples.Do(func(p interface{}) {
		if p != nil {
			count++
		}
	})
	
	return count >= minSamples
}

func calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func calculateStdDev(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	
	mean := calculateMean(values)
	var sumSquaredDiffs float64
	
	for _, v := range values {
		diff := v - mean
		sumSquaredDiffs += diff * diff
	}
	
	variance := sumSquaredDiffs / float64(len(values))
	return math.Sqrt(variance)
}

func CalculateZScore(value, mean, stdDev float64) float64 {
	if stdDev == 0 {
		return 0
	}
	return (value - mean) / stdDev
}

type WindowManager struct {
	mu      sync.RWMutex
	windows map[string]*SlidingWindow
	size    int
}

func NewWindowManager(windowSize int) *WindowManager {
	return &WindowManager{
		windows: make(map[string]*SlidingWindow),
		size:    windowSize,
	}
}

func (wm *WindowManager) GetOrCreateWindow(ip string) *SlidingWindow {
	wm.mu.RLock()
	window, exists := wm.windows[ip]
	wm.mu.RUnlock()
	
	if exists {
		return window
	}
	
	wm.mu.Lock()
	defer wm.mu.Unlock()
	
	if window, exists := wm.windows[ip]; exists {
		return window
	}
	
	window = NewSlidingWindow(ip, wm.size)
	wm.windows[ip] = window
	return window
}

func (wm *WindowManager) GetWindow(ip string) (*SlidingWindow, bool) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	
	window, exists := wm.windows[ip]
	return window, exists
}

func (wm *WindowManager) RemoveWindow(ip string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	
	delete(wm.windows, ip)
}

func (wm *WindowManager) GetAllIPs() []string {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	
	ips := make([]string, 0, len(wm.windows))
	for ip := range wm.windows {
		ips = append(ips, ip)
	}
	return ips
}

func (wm *WindowManager) CleanupOldWindows(maxAge time.Duration) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	
	now := time.Now()
	for ip, window := range wm.windows {
		samples := window.GetSamples()
		if len(samples) == 0 {
			continue
		}
		
		lastSample := samples[len(samples)-1]
		if now.Sub(lastSample.Timestamp) > maxAge {
			delete(wm.windows, ip)
		}
	}
}

func (wm *WindowManager) GetWindowCount() int {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	return len(wm.windows)
}
