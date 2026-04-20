package analyzer

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"anomaly-detector/internal/models"
)

type AnomalyDetector struct {
	windowManager    *models.WindowManager
	thresholdConfig  *models.ThresholdConfig
	results          map[string]*models.AnomalyResult
	resultsMu        sync.RWMutex
	historySize      int
}

func NewAnomalyDetector(config *models.ThresholdConfig) *AnomalyDetector {
	if config == nil {
		config = models.DefaultThresholdConfig()
	}
	
	return &AnomalyDetector{
		windowManager:   models.NewWindowManager(config.WindowSize),
		thresholdConfig: config,
		results:         make(map[string]*models.AnomalyResult),
		historySize:     100,
	}
}

func (ad *AnomalyDetector) ProcessSample(sample *models.TrafficSample) *models.AnomalyResult {
	if sample == nil {
		return nil
	}
	
	window := ad.windowManager.GetOrCreateWindow(sample.IP)
	
	window.AddSample(sample)
	
	metrics := window.GetMetrics()
	
	result := ad.detectAnomaly(sample, metrics)
	
	ad.resultsMu.Lock()
	ad.results[sample.IP] = result
	ad.resultsMu.Unlock()
	
	return result
}

func (ad *AnomalyDetector) detectAnomaly(sample *models.TrafficSample, metrics *models.TrafficMetrics) *models.AnomalyResult {
	result := &models.AnomalyResult{
		Timestamp:     time.Now(),
		IP:            sample.IP,
		CurrentSample: sample,
		WindowMetrics: metrics,
		Details:       &models.AnomalyDetails{
			ContributingFactors: []string{},
		},
	}
	
	if metrics.SampleCount < 10 {
		result.IsAnomaly = false
		result.Score = 0
		result.Details.ContributingFactors = append(result.Details.ContributingFactors,
			"Insufficient data for anomaly detection (need at least 10 samples)")
		return result
	}
	
	totalScore := 0.0
	
	requestRateValue := float64(sample.RequestCount)
	requestRateZScore := models.CalculateZScore(requestRateValue, metrics.RequestRateMean, metrics.RequestRateStd)
	requestRateAnomaly := math.Abs(requestRateZScore) > ad.thresholdConfig.ZScoreThreshold
	
	result.Details.RequestRateZScore = &models.ZScoreResult{
		Value:     requestRateValue,
		Mean:      metrics.RequestRateMean,
		StdDev:    metrics.RequestRateStd,
		ZScore:    requestRateZScore,
		IsAnomaly: requestRateAnomaly,
	}
	
	if requestRateAnomaly {
		totalScore += ad.thresholdConfig.RequestRateWeight
		factor := fmt.Sprintf("Abnormal request rate: %.0f requests/sec (Z-score: %.2f, threshold: %.1f)",
			requestRateValue, requestRateZScore, ad.thresholdConfig.ZScoreThreshold)
		result.Details.ContributingFactors = append(result.Details.ContributingFactors, factor)
	}
	
	portDiversityValue := float64(sample.UniquePortCount)
	portDiversityZScore := models.CalculateZScore(portDiversityValue, metrics.PortDiversityMean, metrics.PortDiversityStd)
	portScanAnomaly := portDiversityZScore > ad.thresholdConfig.ZScoreThreshold
	
	result.Details.PortDiversityZScore = &models.ZScoreResult{
		Value:     portDiversityValue,
		Mean:      metrics.PortDiversityMean,
		StdDev:    metrics.PortDiversityStd,
		ZScore:    portDiversityZScore,
		IsAnomaly: portScanAnomaly,
	}
	
	if portScanAnomaly {
		totalScore += ad.thresholdConfig.PortScanWeight
		factor := fmt.Sprintf("Potential port scan: %d unique ports (Z-score: %.2f, threshold: %.1f)",
			sample.UniquePortCount, portDiversityZScore, ad.thresholdConfig.ZScoreThreshold)
		result.Details.ContributingFactors = append(result.Details.ContributingFactors, factor)
	}
	
	synCountValue := float64(sample.SYNCount)
	synCountZScore := models.CalculateZScore(synCountValue, metrics.SYNCountMean, metrics.SYNCountStd)
	synFloodAnomaly := synCountZScore > ad.thresholdConfig.ZScoreThreshold && sample.SYNCount > 5
	
	result.Details.SYNFloodZScore = &models.ZScoreResult{
		Value:     synCountValue,
		Mean:      metrics.SYNCountMean,
		StdDev:    metrics.SYNCountStd,
		ZScore:    synCountZScore,
		IsAnomaly: synFloodAnomaly,
	}
	
	if synFloodAnomaly {
		totalScore += ad.thresholdConfig.SYNFloodWeight
		factor := fmt.Sprintf("SYN flood indicators: %d SYN packets (Z-score: %.2f, threshold: %.1f)",
			sample.SYNCount, synCountZScore, ad.thresholdConfig.ZScoreThreshold)
		result.Details.ContributingFactors = append(result.Details.ContributingFactors, factor)
	}
	
	packetSizeValue := sample.AvgPacketSize
	packetSizeZScore := models.CalculateZScore(packetSizeValue, metrics.AvgPacketSizeMean, metrics.AvgPacketSizeStd)
	packetSizeAnomaly := math.Abs(packetSizeZScore) > ad.thresholdConfig.ZScoreThreshold
	
	result.Details.PacketSizeZScore = &models.ZScoreResult{
		Value:     packetSizeValue,
		Mean:      metrics.AvgPacketSizeMean,
		StdDev:    metrics.AvgPacketSizeStd,
		ZScore:    packetSizeZScore,
		IsAnomaly: packetSizeAnomaly,
	}
	
	if packetSizeAnomaly {
		totalScore += ad.thresholdConfig.PacketSizeWeight
		direction := "high"
		if packetSizeZScore < 0 {
			direction = "low"
		}
		factor := fmt.Sprintf("Abnormal packet size: %s average (%.0f bytes, Z-score: %.2f)",
			direction, packetSizeValue, packetSizeZScore)
		result.Details.ContributingFactors = append(result.Details.ContributingFactors, factor)
	}
	
	result.Score = totalScore
	result.IsAnomaly = totalScore >= ad.thresholdConfig.AnomalyThreshold
	
	if result.IsAnomaly {
		switch {
		case totalScore >= 0.9:
			result.Details.Severity = "CRITICAL"
		case totalScore >= 0.8:
			result.Details.Severity = "HIGH"
		case totalScore >= 0.7:
			result.Details.Severity = "MEDIUM"
		default:
			result.Details.Severity = "LOW"
		}
		
		result.Details.Confidence = math.Min(0.5+(float64(len(result.Details.ContributingFactors))*0.15), 0.95)
	} else {
		result.Details.Severity = "NONE"
		result.Details.Confidence = 0
		
		if len(result.Details.ContributingFactors) == 0 {
			result.Details.ContributingFactors = append(result.Details.ContributingFactors,
				"Traffic patterns within normal parameters")
		}
	}
	
	return result
}

func (ad *AnomalyDetector) GetResult(ip string) (*models.AnomalyResult, bool) {
	ad.resultsMu.RLock()
	defer ad.resultsMu.RUnlock()
	
	result, exists := ad.results[ip]
	return result, exists
}

func (ad *AnomalyDetector) GetAllResults() []*models.AnomalyResult {
	ad.resultsMu.RLock()
	defer ad.resultsMu.RUnlock()
	
	results := make([]*models.AnomalyResult, 0, len(ad.results))
	for _, result := range ad.results {
		results = append(results, result)
	}
	
	return results
}

func (ad *AnomalyDetector) GetAnomalies() []*models.AnomalyResult {
	ad.resultsMu.RLock()
	defer ad.resultsMu.RUnlock()
	
	anomalies := make([]*models.AnomalyResult, 0)
	for _, result := range ad.results {
		if result.IsAnomaly {
			anomalies = append(anomalies, result)
		}
	}
	
	return anomalies
}

func (ad *AnomalyDetector) GetWindowStats() (totalWindows int, totalSamples int) {
	ips := ad.windowManager.GetAllIPs()
	totalWindows = len(ips)
	
	for _, ip := range ips {
		if window, ok := ad.windowManager.GetWindow(ip); ok {
			samples := window.GetSamples()
			totalSamples += len(samples)
		}
	}
	
	return totalWindows, totalSamples
}

func (ad *AnomalyDetector) ResetIP(ip string) {
	ad.windowManager.RemoveWindow(ip)
	
	ad.resultsMu.Lock()
	delete(ad.results, ip)
	ad.resultsMu.Unlock()
}

func (ad *AnomalyDetector) UpdateThresholds(config *models.ThresholdConfig) {
	if config == nil {
		return
	}
	
	ad.thresholdConfig = config
}

func (ad *AnomalyDetector) GetThresholds() *models.ThresholdConfig {
	return ad.thresholdConfig
}

func (ad *AnomalyDetector) GetWindowManager() *models.WindowManager {
	return ad.windowManager
}

const (
	Reset   = "\033[0m"
	Red     = "\033[1;31m"
	Green   = "\033[1;32m"
	Yellow  = "\033[1;33m"
	Blue    = "\033[1;34m"
	Magenta = "\033[1;35m"
	Cyan    = "\033[1;36m"
	White   = "\033[1;37m"
	Gray    = "\033[90m"
	Orange  = "\033[38;5;208m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
)

func GenerateSummary(result *models.AnomalyResult) string {
	if result == nil {
		return Gray + "No analysis result available" + Reset
	}
	
	var sb strings.Builder
	
	sb.WriteString(Cyan + "\n┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n" + Reset)
	sb.WriteString(Cyan + "┃" + Reset + Magenta + "  🔒  NETWORK ANOMALY DETECTION SYSTEM  🔒" + Cyan + "                    ┃\n" + Reset)
	sb.WriteString(Cyan + "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n" + Reset)
	
	statusColor := Green
	statusIcon := "✓"
	if result.IsAnomaly {
		statusColor = Red
		statusIcon = "⚠"
	}
	
	sb.WriteString(fmt.Sprintf("\n"+Blue+"┌─ "+White+"Target Information"+Blue+" ─────────────────────────────────────┐\n"+Reset))
	sb.WriteString(fmt.Sprintf("│  "+Cyan+"🌐 IP Address:     "+White+"%-40s"+Blue+"│\n"+Reset, result.IP))
	sb.WriteString(fmt.Sprintf("│  "+Cyan+"🕐 Time:           "+Gray+"%-40s"+Blue+"│\n"+Reset, result.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("│  "+Cyan+"📊 Anomaly Score:  "+statusColor+"%.2f/1.00"+White+" %-31s"+Blue+"│\n"+Reset, 
		result.Score, getScoreBar(result.Score)))
	sb.WriteString(fmt.Sprintf("│  "+Cyan+"🔍 Status:         "+statusColor+"%s %s"+White+" %-27s"+Blue+"│\n"+Reset,
		statusIcon, getStatusString(result.IsAnomaly), ""))
	
	if result.IsAnomaly {
		severityColor := Yellow
		if result.Details.Severity == "HIGH" {
			severityColor = Red
		}
		sb.WriteString(fmt.Sprintf("│  "+Cyan+"⚡ Severity:       "+severityColor+"%-40s"+Blue+"│\n"+Reset, result.Details.Severity))
		sb.WriteString(fmt.Sprintf("│  "+Cyan+"🎯 Confidence:     "+White+"%.1f%% %-35s"+Blue+"│\n"+Reset, 
			result.Details.Confidence*100, getConfidenceBar(result.Details.Confidence)))
	}
	sb.WriteString(fmt.Sprintf(Blue+"└──────────────────────────────────────────────────────────────┘\n"+Reset))
	
	sb.WriteString(fmt.Sprintf("\n"+Yellow+"┌─ "+White+"Traffic Metrics"+Yellow+" ─────────────────────────────────────────┐\n"+Reset))
	sb.WriteString(fmt.Sprintf("│  "+Green+"📈 Requests:       "+White+"%-4d"+Gray+" req/sec"+Yellow+"%-31s"+"│\n"+Reset, 
		result.CurrentSample.RequestCount, ""))
	sb.WriteString(fmt.Sprintf("│  "+Green+"🚪 Ports:          "+White+"%-4d"+Gray+" unique"+Yellow+"%-32s"+"│\n"+Reset, 
		result.CurrentSample.UniquePortCount, ""))
	sb.WriteString(fmt.Sprintf("│  "+Green+"📦 SYN Packets:    "+White+"%-4d"+Gray+" packets"+Yellow+"%-30s"+"│\n"+Reset, 
		result.CurrentSample.SYNCount, ""))
	sb.WriteString(fmt.Sprintf("│  "+Green+"📊 Avg Packet:     "+White+"%.0f"+Gray+" bytes"+Yellow+"%-33s"+"│\n"+Reset, 
		result.CurrentSample.AvgPacketSize, ""))
	sb.WriteString(fmt.Sprintf("│  "+Green+"💾 Total Data:     "+White+"%-6d"+Gray+" bytes"+Yellow+"%-29s"+"│\n"+Reset, 
		result.CurrentSample.TotalBytes, ""))
	sb.WriteString(fmt.Sprintf(Yellow+"└──────────────────────────────────────────────────────────────┘\n"+Reset))
	
	if result.IsAnomaly {
		sb.WriteString(fmt.Sprintf("\n"+Red+"┌─ "+White+"🚨 Statistical Analysis (Z-Scores)"+Red+" ───────────────────┐\n"+Reset))
		
		if result.Details.RequestRateZScore != nil {
			sb.WriteString(formatZScoreColored("Request Rate", result.Details.RequestRateZScore))
		}
		if result.Details.PortDiversityZScore != nil {
			sb.WriteString(formatZScoreColored("Port Diversity", result.Details.PortDiversityZScore))
		}
		if result.Details.SYNFloodZScore != nil {
			sb.WriteString(formatZScoreColored("SYN Count", result.Details.SYNFloodZScore))
		}
		if result.Details.PacketSizeZScore != nil {
			sb.WriteString(formatZScoreColored("Packet Size", result.Details.PacketSizeZScore))
		}
		sb.WriteString(fmt.Sprintf(Red+"└──────────────────────────────────────────────────────────────┘\n"+Reset))
		
			sb.WriteString(fmt.Sprintf("\n"+Orange+"┌─ "+White+"⚠️  Threat Analysis"+Orange+" ────────────────────────────────────┐\n"+Reset))
		for i, factor := range result.Details.ContributingFactors {
			sb.WriteString(fmt.Sprintf("│  "+Red+"%d. "+White+"%-56s"+Orange+"│\n"+Reset, i+1, factor))
		}
		sb.WriteString(fmt.Sprintf(Orange+"└──────────────────────────────────────────────────────────────┘\n"+Reset))
	}
	
	sb.WriteString("\n" + Gray + Dim + "─" + strings.Repeat("─", 62) + Reset + "\n")
	
	return sb.String()
}

func getScoreBar(score float64) string {
	filled := int(score * 20)
	if filled > 20 {
		filled = 20
	}
	empty := 20 - filled
	bar := Green + strings.Repeat("█", filled) + Reset + Gray + strings.Repeat("░", empty) + Reset
	return "[" + bar + "]"
}

func getConfidenceBar(confidence float64) string {
	filled := int(confidence * 20)
	if filled > 20 {
		filled = 20
	}
	empty := 20 - filled
	bar := Cyan + strings.Repeat("█", filled) + Reset + Gray + strings.Repeat("░", empty) + Reset
	return "[" + bar + "]"
}

func formatZScoreColored(name string, zs *models.ZScoreResult) string {
	statusIcon := Green + "✓" + Reset
	zColor := Green
	if zs.IsAnomaly {
		statusIcon = Red + "⚠" + Reset
		zColor = Red
	}
	return fmt.Sprintf("│  %s  "+Cyan+"%-18s"+White+": "+zColor+"Z=%+6.2f"+Gray+" (μ=%.1f, σ=%.1f)"+Red+"%-17s"+"│\n"+Reset,
		statusIcon, name, zs.ZScore, zs.Mean, zs.StdDev, "")
}

func getStatusString(isAnomaly bool) string {
	if isAnomaly {
		return "⚠️  ANOMALY DETECTED"
	}
	return "✅ NORMAL"
}

func formatZScore(name string, zs *models.ZScoreResult) string {
	status := "✅"
	if zs.IsAnomaly {
		status = "⚠️"
	}
	return fmt.Sprintf("  %s %-18s: Z=%+6.2f (value=%.1f, μ=%.1f, σ=%.1f)\n",
		status, name, zs.ZScore, zs.Value, zs.Mean, zs.StdDev)
}
