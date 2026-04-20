package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"strings"
	"time"
)

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
	Dim     = "\033[2m"
	Bold    = "\033[1m"
)

func Colorize(color, text string) string {
	return color + text + Reset
}

func PrintBanner(title, subtitle string) {
	fmt.Println()
	fmt.Println(Cyan + "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓" + Reset)
	fmt.Printf(Cyan+"┃"+Reset+Magenta+"  %s"+Cyan+"%*s┃\n"+Reset, title, 52-len(title), "")
	fmt.Printf(Cyan+"┃"+Reset+White+"  %s"+Cyan+"%*s┃\n"+Reset, subtitle, 52-len(subtitle), "")
	fmt.Println(Cyan + "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛" + Reset)
	fmt.Println()
}

func PrintInfo(format string, args ...interface{}) {
	fmt.Printf(Blue+"[ℹ] "+Reset+format+"\n", args...)
}

func PrintSuccess(format string, args ...interface{}) {
	fmt.Printf(Green+"[✓] "+Reset+format+"\n", args...)
}

func PrintWarning(format string, args ...interface{}) {
	fmt.Printf(Yellow+"[⚠] "+Reset+format+"\n", args...)
}

func PrintError(format string, args ...interface{}) {
	fmt.Printf(Red+"[✗] "+Reset+format+"\n", args...)
}

func Clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func Round(value float64, decimals int) float64 {
	p := math.Pow(10, float64(decimals))
	return math.Round(value*p) / p
}

func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}

func HashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}
	
	for _, cidr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}
	
	return false
}

func GetLocalIPs() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	
	var ips []string
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}
	
	return ips, nil
}

func ParseIPList(ipList string) []string {
	var ips []string
	for _, ip := range strings.Split(ipList, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" && net.ParseIP(ip) != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func Percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	if p <= 0 {
		return values[0]
	}
	
	if p >= 100 {
		return values[len(values)-1]
	}
	
	index := (p / 100) * float64(len(values)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))
	
	if lower == upper {
		return values[lower]
	}
	
	weight := index - float64(lower)
	return values[lower]*(1-weight) + values[upper]*weight
}

func Median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	return Percentile(values, 50)
}

func Mad(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	median := Median(values)
	
	absDeviations := make([]float64, len(values))
	for i, v := range values {
		absDeviations[i] = math.Abs(v - median)
	}
	
	return Median(absDeviations)
}

func TimeAgo(t time.Time) string {
	duration := time.Since(t)
	
	switch {
	case duration < time.Second:
		return "just now"
	case duration < time.Minute:
		return fmt.Sprintf("%ds ago", int(duration.Seconds()))
	case duration < time.Hour:
		return fmt.Sprintf("%dm ago", int(duration.Minutes()))
	case duration < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(duration.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(duration.Hours()/24))
	}
}

func ByteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

func ByteCountIEC(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB",
		float64(b)/float64(div), "KMGTPE"[exp])
}
