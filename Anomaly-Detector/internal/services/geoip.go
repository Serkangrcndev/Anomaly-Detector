package services

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/oschwald/geoip2-golang"
	"anomaly-detector/internal/models"
)

type GeoIPService struct {
	reader *geoip2.Reader
	mu     sync.RWMutex
	cache  map[string]*models.GeoLocation
}

func NewGeoIPService(dbPath string) (*GeoIPService, error) {
	if dbPath == "" {
			possiblePaths := []string{
			"data/GeoLite2-City.mmdb",
			"/usr/share/GeoIP/GeoLite2-City.mmdb",
			"GeoLite2-City.mmdb",
		}
		
		for _, path := range possiblePaths {
			if _, err := os.Stat(path); err == nil {
				dbPath = path
				break
			}
		}
	}
	
	if dbPath == "" {
		return nil, fmt.Errorf("GeoIP database not found. Please provide a valid path to GeoLite2-City.mmdb")
	}
	
	reader, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open GeoIP database: %w", err)
	}
	
	return &GeoIPService{
		reader: reader,
		cache:  make(map[string]*models.GeoLocation),
	}, nil
}

func NewGeoIPServiceMock() *GeoIPService {
	return &GeoIPService{
		cache: make(map[string]*models.GeoLocation),
	}
	}

func (g *GeoIPService) LookupIP(ipStr string) (*models.GeoLocation, error) {
	g.mu.RLock()
	if cached, exists := g.cache[ipStr]; exists {
		g.mu.RUnlock()
		return cached, nil
	}
	g.mu.RUnlock()
	
	if g.reader == nil {
		location := g.generateMockLocation(ipStr)
		g.mu.Lock()
		g.cache[ipStr] = location
		g.mu.Unlock()
		return location, nil
	}
	
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	
	record, err := g.reader.City(ip)
	if err != nil {
		return nil, fmt.Errorf("GeoIP lookup failed: %w", err)
	}
	
	location := &models.GeoLocation{
		Country:     record.Country.Names["en"],
		CountryCode: record.Country.IsoCode,
		City:        record.City.Names["en"],
		Latitude:    record.Location.Latitude,
		Longitude:   record.Location.Longitude,
	}
	
	g.mu.Lock()
	g.cache[ipStr] = location
	g.mu.Unlock()
	
	return location, nil
}

func (g *GeoIPService) LookupIPs(ipStrs []string) map[string]*models.GeoLocation {
	results := make(map[string]*models.GeoLocation)
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	for _, ip := range ipStrs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			
			location, err := g.LookupIP(ip)
			if err == nil {
				mu.Lock()
				results[ip] = location
				mu.Unlock()
			}
		}(ip)
	}
	
	wg.Wait()
	return results
}

func (g *GeoIPService) generateMockLocation(ipStr string) *models.GeoLocation {
	mockCountries := []struct {
		name string
		code string
		city string
		lat  float64
		lon  float64
	}{
		{"United States", "US", "New York", 40.7128, -74.0060},
		{"United Kingdom", "GB", "London", 51.5074, -0.1278},
		{"Germany", "DE", "Berlin", 52.5200, 13.4050},
		{"France", "FR", "Paris", 48.8566, 2.3522},
		{"Japan", "JP", "Tokyo", 35.6762, 139.6503},
		{"China", "CN", "Beijing", 39.9042, 116.4074},
		{"Russia", "RU", "Moscow", 55.7558, 37.6173},
		{"Brazil", "BR", "Sao Paulo", -23.5505, -46.6333},
	}
	
	hash := 0
	for _, c := range ipStr {
		hash = (hash + int(c)) % len(mockCountries)
	}
	if hash < 0 {
		hash = -hash
	}
	
	country := mockCountries[hash%len(mockCountries)]
	
	return &models.GeoLocation{
		Country:     country.name,
		CountryCode: country.code,
		City:        country.city,
		Latitude:    country.lat,
		Longitude:   country.lon,
		ISP:         "Mock ISP",
	}
}

func (g *GeoIPService) Close() error {
	if g.reader != nil {
		return g.reader.Close()
	}
	return nil
}

func (g *GeoIPService) GetCacheStats() (size int, hitRate float64) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	
	return len(g.cache), 0 // Hit rate tracking could be added
}
