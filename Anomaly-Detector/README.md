# Ağ Anomali Tespit Sistemi

Canlı paket yakalama ve Z-skor tabanlı eşik analizi ile ağ trafik anomalilerini tespit eden gerçek zamanlı istatistiksel analiz motoru.

## Genel Bakış

Bu sistem, imza tabanlı yöntemlere bağımlı olmadan gerçek zamanlı ağ izinsiz giriş tespiti ihtiyacını karşılar. Geleneksel IDS sistemleri sürekli kural güncellemeleri ve bilinen saldırı desenleri gerektirir. Bu motor, istatistiksel davranış analizi kullanarak oluşturulan trafik baz çizgilerinden sapmaları tespit eder ve zero-day saldırılar ile yeni saldırı vektörlerinin belirlenmesini sağlar.

## Teknik Mimari

### Temel Tespit Metodolojisi

Sistem çok boyutlu istatistiksel yaklaşım uygular:

- **İstek Hızı Analizi**: Saniyedeki paket sapmaları için Z-skor hesaplama
- **Port Tarama Tespiti**: Zaman pencereleri boyunca port çeşitliliğinin istatistiksel analizi
- **SYN Flood Tespiti**: Tamamlanmamış TCP el sıkışmalarının eşik tabanlı analizi
- **Paket Boyutu Anomalisi**: Anormal yük dağılımlarının tespiti

### Kayan Pencere İstatistikleri

Trafik metrikleri her IP adresi için dairesel arabellek pencerelerinde tutulur:

```
Pencere Boyutu: 60 saniye (yapılandırılabilir)
İzlenen Metrikler:
  - İstek hızı ortalama ve standart sapma
  - Port çeşitliliği istatistikleri
  - SYN paket sıklığı
  - Ortalama paket boyutu dağılımı
```

### Anomali Puanlama Algoritması

```
Puan = (İstekHızıAğırlığı × İstekHızıAnomalisi) +
       (PortTaramaAğırlığı × PortTaramaAnomalisi) +
       (SYNFloodAğırlığı × SYNFloodAnomalisi) +
       (PaketBoyutuAğırlığı × PaketBoyutuAnomalisi)

Eşik: 0.70 (yapılandırılabilir)
Ciddiyet Seviyeleri: DÜŞÜK (0.7), ORTA (0.8), YÜKSEK (0.9), KRİTİK (1.0)
```

## Sistem Gereksinimleri

### Bağımlılıklar

- Go 1.22 veya üstü
- Npcap/WinPcap (Windows) veya libpcap (Linux/macOS)
- GeoLite2-City.mmdb (isteğe bağlı, coğrafi konum için)

### Ağ Arayüz Gereksinimleri

- Promiscuous mod destekli ağ arayüzü
- WinPcap/Npcap sürücüsü kurulu (Windows sistemleri)

## Kurulum

```bash
# Depoyu klonlayın
git clone <repository-url>
cd anomaly-detector

# Bağımlılıkları indirin
go mod tidy

# Binary derleyin
go build -o anomaly-detector ./cmd/anomaly-detector
```

## Kullanım

### Temel İşletim

```bash
# Ağ arayüzünü otomatik tespit et
./anomaly-detector

# Arayüzü manuel belirt
./anomaly-detector -iface eth0

# BPF filtresi uygula
./anomaly-detector -filter "tcp port 80"

# Tespit eşiğini yapılandır
./anomaly-detector -threshold 0.8

# GeoIP aramasını etkinleştir
./anomaly-detector -geoip /path/to/GeoLite2-City.mmdb
```

### Komut Satırı Parametreleri

| Parametre | Tür | Varsayılan | Açıklama |
|-----------|-----|------------|----------|
| `-iface` | string | otomatik-tespit | Yakalama için ağ arayüzü |
| `-filter` | string | yok | Berkeley Packet Filter ifadesi |
| `-geoip` | string | yok | GeoIP veritabanı yolu |
| `-window` | int | 60 | Kayan pencere boyutu (saniye) |
| `-threshold` | float64 | 0.7 | Anomali tespit eşiği (0.0-1.0) |

## Yapılandırma

### Eşik Ayarlama

Tespit hassasiyeti ağırlık yapılandırması ile kontrol edilir:

```go
config := &models.ThresholdConfig{
    ZScoreThreshold:     2.5,   // İstatistiksel sapma eşiği
    RequestRateWeight:   0.30,  // İstek hızı anomalileri için ağırlık
    PortScanWeight:      0.30,  // Port tarama tespiti için ağırlık
    SYNFloodWeight:      0.25,  // SYN flood tespiti için ağırlık
    PacketSizeWeight:    0.15,  // Paket boyutu anomalileri için ağırlık
    AnomalyThreshold:    0.70,  // Anomali sınıflandırması için minimum puan
    WindowSize:          60,    // Analiz penceresi (saniye)
}
```

## Proje Yapısı

```
anomaly-detector/
├── cmd/anomaly-detector/
│   └── main.go              # Uygulama giriş noktası
├── internal/
│   ├── analyzer/
│   │   └── detector.go      # İstatistiksel analiz motoru
│   ├── collector/
│   │   ├── packet_capture.go    # Canlı paket yakalama (libpcap)
│   │   └── traffic_simulator.go # Sentetik trafik oluşturma (test)
│   ├── engine/
│   │   └── pipeline.go      # Orkestrasyon katmanı
│   ├── extractor/
│   │   └── aggregator.go    # Trafik toplama ve örnekleme
│   ├── models/
│   │   ├── packet.go        # Veri yapıları
│   │   └── window.go        # Kayan pencere uygulaması
│   └── services/
│       └── geoip.go         # Coğrafi konum arama servisi
└── pkg/utils/
    └── helpers.go           # Yardımcı fonksiyonlar
```

## Tespit Yetenekleri

### Tespit Edilen Saldırı Vektörleri

1. **Dağıtık Hizmet Reddi (DDoS)**
   - İstek hızı analizi ile hacimsel tespit
   - SYN izleme üzerinden bağlantı flood tanımlama

2. **Port Tarama**
   - Yatay tarama tespiti (çok host, az port)
   - Dikey tarama tespiti (tek host, çok port)

3. **Protokol Anomalileri**
   - Sıra dışı yük boyutu dağılımları
   - Protokol kötüye kullanım desenleri

### Sınırlamalar

- İstatistiksel geçerlilik için yeterli baz trafik gerektirir (minimum 10 örnek)
- Yalnızca IPv4/IPv6 paket yakalama; uygulama katmanı analizi uygulanmadı
- Coğrafi konum için harici MaxMind veritabanı gerekir
- TLS izinsiz kesme olmadan şifreli trafik analizi için uygunsuz

## Performans Değerlendirmeleri

- Paket işleme: Modern donanımda saniyede ~100.000 paket
- Bellek kullanımı: ~50MB temel + 1000 aktif IP başına ~1MB
- CPU kullanımı: Tek çekirdek optimize; çok çekirdek ölçekleme harici yük dengeleme gerektirir

## Lisans

MIT Lisansı

## Referanslar

- Z-Skor İstatistiksel Metod: Aykırı değer tespiti için standart puan hesaplama
- Berkeley Packet Filter: Çekirdek seviyesi paket filtreleme mekanizması
- Dairesel Arabellek Algoritması: Sabit bellek ayak izi ile O(1) ekleme
