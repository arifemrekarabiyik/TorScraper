package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

// --- KONFIGURASYON ---
const (
	TorProxyAddr = "127.0.0.1:9150" // Tor Browser: 9150, Servis: 9050
	UserAgent    = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
	ReportFile   = "scan_report.log"
	TimeoutHTTP  = 60 // Saniye
	TimeoutShot  = 90 // Saniye
)

// YAML Okuma Yapısı
type Config struct {
	Targets []string `yaml:"targets"`
}

// IP Kontrol Yapısı
type TorCheckIP struct {
	IsTor bool   `json:"IsTor"`
	IP    string `json:"IP"`
}

func main() {
	// 1. HTTP CLIENT OLUŞTUR (http.Transport ve SOCKS5 Şartı için)
	httpClient, err := getTorHttpClient()
	if err != nil {
		log.Fatalf("[FATAL] HTTP Client oluşturulamadı: %v", err)
	}

	// 2. GÜVENLİK KONTROLÜ (IP Sızıntısı Var mı?)
	fmt.Println("[*] Tor baglantisi ve IP gizliligi kontrol ediliyor...")
	if err := verifyTorConnection(httpClient); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	// 3. HEDEFLERİ YÜKLE
	urls, err := loadTargets("targets.yaml")
	if err != nil {
		log.Fatalf("[FATAL] targets.yaml okunamadı: %v", err)
	}
	fmt.Printf("[*] %d hedef yüklendi. Tarama başlıyor...\n\n", len(urls))

	// Rapor dosyasını hazırla
	initReportFile()

	// --- CHROMEDP HAZIRLIĞI ---
	// Ekran görüntüsü için tarayıcı ayarları
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ProxyServer("socks5://"+TorProxyAddr), // Tarayıcı da Tor kullanmalı
		chromedp.Flag("headless", true),
		chromedp.WindowSize(1920, 1080),
		chromedp.IgnoreCertErrors,
		chromedp.DisableGPU,
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()

	// 4. ANA DÖNGÜ
	for i, rawUrl := range urls {
		targetURL := strings.TrimSpace(rawUrl)
		if targetURL == "" {
			continue
		}

		fmt.Printf("[%d/%d] Isleniyor: %s\n", i+1, len(urls), targetURL)

		// Dosya isimlerini hazırla
		baseName := generateFilename(targetURL)
		htmlFile := baseName + ".html"
		imgFile := baseName + ".png"

		// ADIM A: HTML ÇEK (net/http ile)
		fmt.Print("   |-- [HTTP] Baglaniyor... ")
		htmlContent, err := fetchHTML(httpClient, targetURL)
		if err != nil {
			fmt.Println("BAŞARISIZ.")
			logToReport(targetURL, "PASSIVE", fmt.Sprintf("HTTP Error: %v", err))
			continue // HTML alamazsak screenshot denemeye gerek yok
		}

		// HTML Kaydet
		if err := os.WriteFile(htmlFile, htmlContent, 0644); err != nil {
			fmt.Printf("Dosya Hatasi: %v\n", err)
		}
		fmt.Println("HTML İndirildi.")

		// ADIM B: EKRAN GÖRÜNTÜSÜ AL (Chromedp ile)
		fmt.Print("   |-- [SHOT] Goruntu aliniyor... ")

		// Her site için yeni context
		ctx, cancelCtx := chromedp.NewContext(allocCtx)
		ctx, cancelTimeout := context.WithTimeout(ctx, time.Duration(TimeoutShot)*time.Second)

		err = takeScreenshot(ctx, targetURL, imgFile)
		if err != nil {
			fmt.Printf("BAŞARISIZ (%v)\n", err)
			// Site aktif ama screenshot alınamadı (HTML var, Resim yok)
			logToReport(targetURL, "PARTIAL", "HTML OK, Screenshot FAILED")
		} else {
			fmt.Println("KAYDEDİLDİ.")
			logToReport(targetURL, "ACTIVE", fmt.Sprintf("HTML & PNG Saved (%s)", baseName))
		}

		// Temizlik
		cancelTimeout()
		cancelCtx()
	}

	fmt.Println("\n[*] İşlem tamamlandı. Rapor: " + ReportFile)
}

// ---------------- FONKSİYONLAR ----------------

// ŞART: http.Transport kullanılarak trafiğin SOCKS5 üzerinden geçirilmesi
func getTorHttpClient() (*http.Client, error) {
	// SOCKS5 Dialer tanımla
	dialer, err := proxy.SOCKS5("tcp", TorProxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	// Transport katmanını özelleştir
	tr := &http.Transport{
		Dial:                dialer.Dial, // Trafiği SOCKS5'e zorla
		TLSHandshakeTimeout: 15 * time.Second,
		DisableKeepAlives:   true,
	}

	// Client oluştur
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(TimeoutHTTP) * time.Second,
	}

	return client, nil
}

// HTML Kaynağını çeker
func fetchHTML(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Status Code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// Ekran görüntüsü alır
func takeScreenshot(ctx context.Context, url string, filename string) error {
	var buf []byte
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Sleep(5*time.Second), // Render için bekleme
		chromedp.FullScreenshot(&buf, 90),
	)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, buf, 0644)
}

// IP kontrolü
func verifyTorConnection(client *http.Client) error {
	resp, err := client.Get("https://check.torproject.org/api/ip")
	if err != nil {
		return fmt.Errorf("Tor API erişim hatası: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result TorCheckIP
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("JSON hatası: %v", err)
	}

	if !result.IsTor {
		return fmt.Errorf("DİKKAT! Tor IP'si kullanılmıyor! Mevcut IP: %s", result.IP)
	}
	fmt.Printf("[OK] Tor IP Onaylandı: %s\n", result.IP)
	return nil
}

// Yardımcılar
func generateFilename(rawUrl string) string {
	name := strings.TrimPrefix(rawUrl, "http://")
	name = strings.TrimPrefix(name, "https://")
	name = strings.TrimSuffix(name, "/")
	r := strings.NewReplacer(":", "_", "/", "_", ".", "_")
	safe := r.Replace(name)
	if len(safe) > 50 {
		safe = safe[:50]
	}
	return safe
}

func initReportFile() {
	f, err := os.Create(ReportFile)
	if err != nil {
		return
	}
	header := fmt.Sprintf("SCAN REPORT - %s\nTarget | Status | Details\n%s\n",
		time.Now().Format(time.RFC3339), strings.Repeat("-", 60))
	f.WriteString(header)
	f.Close()
}

func logToReport(url, status, msg string) {
	f, err := os.OpenFile(ReportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	line := fmt.Sprintf("%-30s | %-8s | %s\n", url, status, msg)
	f.WriteString(line)
}

func loadTargets(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return c.Targets, nil
}
