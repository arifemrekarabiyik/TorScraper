⚙️ Kurulum ve Gereksinimler

​Ön Koşullar

​Go: Sisteminizde Go 1.20 veya üzeri kurulu olmalıdır.
​Tor Browser: Arka planda Tor Browser açık olmalı ve bağlantı kurulmuş olmalıdır (Varsayılan Port: 9150).


​Adım Adım Çalıştırma

1- Projeyi Klonlayın:

git clone https://github.com/arifemrekarabiyik/TorScraper.git
cd TorScraper

2- Bağımlılıkları İndirin:

go mod tidy


3- Hedefleri Belirleyin:

targets.yaml dosyasını açın ve taramak istediğiniz .onion linklerini ekleyin

Uygulamayı Çalıştırın:
(Tor Browser'ın açık olduğundan emin olun)

go run main.go
