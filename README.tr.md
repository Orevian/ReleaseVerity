<div align="center">

# ReleaseVerity

**Bu sürüm güvenilir mi, kaynak koduyla tutarlı mı, kurulabiliyor mu ve gerçekten çalışıyor mu?**

ReleaseVerity yazılım sürümlerini uçtan uca doğrular: tedarik zinciri, tekrarlanabilirlik, kurulum ve çalışma zamanı. Yerel bir Windows masaüstü uygulaması, bir CLI ve bir GitHub Action olarak sunulur; hepsi aynı motoru kullanır.

[English](README.md) · [Türkçe](README.tr.md)

![Panel](docs/images/dashboard-tr-light.png)

</div>

---

## On saniyede

```text
Sürüm ──▶ ReleaseVerity ──┬─ Tedarik zinciri   git etiketi → commit, sağlama toplamları, imzalar, provenance, SBOM
                      ├─ Tekrarlanabilirlik  sürüm artifact'i ile kendi derlemeniz bayt bayt; neden farklı olduğuyla birlikte
                      ├─ Kurulum            gerçek kurulum dosyası temiz ortamda, gerçek kaldırma
                      ├─ Çalışma zamanı     başlatma, çökme / takılma / zaman aşımı tespiti, duman testleri, çıkış kodları
                      └─ Sürüm kalitesi     dokümantasyon, skor ve karar ─▶  DOĞRULANDI · UYARILARLA · BAŞARISIZ
```

Hiçbir şey simüle edilmez: sağlama toplamları hesaplanır, git nesneleri doğrulanır, kurulum dosyaları çalıştırılır, çıkış kodları okunur, ikili dosyalar karşılaştırılır. ReleaseVerity bir şeyi ölçemediğinde **"Doğrulanamadı"** veya **"Henüz mevcut değil"** der; asla uydurma bir "geçti" üretmez.

## Ekran görüntüleri

Hepsi gerçek uygulamadan, gerçek verilerle alınmıştır (gerçek bir halka açık sürüm olan [ripgrep 14.1.1](https://github.com/BurntSushi/ripgrep/releases/tag/14.1.1) dahil).

| | |
|---|---|
| ![Sürüm detayı](docs/images/release-detail.png) **Sürüm detayı** – her sonuca tıklanır: neden, öneri, günlük, kanıt | ![Ortam matrisi](docs/images/environment-matrix.png) **Ortam matrisi** – ortam başına kurulum / başlatma / duman testi / kaldırma |
| ![Bozuk sürüm](docs/images/failed-release.png) **Üzerinde oynanmış sürüm** – beklenen ve gerçek özetlerle gerçek checksum uyuşmazlığı | ![Tekrarlanabilirlik](docs/images/reproducibility.png) **Tekrarlanabilirlik** – bölgelere atfedilmiş bayt farkı ve olası neden |

![CLI](docs/images/cli.png)

## Kurulum

[Releases](../../releases) sayfasından indirin: `ReleaseVerity-Setup-x64.exe` (kurulum), `ReleaseVerity-<sürüm>-portable-x64.zip` (taşınabilir klasör), `SHA256SUMS`, SBOM. Windows 10/11 x64 gerekir; Visual C++ Redistributable gerekmez.

## Hızlı başlangıç

```powershell
releaseverity doctor
releaseverity verify --repo https://github.com/ornek/proje --release v1.4.0 --report html,json
releaseverity --lang tr shipcheck run --package .\uygulama.zip --exe uygulama.exe --smoke "--version => 1.4.0"
releaseverity repro compare .\surum\uygulama.exe .\benim-derlemem\uygulama.exe
```

Dil: **Ayarlar → Dil** veya `releaseverity config set general.language tr`. Arayüz, CLI mesajları, motor sonuçları ve raporlar iki dilde de gösterilir; dil yalnızca bir görünüm tercihidir (kayıtlı sonuçlar istenen dilde yeniden çizilir).

## Yalıtım (güvenlik)

ShipCheck güvenilmeyen yazılım çalıştırır; bu yüzden önce yalıtım:

| Ortam | Nerede | Yalıtım | Ne için |
|---|---|---|---|
| `appcontainer` — **ReleaseVerity'un kendi sandbox'ı** | her Windows sürümü (Home dahil) | işletim sistemi zorlamalı: ağ yok, sandbox dışına erişim yok | portable paketler |
| `windows-sandbox` | Windows Pro/Enterprise/Education | tek kullanımlık VM | kurulum dosyaları |
| `host` | her yerde | **yok** — yalnızca açık onayla | güvendiğiniz yazılımlar |

## Sınırlamalar

- Windows Sandbox içinde yeni Windows sürümlerinde Akıllı Uygulama Denetimi zorunludur; yalnızca imzalı yazılım çalışır (ReleaseVerity bunu tespit edip nedeniyle raporlar).
- Yerleşik sandbox yalnızca portable paketleri çalıştırır (kurulum dosyaları Program Files/HKLM'ye yazar).
- Sürümün sandbox içinde otomatik yeniden derlenmesi henüz yok; tekrarlanabilirlik, sizin verdiğiniz derlemeyle karşılaştırır.
- Performans kontrolü, PDF dışa aktarma, GitHub OAuth, Hyper-V/Linux/macOS çalıştırıcıları yol haritasında.

Ayrıntılar için İngilizce [README](README.md), [docs/](docs/) ve [SECURITY.md](SECURITY.md) dosyalarına bakın. Lisans: [Apache-2.0](LICENSE).
