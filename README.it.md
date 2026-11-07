🌐 **Lingua / Language**: [🇬🇧 English](README.md) | **🇮🇹 Italiano**  
📖 **Documentazione**: [👤 Guida per l'Utente](docs/USER_GUIDE.it.md) | [🛠️ Guida Tecnica e per Contributori](docs/CONTRIBUTING_AND_ARCHITECTURE.it.md)

# 🚀 Warp IM — Tutte le Tue Chat in un'Unica App Nativa

[![Licenza: PEFL v1.0](https://raw.githubusercontent.com/RubensRainelli/pefl-license-spec/main/badges/pefl-badge-red.svg)](LICENSE.it)
[![CI Multi-Piattaforma](https://github.com/RubensRainelli/warp-im/actions/workflows/ci.yml/badge.svg)](https://github.com/RubensRainelli/warp-im/actions/workflows/ci.yml)
[![Release Packages](https://github.com/RubensRainelli/warp-im/actions/workflows/release.yml/badge.svg)](https://github.com/RubensRainelli/warp-im/releases)

> [!WARNING]
> **🚧 Progetto in Fase Avanzata di Sviluppo (Pre-Release `v0.x` — Non ancora Stabile)**  
> **Warp IM** è attualmente in fase avanzata di sviluppo attivo e **non è ancora da considerare una versione finale stabile (`v1.0`)**.  
> Puoi già scaricare, installare e provare l'applicazione su Desktop (Windows, Linux, macOS) e testare le funzionalità multi-protocollo, i temi e il multi-account, ma alcune integrazioni (in particolare l'esperienza mobile su Android/iOS e alcune funzioni secondarie) sono ancora in fase di completamento in vista della futura **versione `1.0`**.

---

## 💬 Cos'è Warp IM?

Sei stanco di dover tenere aperte decine di app pesanti che consumano gigabyte di memoria sul tuo computer o telefono?  
**Warp IM** è un'applicazione di messaggistica universale, leggerissima (usa **meno di 50 MB di RAM**) e velocissima, progettata per riunire **8 reti di messaggistica diverse** in un'unica applicazione nativa.

Con **Warp IM** sei tu a decidere come vivere le tue conversazioni:
- Puoi **attivare solo i protocolli che usi** e spegnere tutti gli altri con un clic.
- Puoi **collegare più account** (personali, di studio, bot o di lavoro) e scegliere se vederli tutti insieme in una **Lista Unificata** oppure tenerli rigorosamente **separati account per account**.
- Puoi **trasformare l'aspetto dell'app in tempo reale** scegliendo il layout che preferisci (**stile Telegram**, **stile WhatsApp**, **stile Discord** con barra dei server, o **stile IRC compatto**) e il tema colore che ami di più (**Chiaro**, **Scuro** o **Nero Puro OLED**).

---

## 📥 Scarica Warp IM (Tutte le Piattaforme)

Scarica la versione precompilata per il tuo sistema operativo direttamente da [**GitHub Releases**](https://github.com/RubensRainelli/warp-im/releases/latest):

| Piattaforma | Formato | Link Diretto al Download | Note di Installazione |
|-------------|---------|--------------------------|-----------------------|
| 🪟 **Windows 10 / 11** (`64-bit`) | `.zip` (Portatile + Installer) | [**⬇️ Scarica per Windows (`warp-im-0.1.0-windows-x86_64.zip`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/warp-im-0.1.0-windows-x86_64.zip) | Estrai lo `.zip` e avvia `warp-im.exe` (oppure esegui `Install-WarpIM.ps1`) |
| 🐧 **Linux (Ubuntu / Debian / Mint)** | Pacchetto `.deb` | [**⬇️ Scarica `.deb` (`warp-im_0.1.0_amd64.deb`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/warp-im_0.1.0_amd64.deb) | Installa con `sudo apt install ./warp-im_0.1.0_amd64.deb` |
| 🐧 **Linux (Universale Portatile)** | `.AppImage` | [**⬇️ Scarica `.AppImage` (`Warp_IM-0.1.0-x86_64.AppImage`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/Warp_IM-0.1.0-x86_64.AppImage) | Nessuna installazione richiesta (`chmod +x` e doppio clic) |
| 🍎 **macOS** (`Apple Silicon & Intel`) | Immagine Disco `.dmg` | [**⬇️ Scarica per macOS (`Warp-IM-0.1.0-macos-universal.dmg`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/Warp-IM-0.1.0-macos-universal.dmg) | Apri il `.dmg` e trascina **Warp IM.app** in *Applicazioni* |
| 🤖 **Android 8.0+** (`arm64-v8a` — *Beta*) | Pacchetto `.apk` Firmato | [**⬇️ Scarica APK Android (`warp-im-0.1.0-android-arm64-v8a.apk`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/warp-im-0.1.0-android-arm64-v8a.apk) | Scarica e apri il file `.apk` sul tuo smartphone Android *(build pre-v1.0)* |
| 📱 **iOS** (`aarch64` — *Beta*) | Bundle Nativo `.tar.gz` | [**⬇️ Scarica Build iOS (`libwarp_app_ios_aarch64.tar.gz`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/libwarp_app_ios_aarch64.tar.gz) | Bundle per Xcode / TestFlight *(in fase di sviluppo pre-v1.0)* |
| 📦 **Codice Sorgente Linux** | `.tar.gz` | [**⬇️ Scarica Sorgenti (`warp-im-0.1.0-linux-sources.tar.gz`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/warp-im-0.1.0-linux-sources.tar.gz) | Sorgenti completi per compilazione manuale |

👉 **[Vedi tutte le versioni e i codici di controllo SHA-256 nella pagina Releases](https://github.com/RubensRainelli/warp-im/releases)**

---

## 🌐 Protocolli Supportati (Login, Registrazione e Bot)

Warp IM supporta **8 protocolli di messaggistica**. Per tutti i protocolli che lo consentono puoi sia **creare un nuovo account direttamente dall'app (`✨ Registrati / Sign-Up`)** sia **accedere a un account esistente (`🔑 Login`)**:

| Protocollo | Cosa puoi fare | Accesso & Creazione Account in Warp IM | Sicurezza e Privacy |
|------------|----------------|----------------------------------------|---------------------|
| ✈️ **Telegram** | Chat private, Gruppi, Canali e Forum a Topic | **🔑 Login Utente** (Telefono + OTP + 2FA)<br>**🤖 Login come Bot** (Token `@BotFather`)<br>⚙️ Scelta tra **Server Pubblico** e **Server di Test DC2**<br>*(Solo Login: Telegram richiede l'app mobile ufficiale per registrare una nuova SIM)* | Cloud MTProto + Chat Segrete |
| 🟩 **Matrix** | Chat 1-a-1, Stanze, Spazi (Spaces) e Thread | **✨ Registrati (Sign-Up)** su qualsiasi server aperto<br>**🔑 Login** con account esistente | Crittografia End-to-End (**Olm / Megolm**) |
| 💬 **XMPP (Jabber)** | Chat dirette con contatti e stanze di gruppo (MUC) | **✨ Registrati (Sign-Up In-Band)** su server pubblici<br>**🔑 Login** con il tuo indirizzo JID | Crittografia End-to-End (**OMEMO**) |
| 💜 **Nostr** | Messaggi diretti privati e canali decentralizzati | **✨ Crea Nuova Identità (Sign-Up istantaneo)** in 1 clic senza server<br>**🔑 Login** con chiave privata `nsec1` | Messaggi **Gift-Wrapped (NIP-17 / NIP-59)** |
| 🛡️ **SimpleX Chat** | Chat anonime senza numero di telefono né ID utente | **✨ Crea Nuovo Profilo Anonimo (Sign-Up)**<br>**🔑 Connetti** tramite link di invito o codice QR | Crittografia **Double Ratchet** su code anonime |
| #️⃣ **IRCv3** | Reti e canali IRC con cronologia e reazioni moderne | **✨ Registra Nickname (Sign-Up NickServ/Ergo)**<br>**🔑 Login** diretto o tramite Bouncer (Soju/Ergo) | Connessione cifrata TLS + SASL |
| 🦊 **Stoat (ex Revolt)** | Server di comunità, canali testuali e thread | **✨ Crea Nuovo Account (Sign-Up)**<br>**🔑 Login** con email/password o token | TLS + Permessi canale granulari |
| 🏢 **Mattermost** | Team di studio/progetto, canali pubblici/privati e thread | **✨ Registrati sul Server (Sign-Up)**<br>**🔑 Login** con credenziali, 2FA o Token personale | TLS + Controlli di accesso per team |

---

## ✨ Funzionalità Principali

### 🎨 1. Cambia l'Aspetto dell'App come Preferisci (`SuperTheme` + Temi Colore)
Non tutti amano la stessa interfaccia! Con Warp IM puoi cambiare in qualsiasi momento sia **la disposizione dei pannelli** sia **i colori**:
- **4 Layout Strutturali (`SuperTheme`)**:
  - **Stile Telegram**: Cartelle orizzontali in alto, gruppi con Forum Topic espandibili e classiche bolle arrotondate.
  - **Stile WhatsApp**: Interfaccia semplice ed essenziale con schede rapide (*Tutte*, *Non lette*, *Gruppi*).
  - **Stile Discord**: Barra verticale a sinistra con le icone dei tuoi Server/Spazi e albero dei canali.
  - **Stile IRC Compatto**: Testo ad alta densità con orari compatti, pensato per chi segue canali molto affollati.
- **6 Temi di Colore (inclusi Chiaro, Scuro e Nero Puro OLED)**:
  - **☀️ Chiaro (`Light`)** per l'uso diurno.
  - **🌙 Scuro (`Dark`)**, **Night Telegram**, **Discord Dark** e **Catppuccin Mocha** per non affaticare gli occhi.
  - **🖤 OLED (`#000000`)**: Sfondo **Nero Puro assoluto** che spegne fisicamente i pixel sugli schermi AMOLED/OLED, risparmiando batteria.

### 👥 2. Multi-Account e Liste Chat Unificate o Separate
Puoi aggiungere **più account anche dello stesso protocollo** (ad esempio: il tuo account Telegram personale, un Bot Telegram gestito con `@BotFather`, e un account sul Server di Test).  
Sei tu a scegliere come organizzare la barra laterale:
- **🌐 Vista Unificata**: Tutte le tue chat di tutti gli account in un'unica lista ordinata per orario.
- **🔌 Per Protocollo**: Vedi insieme solo le chat del protocollo selezionato (es. solo Telegram o solo Matrix).
- **🔒 Separata per Account**: Ogni singolo account ha la sua lista chat completamente separata dagli altri, senza alcuna mescolanza.
- **⚖️ Ibrida**: Crea cartelle personalizzate unendo solo ciò che desideri.

### 🤖 3. Funzioni Avanzate per Telegram (Login Bot & Scelta Backend)
Aprendo la finestra **`🔐 Auth / Add Account`** e selezionando **Telegram**, trovi due funzioni pensate sia per gli utenti avanzati sia per chi sviluppa o gestisce bot:
- **Login diretto come Bot (`@BotFather`)**: Incolla il token del tuo bot (`123456789:AAH...`) per entrare in Telegram direttamente come Bot e leggere o inviare messaggi senza scrivere codice.
- **Selettore Backend (Pubblico vs Test DC2)**: Scegli con un clic se collegarti ai normali **Server Pubblici di Telegram** oppure al **Server di Test ufficiale (DC2)**.

### 🔌 4. Attiva o Metti in Pausa Qualsiasi Protocollo o Account
Con un clic nella barra superiore puoi **spegnere temporaneamente** un intero protocollo o un singolo account senza perdere la cronologia salvata sul tuo dispositivo.

---

## 📖 Guide Rapide

- 👤 **[Guida Completa per l'Utente (Italiano)](docs/USER_GUIDE.it.md)**: Come installare l'app, configurare i tuoi account, usare i temi e gestire le liste chat.
- 🛠️ **[Guida Architetturale e per Contributori (Italiano)](docs/CONTRIBUTING_AND_ARCHITECTURE.it.md)**: Documentazione tecnica per sviluppatori Rust/Slint che vogliono compilare il progetto da sorgente o contribuire con nuovi plugin.

---

## ⚖️ Licenza: PEFL v1.0 (Personal and Educational Free License)

**Warp IM** è rilasciato sotto la licenza [**Personal and Educational Free License v1.0 (PEFL v1.0)**](https://github.com/RubensRainelli/pefl-license-spec) — Copyright (c) 2026 **Rubens Rainelli** ([`LICENSE.it`](LICENSE.it) | [`LICENSE`](LICENSE) | [`NOTICE.md`](NOTICE.md)).

### Sintesi semplice per gli utenti:
- ✅ **100% Gratuito per Uso Personale, Domestico, Didattico, Studentesco e No-Profit**: Puoi scaricare, installare e usare liberamente Warp IM a casa, per studio, ricerca accademica o all'interno di associazioni senza scopo di lucro (ETS / ONLUS).
- 🚫 **Vietato l'Uso Aziendale o Commerciale senza Licenza**: L'installazione o l'utilizzo di Warp IM su computer aziendali, server d'impresa, per attività lavorative/professionali o all'interno di organizzazioni religiose è vietato senza una preventiva autorizzazione scritta e accordo commerciale con l'Autore.
- 🔔 **Conferma all'Avvio (Clausola 3)**: Al primo avvio (e successivamente una volta ogni **7 giorni**), Warp IM mostra in primo piano il testo della licenza PEFL v1.0 in Italiano e in Inglese chiedendoti di cliccare su **Accetto** prima di entrare nell'app.

### 📬 Contatti dell'Autore (per informazioni o licenze aziendali)
- **Autore**: Rubens Rainelli
- **Email**: [rubens@rainelli.it](mailto:rubens@rainelli.it)
- **GitHub**: [https://github.com/RubensRainelli/](https://github.com/RubensRainelli/)
- **Telefono**: (+39) 342 811 5882
