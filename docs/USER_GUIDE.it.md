🌐 **Lingua / Language**: [🇬🇧 English](USER_GUIDE.md) | **🇮🇹 Italiano**  
⬅️ [Torna al README Principale](../README.it.md) | 🛠️ [Guida Avanzata Architettura e Contributori](CONTRIBUTING_AND_ARCHITECTURE.it.md)

# 👤 Warp IM — Guida Completa per l'Utente Base

[![Licenza: PEFL v1.0](https://raw.githubusercontent.com/RubensRainelli/pefl-license-spec/main/badges/pefl-badge-red.svg)](../LICENSE.it)

Benvenuto in **Warp IM**, il client di messaggistica universale nativo ideato da **Rubens Rainelli** e distribuito sotto licenza **Personal and Educational Free License v1.0 (PEFL v1.0)**.  
Questa guida passo-passo ti spiega come scaricare e installare Warp IM sul tuo dispositivo, approvare la licenza PEFL v1.0 all'avvio, personalizzare l'interfaccia (**SuperTheme** e temi colore **Chiaro / Scuro / OLED**), gestire più account dello stesso protocollo e organizzare le tue liste chat.

---

## 📥 1. Scaricare e Installare Warp IM

Scarica il pacchetto per il tuo sistema operativo dalla pagina ufficiale [**GitHub Releases**](https://github.com/RubensRainelli/warp-im/releases).

### 🐧 Linux (Debian / Ubuntu / Linux Mint / Pop!_OS — `.deb`)
1. Scarica il file `warp-im_<version>_amd64.deb`.
2. Installalo dal terminale con `apt`:
   ```bash
   sudo apt install ./warp-im_<version>_amd64.deb
   ```
3. Avvia **Warp IM** dal menu delle applicazioni del tuo ambiente desktop oppure digitando `warp-im` nel terminale.

### 🐧 Linux (Eseguibile Portatile Universale — `.AppImage`)
1. Scarica il file `Warp_IM-<version>-x86_64.AppImage`.
2. Rendilo eseguibile e avvialo direttamente (non richiede privilegi di amministratore né installazione):
   ```bash
   chmod +x Warp_IM-<version>-x86_64.AppImage
   ./Warp_IM-<version>-x86_64.AppImage
   ```

### 🪟 Windows 10 / 11 (`x86_64`)
1. Scarica l'archivio `warp-im-<version>-windows-x86_64.zip` ed estrailo in una cartella.
2. **Modalità Portatile**: Fai doppio clic direttamente su `warp-im.exe`.
3. **Installazione Utente Locale**: Fai clic destro su `Install-WarpIM.ps1` e seleziona *Esegui con PowerShell* per installare Warp IM in `%LOCALAPPDATA%\Programs\WarpIM`.

### 🍎 macOS (Apple Silicon `M1/M2/M3/M4` e Intel Universal — `.dmg`)
1. Scarica il file `Warp-IM-<version>-macos-universal.dmg`.
2. Fai doppio clic sul file `.dmg` e trascina **Warp IM.app** nella cartella **Applicazioni** (`Applications`).
3. Avvia **Warp IM** da Launchpad o Spotlight.

### 📱 Android e iOS (Mobile Nativo)
- **Android 8.0+ (`arm64-v8a` — `.apk` Firmato)**: Scarica direttamente [**`warp-im-0.1.0-android-arm64-v8a.apk`**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/warp-im-0.1.0-android-arm64-v8a.apk) dalla pagina Releases e aprilo sul tuo smartphone Android per installarlo.
- **iOS (`aarch64-apple-ios`)**: Installa tramite Xcode / TestFlight usando il bundle statico `libwarp_app_ios_aarch64.tar.gz`.
- Sugli schermi smartphone (oppure cliccando il pulsante **`📱 Mobile`** nella barra superiore su Desktop), Warp IM passa automaticamente al layout compatto a singola schermata con navigazione touch.

---

## ⚖️ 2. Primo Avvio: Approvazione della Licenza PEFL v1.0 (Clausola 3)

In conformità con la **Clausola 3** della licenza **Personal and Educational Free License v1.0 (PEFL v1.0)**:
1. **Finestra Licenza in Primo Piano**: Al primo avvio, Warp IM mostra in primo piano il testo integrale della licenza **PEFL v1.0**.
2. **Selettore di Lingua**: All'interno della finestra modale puoi passare istantaneamente tra **`🇮🇹 Italiano`** e **`🇬🇧 English`**.
3. **Approvazione Esplicita**:
   - Clicca su **`✅ Accetto / I Accept PEFL v1.0`** se utilizzi Warp IM per scopi **personali, domestici, didattici, educativi, accademici o all'interno di Enti No-Profit / Terzo Settore** (100% gratuito).
   - Clicca su **`❌ Rifiuta ed Esci / Decline & Exit`** se non accetti i termini o se ti trovi su un PC/server aziendale o di un'organizzazione religiosa priva di licenza commerciale concordata con **Rubens Rainelli** (`rubens@rainelli.it`).
4. **Durata di 7 Giorni**: La tua accettazione viene salvata localmente per un massimo di **7 giorni**, trascorsi i quali Warp IM richiederà nuovamente la conferma all'avvio. Puoi rileggere la licenza in qualsiasi momento cliccando sul pulsante **`⚖️ PEFL v1.0`** nella barra superiore.

---

## 🚀 2B. Schermata di Benvenuto: Aggiungere un Account Reale o Provare il Mockup Interattivo

Quando apri Warp IM senza account attivi configurati, l'applicazione **non** carica forzatamente dati fittizi, ma ti mostra la **Schermata di Benvenuto**:
1. **`➕ Aggiungi Account (Login / Sign-Up / Bot)`**: Clicca direttamente sul protocollo che desideri collegare (`Telegram`, `Matrix`, `XMPP`, `Nostr`, `SimpleX`, `IRCv3`, `Stoat`, `Mattermost`) per aprire la schermata di accesso o registrazione del rispettivo servizio e iniziare subito a chattare.
2. **`🧪 Carica Mockup Demo Interattivo`**: Se vuoi esplorare subito l'interfaccia, i 4 SuperTheme e le funzionalità multi-account senza inserire credenziali, clicca su **`🧪 Carica Mockup Demo Interattivo`**. Potrai uscire dal Mockup e ripulire il database locale in qualsiasi momento cliccando su **`🧹 Esci dal Mockup`** nell'intestazione della barra laterale o dentro **`⚙️ Impostazioni`**.

---

## ⚙️ 3. Sezione Impostazioni (`☰` / `⚙️ Impostazioni`), Temi e Scorciatoie Tastiera

Tutte le impostazioni di Warp IM sono raccolte in un'unica **Sezione Impostazioni (`⚙️ Impostazioni`)** accessibile cliccando il pulsante menu **`☰`** in alto a sinistra nella barra laterale:

### A. Scegliere il Layout Strutturale (`SuperTheme`)
Dentro **`⚙️ Impostazioni` → `Layout Strutturale (SuperTheme)`**:
1. **`Telegram`**: Ispirato a Telegram Desktop e Mobile, con cartelle orizzontali scorrevoli sopra la lista chat, avatar circolari `48px`, indicatori online, badge non letti e bolle messaggi arrotondate (ricevute a sinistra con avatar, inviate a destra con spunte `✓✓`).
2. **`WhatsApp`**: Organizza le conversazioni in tab minimali (`Tutte`, `Non lette`, `Gruppi`) con bolle divise per messaggi inviati e ricevuti.
3. **`Discord`**: Attiva la barra verticale sinistra con le icone dei Server/Workspace (`Server Rail`), la colonna dedicata ai canali e le righe messaggi compatte.
4. **`IRC Dense`**: Layout ad alta densità con font monospace e orari compatti `[HH:MM]`, perfetto per canali IRCv3 e stanze XMPP.

### B. Scegliere il Tema Colore (`ThemePalette`)
Dentro **`⚙️ Impostazioni` → `Palette Colori`**:
- **`☀️ Chiaro` (`Light`)**: Tema chiaro ad alto contrasto (`#F8FAFC` / `#FFFFFF`) ideale di giorno.
- **`🌙 Scuro` (`Dark`)**: Tema scuro bilanciato (`#0F172A`) riposante per gli occhi.
- **`🖤 OLED` (`Pure Black #000000`)**: Sfondo **Nero Puro assoluto (`#000000`)** che spegne fisicamente i pixel sugli schermi AMOLED/OLED.
- **`Night TG`**: Classica palette blu notte di Telegram (`#17212B`).
- **`Discord Dark`**: Palette grigio antracite e blurple (`#313338`).
- **`Catppuccin`**: Tema scuro pastello caldo Catppuccin Mocha (`#1E1E2E`).

### C. Scorciatoia Invio Messaggi (`Invio` vs `Ctrl+Invio` / `Alt+Invio`)
Dentro **`⚙️ Impostazioni` → `Comportamento Tastiera e Invio Messaggi`** puoi scegliere come inviare i messaggi:
- **Modalità `Invio` (`Enter` invia)**: Premendo `Invio` il messaggio viene inviato subito, mentre `Ctrl+Invio`, `Alt+Invio` o `Shift+Invio` inseriscono una nuova riga (`\n`).
- **Modalità `Ctrl+Invio / Alt+Invio` (`Ctrl+Enter` o `Alt+Enter` invia)**: Premendo `Invio` vai semplicemente a capo nel testo multi-riga, mentre il messaggio parte solo quando premi `Ctrl+Invio` o `Alt+Invio` (oppure clicchi il pulsante `➤`).

### D. Aree Ridimensionabili su Desktop e Scroll Orizzontale dei Filtri
- **Pannelli Ridimensionabili (`Drag-to-Resize`)**: Su PC Desktop puoi trascinare con il mouse il bordo verticale tra la barra laterale delle chat (o dei canali) e l'area messaggi per allargare o restringere liberamente le colonne.
- **Scroll Orizzontale nelle Categorie Chat e Account**: Le barre orizzontali delle categorie/cartelle (`Tutte`, `Non lette`, `Lavoro`, `Gruppi`) e degli account supportano lo **scroll orizzontale con la rotellina del mouse**, il trascinamento touch/trackpad e i comodi pulsanti **`‹`** e **`›`** ai lati.

---

## 👥 4. Multi-Account per Protocollo, Nuove Chat e Modalità di Isolamento Liste Chat

In Warp IM puoi collegare **più account contemporaneamente sullo stesso protocollo** (ad esempio: un account Telegram personale insieme a un account Telegram di test sul Data Center 2, oppure due reti IRC distinte su Libera.Chat e OFTC).

### Come Accedere (`🔑 Login`), Registrarsi (`✨ Sign-Up`) o Collegare un Bot (`🤖 @BotFather`)
1. Clicca sul pulsante **`👤+`** nella barra laterale (oppure **`➕ Aggiungi Account`** dentro `⚙️ Impostazioni`).
2. Seleziona uno degli **8 protocolli** (`Telegram`, `Matrix`, `XMPP`, `Nostr`, `SimpleX`, `IRCv3`, `Stoat`, `Mattermost`).
3. Scegli la modalità desiderata usando i pulsanti in alto nella finestra:
   - **Sui 7 protocolli aperti (`Matrix`, `XMPP`, `Nostr`, `SimpleX`, `IRCv3`, `Stoat`, `Mattermost`)**:
     - **`🔑 Accedi (Login Account Esistente)`**: Entra con il tuo account già registrato.
     - **`✨ Registrati (Crea Nuovo Account)`**: Crea un nuovo account direttamente dentro Warp IM.
   - **Su `Telegram` (Solo Login Utente o Bot)**:
     - **`👤 Login Utente (Telefono + OTP)`**: Accedi con il tuo numero di telefono e il codice OTP (+ eventuale 2FA).
     - **`🤖 Login come Bot (@BotFather Token)`**: Incolla direttamente il token del tuo bot fornito da `@BotFather` (es. `123456789:AAH...`) per operare come Bot Telegram.
4. Cliccando su **`Conferma / Connetti`**, l'account viene salvato nel database locale SQLite e reso immediatamente operativo.

### ➕ Creare una Nuova Chat o Canale e Cercare Conversazioni
- **Nuova Chat / Canale (`➕`)**: Clicca il pulsante **`➕`** accanto alla barra di ricerca nella colonna sinistra per avviare una nuova chat privata, un gruppo o entrare/creare un canale sull'account selezionato.
- **Ricerca Istantanea (`🔍 Cerca chat...`)**: Digita nella casella di ricerca in alto nella barra laterale per filtrare in tempo reale le conversazioni per titolo, anteprima messaggio o badge account.

### ✈️ Selettore Backend Telegram (Server Pubblico vs Server di Test DC2)
Dentro **`⚙️ Impostazioni`** o nel pannello **`➕ Aggiungi Account` → `Telegram`** puoi scegliere quale ambiente MTProto utilizzare:
- **`🌐 Backend Pubblico (Production DC1–DC5)`**: Connette l'account o il bot Telegram ai Data Center pubblici ufficiali (`149.154.167.50:443`).
- **`🧪 Backend di Test (Test DC2 — 149.154.167.40:443)`**: Connette l'account o il bot alla sandbox ufficiale di test Telegram DC2 (`149.154.167.40:443`, `use_test_dc = true`).

### Scegliere Come Organizzare le Liste Chat (4 Modalità di Isolamento)
Dentro **`⚙️ Impostazioni` → `Isolamento Liste Chat`**:
1. **`🌐 Unificata` (`UnifiedInbox`)**: Raccoglie in un'unica lista cronologica tutte le conversazioni di tutti gli account attivi con badge identificativo (`TG•1`, `MX•1`, `IRC•LIB`).
2. **`🔌 Per Protocollo` (`PerProtocol`)**: Mostra nella barra laterale solo le chat appartenenti al protocollo selezionato.
3. **`🔒 Separata per Account` (`PerAccount`)**: Isolamento totale per singolo account cliccando sul suo badge nella Barra Account.
4. **`⚖️ Ibrida` (`HybridCustom`)**: Affianca cartelle unificate personalizzate a silos isolati per singoli account.

---

## 🔌 5. Azioni Messaggi, Protocolli e Singoli Account

- **Rispondere (`↩`), Reagire (`👍`, `❤️`), Modificare (`✎`) ed Eliminare (`🗑`)**: Ogni bolla messaggio offre pulsanti rapidi per citare/rispondere al messaggio, aggiungere/rimuovere reazioni emoji, modificare il testo (con salvataggio immediato) o eliminare il messaggio.
- **Fissare in Alto una Chat (`📌`)**: Clicca l'icona **`📌`** nell'intestazione della conversazione attiva per fissare o sbloccare la chat.
- **Attivare/Disattivare Protocolli o Singoli Account**: Dentro **`⚙️ Impostazioni`** (o cliccando sui chip nella Barra Account) puoi attivare/disattivare istantaneamente qualsiasi protocollo o singolo account.
