/*
 * Personal and Educational Free License (PEF License / PEFL)
 * Version 1.0 - 2026-05-26
 * Copyright (c) 2026 Rubens Rainelli
 *
 * Contact Details:
 *   Email: rubens@rainelli.it
 *   GitHub: https://github.com/RubensRainelli/
 *   Tel: (+39) 342 811 5882
 *
 * Personal and educational free use permitted.
 * Corporate, business or enterprise use prohibited without written authorization and fee.
 * The full license can be found in the LICENSE file.
 */

//! Declarative Auth & Onboarding State Machine (`AuthFlowDescriptor`, `AuthStep`).
//!
//! Instead of hardcoding a rigid `login(username, password)` method on protocol plugins,
//! each adapter emits a declarative [`AuthFlowDescriptor`] describing the exact onboarding
//! step and input fields required. The Slint UI dynamically renders the onboarding form
//! from `AuthStep` without needing protocol-specific `.slint` dialogs.
//!
//! Supported onboarding paradigms across the 8 protocols:
//! - **Telegram**: `AuthStep::PhoneAndOtp` (Phone -> SMS/App OTP -> optional 2FA Cloud Password)
//! - **Matrix**: `AuthStep::ProvideServerUrl` -> `AuthStep::UsernamePasswordSasl` (Homeserver + login/SSO + cross-signing recovery phrase)
//! - **XMPP**: `AuthStep::UsernamePasswordSasl` (JID `user@domain` + SASL SCRAM-SHA-256 password)
//! - **Nostr**: `AuthStep::ImportPrivateKeyNsec` (`nsec1...` / hex secret key or NIP-46 Bunker URI + relay URLs)
//! - **SimpleX**: `AuthStep::ScanOrDisplayQrInvite` (`simplex:/...` pairwise SMP invitation queue QR / link, zero global user ID)
//! - **IRCv3**: `AuthStep::UsernamePasswordSasl` (Server/Soju Bouncer URL + TLS + Nick + SASL PLAIN/EXTERNAL)
//! - **Stoat**: `AuthStep::ProvideServerUrl` -> `AuthStep::UsernamePasswordSasl` (Stoat instance URL + credentials/session token)
//! - **Mattermost**: `AuthStep::ProvideServerUrl` -> `AuthStep::UsernamePasswordSasl` (Enterprise server URL + Login/PAT)

use crate::ids::{AccountId, ProtocolKind};
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Sub-phase for phone + OTP authentication (e.g., Telegram `grammers`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtpPhase {
    EnterPhoneNumber,
    EnterVerificationCode,
    EnterTwoFactorPassword,
}

/// Onboarding action mode selected by the user for a protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingMode {
    /// Log in to an existing user account (`login`).
    #[default]
    Login,
    /// Register / create a brand-new account in-app (`signup`), supported on
    /// Matrix, XMPP (XEP-0077), Nostr (local keypair), SimpleX (local profile),
    /// IRCv3 (NickServ/Ergo), Stoat, and Mattermost.
    SignUp,
    /// Log in to Telegram as a Bot using a `@BotFather` token (`bot_token`, `auth.importBotAuthorization`).
    TelegramBotToken,
}

impl OnboardingMode {
    pub fn as_slug(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::SignUp => "signup",
            Self::TelegramBotToken => "bot_token",
        }
    }

    pub fn from_slug(slug: &str) -> Self {
        match slug.trim().to_ascii_lowercase().as_str() {
            "signup" | "sign_up" | "register" | "registrazione" => Self::SignUp,
            "bot" | "bot_token" | "telegram_bot" | "botfather" => Self::TelegramBotToken,
            _ => Self::Login,
        }
    }
}

/// Mode for out-of-band QR / invite link pairing (e.g., SimpleX Chat SMP queues).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QrInviteMode {
    /// Display a generated one-time invitation URI/QR for a contact to scan, or paste theirs.
    DisplayOrPasteInvite,
    /// Scan a device-linking QR code.
    ScanDeviceLink,
}

/// Declarative specification of a single form input field rendered dynamically by Slint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthFieldSpec {
    pub key: CompactString,
    pub label: CompactString,
    pub placeholder: CompactString,
    pub is_secret: bool,
    pub required: bool,
    pub default_value: Option<CompactString>,
}

/// Declarative authentication state machine step emitted by any [`crate::plugin::MessagingBackend`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step_kind", rename_all = "snake_case")]
pub enum AuthStep {
    /// Step asking for a self-hosted or federated server endpoint (Matrix, Stoat, Mattermost, IRC).
    ProvideServerUrl {
        title: CompactString,
        default_url: Option<CompactString>,
        allow_custom_port: bool,
        tls_default: bool,
    },
    /// Multi-phase phone number + OTP code + optional 2FA password (Telegram User Login).
    PhoneAndOtp {
        phase: OtpPhase,
        phone_hint: Option<CompactString>,
        code_length: u8,
        requires_2fa_password: bool,
    },
    /// Telegram Bot Token authentication (`auth.importBotAuthorization` via `@BotFather` token).
    TelegramBotToken {
        bot_token_label: CompactString,
        bot_token_placeholder: CompactString,
    },
    /// In-app Account Sign-Up / Registration step for protocols that permit creating new accounts
    /// (Matrix, XMPP XEP-0077, Nostr Keygen, SimpleX Local Profile, IRCv3 NickServ/Ergo, Stoat, Mattermost).
    AccountRegistration {
        server_url_default: Option<CompactString>,
        registration_hint: CompactString,
    },
    /// Cryptographic keypair import/generation + relay bootstrap list (Nostr NIP-17/NIP-59).
    ImportPrivateKeyNsec {
        key_format_hint: CompactString,
        default_relays: Vec<CompactString>,
        allow_generate_new: bool,
    },
    /// Identity-less pairwise queue creation via QR code or `simplex:/` URI (SimpleX Chat).
    ScanOrDisplayQrInvite {
        mode: QrInviteMode,
        qr_payload_uri: CompactString,
        smp_server_hint: CompactString,
    },
    /// Username/JID/Nick + Password SASL authentication (XMPP, IRCv3/Soju, Matrix, Mattermost, Stoat).
    UsernamePasswordSasl {
        identifier_label: CompactString,
        identifier_placeholder: CompactString,
        requires_server_url: bool,
        default_server_url: Option<CompactString>,
        supports_bouncer_network_tag: bool,
    },
    /// Authentication or registration completed; account is ready to sync.
    Completed {
        account_id: AccountId,
        display_handle: CompactString,
    },
    /// Authentication step failed with retryable diagnostic.
    Failed {
        reason: CompactString,
        can_retry: bool,
    },
}

/// Complete state descriptor of an active onboarding flow for the Slint UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthFlowDescriptor {
    pub protocol: ProtocolKind,
    pub flow_id: CompactString,
    pub step_index: u32,
    pub total_steps: u32,
    pub step_title: CompactString,
    pub step_description: CompactString,
    pub current_step: AuthStep,
    pub fields: Vec<AuthFieldSpec>,
}

/// User form values submitted from the Slint UI back to the protocol adapter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStepSubmission {
    pub values: HashMap<CompactString, String>,
    pub action: Option<CompactString>,
}

impl AuthStepSubmission {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|s| s.as_str())
    }
}

impl AuthFlowDescriptor {
    /// Returns `true` if the protocol supports creating/registering a brand-new account directly in-app.
    ///
    /// Note: Telegram restricts new phone number SMS registrations (`auth.signUp`) to first-party
    /// official mobile apps since 2023; therefore Telegram supports **User Login** and **Bot Token Login**
    /// (`supports_bot_token_login == true`), while all other 7 protocols support in-app **Sign-Up + Login**.
    pub fn supports_in_app_signup(protocol: &ProtocolKind) -> bool {
        !matches!(protocol, ProtocolKind::Telegram)
    }

    /// Returns `true` if the protocol supports logging in as an automated/interactive Bot via token.
    pub fn supports_bot_token_login(protocol: &ProtocolKind) -> bool {
        matches!(protocol, ProtocolKind::Telegram)
    }

    /// Produces the Telegram MTProto **User Login** flow configured for either the Public Production
    /// backend (`use_test_dc = false`, `149.154.167.50:443` DC1–DC5) or the Test Server backend
    /// (`use_test_dc = true`, `149.154.167.40:443` Test DC2 with `+999662xxxx` / OTP `22222`).
    pub fn telegram_with_backend(use_test_dc: bool) -> Self {
        if use_test_dc {
            Self {
                protocol: ProtocolKind::Telegram,
                flow_id: "auth-tg-mtproto-test-dc2".into(),
                step_index: 1,
                total_steps: 2,
                step_title: "Telegram Login Utente — 🧪 Backend di Test (DC2 149.154.167.40:443)".into(),
                step_description:
                    "Connessione al Test Server Telegram DC2 (149.154.167.40:443). Usa un numero di test +999662xxxx e il codice OTP 22222."
                        .into(),
                current_step: AuthStep::PhoneAndOtp {
                    phase: OtpPhase::EnterPhoneNumber,
                    phone_hint: Some("+9996621234".into()),
                    code_length: 5,
                    requires_2fa_password: false,
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "onboarding_mode".into(),
                        label: "Modalità Accesso Telegram (login | bot_token)".into(),
                        placeholder: "login".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("login".into()),
                    },
                    AuthFieldSpec {
                        key: "backend_env".into(),
                        label: "Telegram Backend Environment (public | test_dc2)".into(),
                        placeholder: "test_dc2".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("test_dc2".into()),
                    },
                    AuthFieldSpec {
                        key: "phone_number".into(),
                        label: "Phone Number (Test DC2 +999662xxxx)".into(),
                        placeholder: "+9996621234".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("+9996621234".into()),
                    },
                    AuthFieldSpec {
                        key: "otp_code".into(),
                        label: "Telegram Test DC2 OTP Code (22222)".into(),
                        placeholder: "22222".into(),
                        is_secret: false,
                        required: false,
                        default_value: Some("22222".into()),
                    },
                ],
            }
        } else {
            Self {
                protocol: ProtocolKind::Telegram,
                flow_id: "auth-tg-mtproto".into(),
                step_index: 1,
                total_steps: 2,
                step_title: "Telegram Login Utente — 🌐 Backend Pubblico (DC1–DC5 Produzione)".into(),
                step_description:
                    "Accedi ai server pubblici ufficiali di Telegram (149.154.167.50:443 DC1–DC5) tramite numero di telefono internazionale e codice OTP."
                        .into(),
                current_step: AuthStep::PhoneAndOtp {
                    phase: OtpPhase::EnterPhoneNumber,
                    phone_hint: Some("+39 3xx xxx xxxx".into()),
                    code_length: 5,
                    requires_2fa_password: false,
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "onboarding_mode".into(),
                        label: "Modalità Accesso Telegram (login | bot_token)".into(),
                        placeholder: "login".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("login".into()),
                    },
                    AuthFieldSpec {
                        key: "backend_env".into(),
                        label: "Telegram Backend Environment (public | test_dc2)".into(),
                        placeholder: "public".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("public".into()),
                    },
                    AuthFieldSpec {
                        key: "phone_number".into(),
                        label: "Phone Number (International)".into(),
                        placeholder: "+39 340 123 4567".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "otp_code".into(),
                        label: "Telegram OTP Code (Step 2)".into(),
                        placeholder: "12345".into(),
                        is_secret: false,
                        required: false,
                        default_value: None,
                    },
                ],
            }
        }
    }

    /// Produces the Telegram MTProto **Bot Token Login** (`auth.importBotAuthorization`) flow
    /// for either the Public Production backend (`use_test_dc = false`) or Test DC2 (`use_test_dc = true`).
    pub fn telegram_bot_with_backend(use_test_dc: bool) -> Self {
        let (env_slug, title_suffix, desc) = if use_test_dc {
            (
                "test_dc2",
                "🧪 Backend di Test (DC2 149.154.167.40:443)",
                "Accedi direttamente come Bot Telegram sul Test Server DC2 (auth.importBotAuthorization) inserendo il token generato da @BotFather.",
            )
        } else {
            (
                "public",
                "🌐 Backend Pubblico (DC1–DC5 Produzione)",
                "Accedi direttamente come Bot Telegram sui Data Center di produzione (auth.importBotAuthorization) inserendo il token fornito da @BotFather (es. 123456789:AAH...).",
            )
        };
        Self {
            protocol: ProtocolKind::Telegram,
            flow_id: CompactString::from(format!("auth-tg-bot-{}", env_slug)),
            step_index: 1,
            total_steps: 1,
            step_title: CompactString::from(format!("Telegram Login Bot (@BotFather) — {}", title_suffix)),
            step_description: CompactString::from(desc),
            current_step: AuthStep::TelegramBotToken {
                bot_token_label: "Bot Token (@BotFather)".into(),
                bot_token_placeholder: "1234567890:AAHfiqksKZ8WmR2z9pL0xYzExampleBotToken".into(),
            },
            fields: vec![
                AuthFieldSpec {
                    key: "onboarding_mode".into(),
                    label: "Modalità Accesso Telegram (login | bot_token)".into(),
                    placeholder: "bot_token".into(),
                    is_secret: false,
                    required: true,
                    default_value: Some("bot_token".into()),
                },
                AuthFieldSpec {
                    key: "backend_env".into(),
                    label: "Telegram Backend Environment (public | test_dc2)".into(),
                    placeholder: env_slug.into(),
                    is_secret: false,
                    required: true,
                    default_value: Some(env_slug.into()),
                },
                AuthFieldSpec {
                    key: "bot_token".into(),
                    label: "Token Bot Telegram (@BotFather — bot_id:secret)".into(),
                    placeholder: "1234567890:AAHfiqksKZ8WmR2z9pL0xYzExampleBotToken".into(),
                    is_secret: true,
                    required: true,
                    default_value: None,
                },
                AuthFieldSpec {
                    key: "bot_alias".into(),
                    label: "Username / Nome Visualizzato del Bot (opzionale)".into(),
                    placeholder: "@mio_warp_bot".into(),
                    is_secret: false,
                    required: false,
                    default_value: Some("@warp_assistant_bot".into()),
                },
            ],
        }
    }

    /// Produces the declarative **Sign-Up / Account Creation** flow for protocols that allow in-app registration.
    pub fn signup_for(protocol: ProtocolKind) -> Self {
        match protocol {
            ProtocolKind::Telegram => {
                // Telegram restricts SMS phone registration to official mobile apps; fall back to User Login
                Self::telegram_with_backend(false)
            }
            ProtocolKind::Matrix => Self {
                protocol: ProtocolKind::Matrix,
                flow_id: "signup-matrix-cs".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "Matrix — ✨ Registrazione Nuovo Account (Sign-Up)".into(),
                step_description:
                    "Crea un nuovo account Matrix su qualsiasi Homeserver aperto (/_matrix/client/v3/register) con generazione automatica delle chiavi E2EE Olm/Megolm."
                        .into(),
                current_step: AuthStep::AccountRegistration {
                    server_url_default: Some("https://matrix.org".into()),
                    registration_hint: "POST /_matrix/client/v3/register (m.login.dummy / token)".into(),
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "onboarding_mode".into(),
                        label: "Modalità (login | signup)".into(),
                        placeholder: "signup".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("signup".into()),
                    },
                    AuthFieldSpec {
                        key: "homeserver_url".into(),
                        label: "Homeserver URL".into(),
                        placeholder: "https://matrix.org".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("https://matrix.org".into()),
                    },
                    AuthFieldSpec {
                        key: "username".into(),
                        label: "Nuovo Username Matrix (senza dominio)".into(),
                        placeholder: "rubens_warp".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "password".into(),
                        label: "Scegli una Password Sicura".into(),
                        placeholder: "••••••••••••".into(),
                        is_secret: true,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "email".into(),
                        label: "Email di Recupero / Token Invito (opzionale)".into(),
                        placeholder: "user@example.org".into(),
                        is_secret: false,
                        required: false,
                        default_value: None,
                    },
                ],
            },
            ProtocolKind::Xmpp => Self {
                protocol: ProtocolKind::Xmpp,
                flow_id: "signup-xmpp-ibr".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "XMPP (Jabber) — ✨ Registrazione In-Band (XEP-0077)".into(),
                step_description:
                    "Registra un nuovo JID tramite XEP-0077 (jabber:iq:register) su un server XMPP pubblico con creazione automatica del bundle OMEMO."
                        .into(),
                current_step: AuthStep::AccountRegistration {
                    server_url_default: Some("conversations.im".into()),
                    registration_hint: "XEP-0077 In-Band Registration (jabber:iq:register)".into(),
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "onboarding_mode".into(),
                        label: "Modalità (login | signup)".into(),
                        placeholder: "signup".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("signup".into()),
                    },
                    AuthFieldSpec {
                        key: "server_domain".into(),
                        label: "Dominio Server XMPP".into(),
                        placeholder: "conversations.im".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("conversations.im".into()),
                    },
                    AuthFieldSpec {
                        key: "username".into(),
                        label: "Nuovo Username JID".into(),
                        placeholder: "alice_warp".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "password".into(),
                        label: "Scegli una Password SASL".into(),
                        placeholder: "••••••••••••".into(),
                        is_secret: true,
                        required: true,
                        default_value: None,
                    },
                ],
            },
            ProtocolKind::Nostr => Self {
                protocol: ProtocolKind::Nostr,
                flow_id: "signup-nostr-keygen".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "Nostr — ✨ Crea Nuova Identità Crittografica (Sign-Up)".into(),
                step_description:
                    "Genera istantaneamente in locale una nuova coppia di chiavi secp256k1 (npub1 / nsec1) senza bisogno di alcun server centrale e pubblica il profilo Kind 0."
                        .into(),
                current_step: AuthStep::AccountRegistration {
                    server_url_default: Some("wss://relay.damus.io, wss://nos.lol".into()),
                    registration_hint: "Local secp256k1 Keypair Generation + NIP-01 Kind 0 Metadata".into(),
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "onboarding_mode".into(),
                        label: "Modalità (login | signup)".into(),
                        placeholder: "signup".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("signup".into()),
                    },
                    AuthFieldSpec {
                        key: "display_name".into(),
                        label: "Nome Profilo Nostr (Kind 0)".into(),
                        placeholder: "Rubens Nostr".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("Warp Nostr User".into()),
                    },
                    AuthFieldSpec {
                        key: "about".into(),
                        label: "Biografia / NIP-05 (opzionale)".into(),
                        placeholder: "Crittografia decentralizzata con Warp IM".into(),
                        is_secret: false,
                        required: false,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "relays".into(),
                        label: "Relay NIP-17 Predefiniti".into(),
                        placeholder: "wss://relay.damus.io, wss://nos.lol".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("wss://relay.damus.io, wss://nos.lol".into()),
                    },
                ],
            },
            ProtocolKind::SimpleX => Self {
                protocol: ProtocolKind::SimpleX,
                flow_id: "signup-simplex-profile".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "SimpleX Chat — ✨ Crea Nuovo Profilo Locale Anonimo (Sign-Up)".into(),
                step_description:
                    "SimpleX non usa ID utente globali: crea un nuovo profilo locale anonimo e genera automaticamente la tua coda SMP pairwise con chiavi X3DH/Double Ratchet."
                        .into(),
                current_step: AuthStep::AccountRegistration {
                    server_url_default: Some("smp://smp11.simplex.im".into()),
                    registration_hint: "Anonymous Local Profile + Pairwise SMP Queue Allocation".into(),
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "onboarding_mode".into(),
                        label: "Modalità (login | signup)".into(),
                        placeholder: "signup".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("signup".into()),
                    },
                    AuthFieldSpec {
                        key: "display_name".into(),
                        label: "Nome Visualizzato Locale (Alias)".into(),
                        placeholder: "anon_warp".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("anon_warp_user".into()),
                    },
                    AuthFieldSpec {
                        key: "smp_server".into(),
                        label: "Server Relay SMP per Code in Ingresso".into(),
                        placeholder: "smp://smp11.simplex.im".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("smp://smp11.simplex.im".into()),
                    },
                ],
            },
            ProtocolKind::Irc => Self {
                protocol: ProtocolKind::Irc,
                flow_id: "signup-ircv3-acctreg".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "IRCv3 — ✨ Registrazione Account (NickServ / Ergo ACCTREG)".into(),
                step_description:
                    "Registra un nuovo nickname e account SASL sulla rete IRC tramite l'estensione IRCv3 draft/account-registration o NickServ REGISTER."
                        .into(),
                current_step: AuthStep::AccountRegistration {
                    server_url_default: Some("ircs://irc.libera.chat:6697".into()),
                    registration_hint: "IRCv3 draft/account-registration (REGISTER) / NickServ".into(),
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "onboarding_mode".into(),
                        label: "Modalità (login | signup)".into(),
                        placeholder: "signup".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("signup".into()),
                    },
                    AuthFieldSpec {
                        key: "server_url".into(),
                        label: "Server IRCv3 / Ergo / Soju URI".into(),
                        placeholder: "ircs://irc.libera.chat:6697".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("ircs://irc.libera.chat:6697".into()),
                    },
                    AuthFieldSpec {
                        key: "nickname".into(),
                        label: "Nuovo Nickname da Registrare".into(),
                        placeholder: "warp_rustacean".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "password".into(),
                        label: "Password Account NickServ / SASL".into(),
                        placeholder: "••••••••••••".into(),
                        is_secret: true,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "email".into(),
                        label: "Email di Verifica NickServ".into(),
                        placeholder: "user@example.org".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                ],
            },
            ProtocolKind::Stoat => Self {
                protocol: ProtocolKind::Stoat,
                flow_id: "signup-stoat-account".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "Stoat (ex Revolt) — ✨ Registrazione Nuovo Account (Sign-Up)".into(),
                step_description:
                    "Crea un nuovo account su un'istanza Stoat / Revolt tramite POST /auth/account/create."
                        .into(),
                current_step: AuthStep::AccountRegistration {
                    server_url_default: Some("https://api.stoat.chat".into()),
                    registration_hint: "POST /auth/account/create (ULID Identity)".into(),
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "onboarding_mode".into(),
                        label: "Modalità (login | signup)".into(),
                        placeholder: "signup".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("signup".into()),
                    },
                    AuthFieldSpec {
                        key: "server_url".into(),
                        label: "Endpoint API Istanza Stoat".into(),
                        placeholder: "https://api.stoat.chat".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("https://api.stoat.chat".into()),
                    },
                    AuthFieldSpec {
                        key: "username".into(),
                        label: "Nuovo Username Stoat".into(),
                        placeholder: "warp_pilot".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "email".into(),
                        label: "Email di Registrazione".into(),
                        placeholder: "pilot@stoat.chat".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "password".into(),
                        label: "Scegli una Password".into(),
                        placeholder: "••••••••••••".into(),
                        is_secret: true,
                        required: true,
                        default_value: None,
                    },
                ],
            },
            ProtocolKind::Mattermost => Self {
                protocol: ProtocolKind::Mattermost,
                flow_id: "signup-mattermost-v4".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "Mattermost — ✨ Registrazione Utente sul Server (Sign-Up)".into(),
                step_description:
                    "Crea un nuovo account utente su un workspace Mattermost con creazione account abilitata (POST /api/v4/users)."
                        .into(),
                current_step: AuthStep::AccountRegistration {
                    server_url_default: Some("https://chat.acme.corp".into()),
                    registration_hint: "POST /api/v4/users (REST API v4)".into(),
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "onboarding_mode".into(),
                        label: "Modalità (login | signup)".into(),
                        placeholder: "signup".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("signup".into()),
                    },
                    AuthFieldSpec {
                        key: "server_url".into(),
                        label: "URL Server Mattermost".into(),
                        placeholder: "https://chat.acme.corp".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("https://chat.acme.corp".into()),
                    },
                    AuthFieldSpec {
                        key: "username".into(),
                        label: "Nuovo Username".into(),
                        placeholder: "devops_warp".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "email".into(),
                        label: "Email".into(),
                        placeholder: "devops@acme.corp".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "password".into(),
                        label: "Password".into(),
                        placeholder: "••••••••••••".into(),
                        is_secret: true,
                        required: true,
                        default_value: None,
                    },
                ],
            },
            ProtocolKind::Custom(ref slug) => Self {
                protocol: protocol.clone(),
                flow_id: CompactString::from(format!("signup-custom-{}", slug)),
                step_index: 1,
                total_steps: 1,
                step_title: CompactString::from(format!("{} — Registrazione Account", slug)),
                step_description: "Crea un nuovo account sul plugin personalizzato.".into(),
                current_step: AuthStep::AccountRegistration {
                    server_url_default: None,
                    registration_hint: "Custom Plugin Registration".into(),
                },
                fields: vec![AuthFieldSpec {
                    key: "identifier".into(),
                    label: "Nuovo Identificatore".into(),
                    placeholder: "new_user".into(),
                    is_secret: false,
                    required: true,
                    default_value: None,
                }],
            },
        }
    }

    /// Returns the appropriate [`AuthFlowDescriptor`] for a given protocol, [`OnboardingMode`],
    /// and Telegram backend flag (`use_test_dc`).
    pub fn for_protocol_and_mode(
        protocol: ProtocolKind,
        mode: OnboardingMode,
        use_test_dc: bool,
    ) -> Self {
        match (&protocol, mode) {
            (ProtocolKind::Telegram, OnboardingMode::TelegramBotToken) => {
                Self::telegram_bot_with_backend(use_test_dc)
            }
            (ProtocolKind::Telegram, _) => Self::telegram_with_backend(use_test_dc),
            (_, OnboardingMode::SignUp) => Self::signup_for(protocol),
            (_, _) => Self::initial_for(protocol),
        }
    }

    /// Produces the canonical initial onboarding state machine step for each of the 8 protocols.
    pub fn initial_for(protocol: ProtocolKind) -> Self {
        match protocol {
            ProtocolKind::Telegram => Self::telegram_with_backend(false),
            ProtocolKind::Matrix => Self {
                protocol: ProtocolKind::Matrix,
                flow_id: "auth-matrix-cs".into(),
                step_index: 1,
                total_steps: 2,
                step_title: "Matrix Homeserver & E2EE Login".into(),
                step_description:
                    "Connect to any Matrix homeserver with Olm/Megolm cross-signing.".into(),
                current_step: AuthStep::ProvideServerUrl {
                    title: "Matrix Homeserver URL".into(),
                    default_url: Some("https://matrix-client.matrix.org".into()),
                    allow_custom_port: true,
                    tls_default: true,
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "homeserver_url".into(),
                        label: "Homeserver URL".into(),
                        placeholder: "https://matrix.org".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("https://matrix.org".into()),
                    },
                    AuthFieldSpec {
                        key: "username".into(),
                        label: "Matrix ID (@user:domain)".into(),
                        placeholder: "@alice:matrix.org".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "password".into(),
                        label: "Password / Access Token".into(),
                        placeholder: "••••••••••••".into(),
                        is_secret: true,
                        required: true,
                        default_value: None,
                    },
                ],
            },
            ProtocolKind::Xmpp => Self {
                protocol: ProtocolKind::Xmpp,
                flow_id: "auth-xmpp-sasl".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "XMPP (Jabber) + OMEMO Onboarding".into(),
                step_description:
                    "Sign in with your bare JID and SCRAM-SHA-256 password.".into(),
                current_step: AuthStep::UsernamePasswordSasl {
                    identifier_label: "Jabber ID (JID)".into(),
                    identifier_placeholder: "user@conversations.im".into(),
                    requires_server_url: false,
                    default_server_url: None,
                    supports_bouncer_network_tag: false,
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "jid".into(),
                        label: "Jabber ID (JID)".into(),
                        placeholder: "user@conversations.im".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "password".into(),
                        label: "SASL Password".into(),
                        placeholder: "••••••••••••".into(),
                        is_secret: true,
                        required: true,
                        default_value: None,
                    },
                ],
            },
            ProtocolKind::Nostr => Self {
                protocol: ProtocolKind::Nostr,
                flow_id: "auth-nostr-nip17".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "Nostr Keypair & NIP-17 Relays".into(),
                step_description:
                    "Import an existing nsec1 private key or generate an ephemeral identity for NIP-17/NIP-59 Gift-Wrapped DMs."
                        .into(),
                current_step: AuthStep::ImportPrivateKeyNsec {
                    key_format_hint: "nsec1... or 64-char hex secret key".into(),
                    default_relays: vec![
                        "wss://relay.damus.io".into(),
                        "wss://nos.lol".into(),
                        "wss://relay.primal.net".into(),
                    ],
                    allow_generate_new: true,
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "nsec".into(),
                        label: "Secret Key (nsec1 / hex)".into(),
                        placeholder: "nsec1...".into(),
                        is_secret: true,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "relays".into(),
                        label: "NIP-17 Inbox Relays (comma-separated)".into(),
                        placeholder: "wss://relay.damus.io, wss://nos.lol".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("wss://relay.damus.io, wss://nos.lol".into()),
                    },
                ],
            },
            ProtocolKind::SimpleX => Self {
                protocol: ProtocolKind::SimpleX,
                flow_id: "auth-simplex-smp".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "SimpleX Chat Pairwise SMP Queue".into(),
                step_description:
                    "SimpleX has no global user IDs. Scan a contact's QR invite or share your one-time SMP queue link."
                        .into(),
                current_step: AuthStep::ScanOrDisplayQrInvite {
                    mode: QrInviteMode::DisplayOrPasteInvite,
                    qr_payload_uri: "simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2F6iIcWT_dF2zN_w5xzZEY7HI2Prbh3ldP07YTyDexPjE%3D%40smp11.simplex.im".into(),
                    smp_server_hint: "smp://smp11.simplex.im".into(),
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "display_name".into(),
                        label: "Local Profile Alias".into(),
                        placeholder: "anon_cipher".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("warp_simplex_user".into()),
                    },
                    AuthFieldSpec {
                        key: "invite_uri".into(),
                        label: "Contact Invitation Link (simplex:/...)".into(),
                        placeholder: "simplex:/invitation#/?v=2-7&smp=...".into(),
                        is_secret: false,
                        required: false,
                        default_value: None,
                    },
                ],
            },
            ProtocolKind::Irc => Self {
                protocol: ProtocolKind::Irc,
                flow_id: "auth-ircv3-soju".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "IRCv3 + Soju/Ergo Bouncer".into(),
                step_description:
                    "Connect via TLS with SASL PLAIN, chathistory, and message-tags capabilities."
                        .into(),
                current_step: AuthStep::UsernamePasswordSasl {
                    identifier_label: "Nickname / Bouncer User".into(),
                    identifier_placeholder: "warp_nick/libera".into(),
                    requires_server_url: true,
                    default_server_url: Some("ircs://irc.libera.chat:6697".into()),
                    supports_bouncer_network_tag: true,
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "server_url".into(),
                        label: "IRC Server / Soju Bouncer URI".into(),
                        placeholder: "ircs://irc.libera.chat:6697".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("ircs://irc.libera.chat:6697".into()),
                    },
                    AuthFieldSpec {
                        key: "nickname".into(),
                        label: "Nickname / SASL Account".into(),
                        placeholder: "rustacean".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "password".into(),
                        label: "SASL / Bouncer Password".into(),
                        placeholder: "••••••••••••".into(),
                        is_secret: true,
                        required: false,
                        default_value: None,
                    },
                ],
            },
            ProtocolKind::Stoat => Self {
                protocol: ProtocolKind::Stoat,
                flow_id: "auth-stoat-ws".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "Stoat (Revolt) Server & WebSocket Auth".into(),
                step_description:
                    "Authenticate against Stoat REST API and subscribe to Bonfire WebSocket events."
                        .into(),
                current_step: AuthStep::UsernamePasswordSasl {
                    identifier_label: "Email or Session Token".into(),
                    identifier_placeholder: "user@stoat.chat".into(),
                    requires_server_url: true,
                    default_server_url: Some("https://api.stoat.chat".into()),
                    supports_bouncer_network_tag: false,
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "server_url".into(),
                        label: "Stoat API Endpoint".into(),
                        placeholder: "https://api.stoat.chat".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("https://api.stoat.chat".into()),
                    },
                    AuthFieldSpec {
                        key: "identifier".into(),
                        label: "Email or Token".into(),
                        placeholder: "pilot@stoat.chat".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "password".into(),
                        label: "Password".into(),
                        placeholder: "••••••••••••".into(),
                        is_secret: true,
                        required: true,
                        default_value: None,
                    },
                ],
            },
            ProtocolKind::Mattermost => Self {
                protocol: ProtocolKind::Mattermost,
                flow_id: "auth-mattermost-v4".into(),
                step_index: 1,
                total_steps: 1,
                step_title: "Mattermost REST v4 + WebSocket".into(),
                step_description:
                    "Sign in to your Mattermost workspace using credentials or a Personal Access Token."
                        .into(),
                current_step: AuthStep::UsernamePasswordSasl {
                    identifier_label: "Username / Email".into(),
                    identifier_placeholder: "devops@acme.corp".into(),
                    requires_server_url: true,
                    default_server_url: Some("https://chat.acme.corp".into()),
                    supports_bouncer_network_tag: false,
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "server_url".into(),
                        label: "Mattermost Server URL".into(),
                        placeholder: "https://chat.acme.corp".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some("https://chat.acme.corp".into()),
                    },
                    AuthFieldSpec {
                        key: "identifier".into(),
                        label: "Username or Email".into(),
                        placeholder: "devops@acme.corp".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                    AuthFieldSpec {
                        key: "password".into(),
                        label: "Password or Personal Access Token".into(),
                        placeholder: "••••••••••••".into(),
                        is_secret: true,
                        required: true,
                        default_value: None,
                    },
                ],
            },
            ProtocolKind::Custom(ref slug) => Self {
                protocol: protocol.clone(),
                flow_id: CompactString::from(format!("auth-custom-{}", slug)),
                step_index: 1,
                total_steps: 1,
                step_title: CompactString::from(format!("{} Onboarding", slug)),
                step_description: "Configure custom protocol plugin credentials.".into(),
                current_step: AuthStep::UsernamePasswordSasl {
                    identifier_label: "Account Identifier".into(),
                    identifier_placeholder: "user_id".into(),
                    requires_server_url: true,
                    default_server_url: None,
                    supports_bouncer_network_tag: false,
                },
                fields: vec![AuthFieldSpec {
                    key: "identifier".into(),
                    label: "Identifier".into(),
                    placeholder: "user_id".into(),
                    is_secret: false,
                    required: true,
                    default_value: None,
                }],
            },
        }
    }
}
