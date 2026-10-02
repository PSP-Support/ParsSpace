# 🏛️ Pars Space

> **A modern Persian-first panel for managing users, configurations, subscriptions and server services.**

<p align="center">
  <strong>🖤 Minimal · ⚡ Fast · 🧊 Liquid Glass · 🌍 RTL / LTR</strong>
</p>

---

## 🖼️ Dashboard Review

Pars Space is designed around a clean dashboard instead of throwing every possible control at the user at once. The main screen focuses on the information that matters first:

```text
┌─────────────────────────────────────────────────────────────────────┐
│  🏛️ Pars Space                         🌙 Theme   🇮🇷 FA   ⚙ Settings │
├───────────────────┬─────────────────────────────────────────────────┤
│                   │                                                 │
│  🏠 Dashboard     │   📊 Server Overview                            │
│  👤 Users         │                                                 │
│  ⚙️ Inbounds      │   ┌─────────┐ ┌─────────┐ ┌─────────┐          │
│  🔎 Scanner       │   │ Users   │ │ Active  │ │ Traffic │          │
│  ⚡ Speed Test    │   │   128   │ │   24    │ │ 42.8 GB │          │
│  ⚙️ Settings      │   └─────────┘ └─────────┘ └─────────┘          │
│                   │                                                 │
│                   │   📈 Live Traffic                               │
│                   │   ─────╮      ╭──────╮      ╭──────             │
│                   │         ╰────╯        ╰────╯                    │
│                   │                                                 │
│                   │   🟢 Server Online     ⚡ Average Connections  │
│                   │                                                 │
└───────────────────┴─────────────────────────────────────────────────┘
```

### 🎨 UI highlights

- 🧊 **Liquid Glass cards** with readable contrast
- 🌙 **Dark / Light themes**
- 📱 Responsive layout for phones
- 🖥️ Desktop-friendly navigation
- ✨ Smooth micro-animations
- 🌐 Full **RTL / LTR** support
- 📊 Live traffic and server statistics
- 🔐 User-specific subscription management

> **Note:** This README review describes the current dashboard structure. For an actual screenshot, place a real capture of the current `index.html` at `docs/dashboard-preview.png` and uncomment the image below.

<!--
![Pars Space Dashboard](./docs/dashboard-preview.png)
-->

---

# ✨ Features

## 👥 User Management

Manage users from a dedicated, clean interface:

- ➕ Create user
- ✏️ Edit user
- 🔄 Enable / disable account
- 🗑️ Delete user
- ♻️ Reset traffic
- 📊 View traffic usage
- ⏳ Configure expiry
- 🔗 Generate personal subscription link
- 📱 Generate QR code
- 📋 Copy generated configuration

The normal Users view stays focused on the user list. Creation and configuration are opened through a dedicated action instead of filling the screen with forms.

---

## ⚙️ Inbound Management

Create and edit inbound configurations without rebuilding the entire panel.

Supported protocol families include:

- 🔹 VLESS
- 🔹 VMess
- 🔹 Trojan
- 🔐 Reality
- 🔒 TLS where a valid certificate is available

Inbound editing can be used to change the stored settings of an existing inbound instead of deleting and recreating it.

---

## 🔗 Personal Subscription

Each user can have a personal subscription URL.

The subscription page can expose:

- User information
- Subscription status
- Traffic usage
- Expiry
- Connection profiles
- QR code
- Copy actions

Long configuration strings are kept inside scrollable/wrapped containers so they do not break the layout on mobile.

---

# 📊 Live Dashboard

The dashboard can display:

- 👤 Total users
- 🟢 Active users
- 🔌 Active connections
- 📦 Traffic usage
- 🖥️ CPU / RAM / disk information where available
- ⏱️ Uptime
- 📈 Traffic history

Traffic views can be grouped by:

- ⏱️ Last hour
- 📅 Last day
- 🗓️ Last week
- 📆 Last month

The dashboard is intended to show both the current state and a short history rather than a pile of static numbers. Humanity has suffered enough dashboards that only say "Online".

---

# ⚡ Speed Test

The Speed Test page provides a visual representation of connection testing, with special focus on:

- ⬇️ Download speed
- ⬆️ Upload speed
- 📡 Latency
- 🟢 Connection status

The download section is presented as a graphical meter so the result is easier to understand at a glance.

---

# 🔎 Scanner

Pars Space includes scanner tools for authorized network testing.

The SNI scanner can work with a custom SNI list.

Example file:

```text
data/sni_reality_for_scan.txt
```

Put one hostname on each line:

```text
example.com
www.example.com
your-authorized-host.example
```

Comments can start with `#`.

> ⚠️ Only scan hosts and infrastructure you own or are explicitly authorized to test.

---

# 🔐 Secret Key

Pars Space can use a strong secret key for signing/session or other application security settings.

## 🐍 Method 1: Python

The recommended simple method:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Example output:

```text
N9m2Qv...your-generated-secret...xK8
```

Copy the generated value into your environment configuration:

```env
SECRET_KEY=PASTE_GENERATED_VALUE_HERE
```

### Windows

The same command works from **CMD** if Python is installed:

```cmd
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## 💻 Method 2: OpenSSL from CMD

If OpenSSL is installed:

```cmd
openssl rand -hex 48
```

or:

```cmd
openssl rand -base64 48
```

Then:

```env
SECRET_KEY=PASTE_GENERATED_VALUE_HERE
```

### Check that OpenSSL exists

```cmd
openssl version
```

If CMD says that `openssl` is not recognized, use the Python method above. It is simpler and does not require another dependency.

---

## 🔒 Important

Never commit a real secret key to GitHub.

Do **not** put this inside:

```text
main.py
README.md
GitHub source code
public configuration files
```

Use environment variables instead.

For example:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-strong-password
SECRET_KEY=your-generated-secret
```

And add `.env` to `.gitignore`:

```gitignore
.env
*.env
```

---

# 🛠️ Installation

## 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/ParsSpace.git
cd ParsSpace
```

## 2. Create a virtual environment

### Windows

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

# ⚙️ Configuration

Create an environment file or configure environment variables through your hosting provider.

Example:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=CHANGE_THIS_PASSWORD
SECRET_KEY=GENERATE_A_REAL_SECRET
```

Use a strong unique password.

---

# ▶️ Running Locally

Start the application:

```bash
python main.py
```

Or run it through Uvicorn when the project is configured for it:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Then open:

```text
http://127.0.0.1:8000
```

If you use a different port, replace `8000` with your configured port.

---

# ☁️ Deploy on Railway

A typical Railway workflow:

### 1. Push the project to GitHub

```bash
git add .
git commit -m "Initial Pars Space deployment"
git push
```

### 2. Create a Railway project

Create a new project and connect your GitHub repository.

### 3. Add environment variables

In Railway, configure:

```text
ADMIN_USERNAME
ADMIN_PASSWORD
SECRET_KEY
```

Add any other variables required by your deployment configuration.

### 4. Deploy

Railway will build and start the application according to the project's deployment configuration.

---

# 🧩 How Pars Space Works

At a high level:

```text
                    ┌──────────────────┐
                    │    Pars Space    │
                    │      Panel       │
                    └────────┬─────────┘
                             │
             ┌───────────────┼────────────────┐
             │               │                │
             ▼               ▼                ▼
        👥 Users        ⚙️ Inbounds       📊 Dashboard
             │               │                │
             └───────────────┼────────────────┘
                             ▼
                    🔗 User Subscription
                             │
                             ▼
                    📱 Client Configuration
```

The panel manages the application state and configuration data, while generated user links expose only the information intended for that user.

---

# 🌐 Protocols

The panel is designed around common Xray-compatible configuration concepts.

### VLESS

Lightweight modern protocol configuration with support for security/transport options where configured.

### VMess

UUID-based user authentication with protocol-specific share links.

### Trojan

Password-based protocol configuration with its own credential handling.

### Reality

Reality settings can be attached to supported inbound configurations.

> ⚠️ Actual connectivity depends on the server's Xray runtime, ports, DNS, transport settings, certificates where required, and the deployment environment. Generating a configuration is not the same thing as proving that a remote network connection works.

---

# 🎨 Themes

Pars Space includes:

### 🌑 Dark

Designed around deep surfaces, readable text, subtle glow and glass layers.

### ☀️ Light

Uses softer surfaces and stronger text contrast so the interface remains readable instead of becoming a white rectangle with tiny gray writing pretending to be a UI.

### 🖥️ System

Can follow the operating system preference when supported by the interface.

---

# 🌍 Language & Direction

Supported interface directions:

```text
🇮🇷 فارسی  → RTL
🇺🇸 English → LTR
```

Text direction is handled independently so buttons, forms, tables and cards remain readable in both languages.

---

# 📂 Project Structure

A typical project layout:

```text
ParsSpace/
│
├── main.py
├── requirements.txt
├── Dockerfile
├── Procfile
├── railway.json
│
├── static/
│   ├── index.html
│   ├── login.html
│   └── sub.html
│
├── data/
│   └── sni_reality_for_scan.txt
│
└── README.md
```

The exact structure may vary between releases.

---

# 🔒 Security Checklist

Before making the panel public:

- [ ] Change the default admin credentials
- [ ] Generate a unique `SECRET_KEY`
- [ ] Never commit `.env`
- [ ] Use HTTPS in production
- [ ] Keep server dependencies updated
- [ ] Restrict access to administrative endpoints
- [ ] Only use scanner features against authorized targets
- [ ] Do not expose private keys or tokens in GitHub

---

# 🧪 Development

For development changes:

```bash
git checkout -b feature/my-change
```

Make your changes, test locally, then:

```bash
git add .
git commit -m "Add my change"
git push origin feature/my-change
```

---

# 📜 License

Add the project's license here, for example:

```text
MIT License
```

Only use a license that actually matches the legal terms you want to apply to the project.

---

# ❤️ Pars Space

Built around a simple idea:

> **A powerful control panel does not need to look complicated.**

🏛️ Persian-inspired identity  
🧊 Modern Liquid Glass interface  
⚡ Fast workflow  
📱 Mobile-first usability  
🔐 Security-conscious configuration

---

<p align="center">

**Pars Space · Modern infrastructure management**

⭐ Star the repository if you find it useful.

</p>
