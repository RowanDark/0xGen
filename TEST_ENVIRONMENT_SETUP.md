# Test Environment Setup for 0xGen Demo Video

This guide provides instructions for setting up vulnerable web applications (DVWA and OWASP Juice Shop) as test targets for the 0xGen demo video.

---

## Table of Contents

1. [Quick Start (Recommended: OWASP Juice Shop)](#quick-start-recommended-owasp-juice-shop)
2. [Option 1: OWASP Juice Shop](#option-1-owasp-juice-shop)
3. [Option 2: DVWA (Damn Vulnerable Web Application)](#option-2-dvwa-damn-vulnerable-web-application)
4. [Browser Proxy Configuration](#browser-proxy-configuration)
5. [SSL/TLS Certificate Setup](#ssltls-certificate-setup)
6. [Test Scenarios](#test-scenarios)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start (Recommended: OWASP Juice Shop)

**Why Juice Shop?**
- Modern UI (looks professional on camera)
- No setup required beyond Docker
- Contains realistic vulnerabilities
- No authentication needed to explore
- Works well with proxy interception

**Launch in 30 seconds:**

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```

**Access at:** [http://localhost:3000](http://localhost:3000)

**Stop when done:**

```bash
docker stop $(docker ps -q --filter ancestor=bkimminich/juice-shop)
```

---

## Option 1: OWASP Juice Shop

### About

OWASP Juice Shop is a modern, intentionally vulnerable web application with:
- 100+ vulnerabilities (XSS, SQL injection, authentication bypass, etc.)
- Professional-looking UI (Angular/TypeScript frontend)
- REST API backend (good for demonstrating API testing)
- Active development and documentation

**Official Repository:** https://github.com/juice-shop/juice-shop

### Installation Methods

#### Method 1: Docker (Recommended)

**Prerequisites:**
- Docker installed ([get Docker](https://docs.docker.com/get-docker/))

**Launch Juice Shop:**

```bash
# Pull and run latest version
docker run -d -p 3000:3000 bkimminich/juice-shop

# Verify it's running
docker ps

# View logs (optional)
docker logs $(docker ps -q --filter ancestor=bkimminich/juice-shop)
```

**Access:** http://localhost:3000

**Stop:**

```bash
docker stop $(docker ps -q --filter ancestor=bkimminich/juice-shop)
```

**Remove container:**

```bash
docker rm $(docker ps -aq --filter ancestor=bkimminich/juice-shop)
```

#### Method 2: Node.js (Alternative)

**Prerequisites:**
- Node.js 18+ ([download](https://nodejs.org/))
- Git

**Installation:**

```bash
# Clone repository
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop

# Install dependencies
npm install

# Start application
npm start
```

**Access:** http://localhost:3000

**Stop:** Press `Ctrl+C` in terminal

#### Method 3: Prebuilt Binaries

**Download from releases:**
- [GitHub Releases](https://github.com/juice-shop/juice-shop/releases)
- Available for Windows, macOS, Linux

**Run executable:**

```bash
# macOS/Linux
chmod +x juice-shop-*.run
./juice-shop-*.run

# Windows
juice-shop-*.exe
```

### Juice Shop Features for Demo

**Recommended Scenarios:**

1. **SQL Injection (High Severity)**
   - URL: http://localhost:3000/#/login
   - Payload: `admin'--` in email field
   - Shows authentication bypass

2. **XSS (Cross-Site Scripting)**
   - URL: http://localhost:3000/#/search
   - Payload: `<script>alert('XSS')</script>`
   - Shows reflected XSS

3. **Broken Access Control**
   - URL: http://localhost:3000/rest/user/authentication-details
   - Shows unauthorized API access

4. **API Endpoint Discovery**
   - Browse through proxy to discover:
     - `/api/Products`
     - `/api/Users`
     - `/rest/basket/`

**Admin Credentials (for scenarios requiring login):**
- Email: `admin@juice-sh.op`
- Password: `admin123`

### Configuration

**Port Change (if 3000 is in use):**

```bash
docker run -d -p 4000:3000 bkimminich/juice-shop
```

Access at: http://localhost:4000

**Persistent Data:**

```bash
docker run -d -p 3000:3000 \
  -v $(pwd)/juice-shop-data:/juice-shop/data \
  bkimminich/juice-shop
```

---

## Option 2: DVWA (Damn Vulnerable Web Application)

### About

DVWA is a PHP/MySQL web application containing common vulnerabilities:
- SQL injection, XSS, CSRF, file upload, command injection
- Adjustable security levels (low, medium, high, impossible)
- Classic LAMP stack (good for traditional web app testing)
- Simple UI (less modern than Juice Shop)

**Official Website:** https://github.com/digininja/DVWA

### Installation Methods

#### Method 1: Docker (Recommended)

**Launch DVWA:**

```bash
docker run -d -p 8080:80 vulnerables/web-dvwa
```

**Access:** http://localhost:8080

**Default Credentials:**
- Username: `admin`
- Password: `password`

**First-time Setup:**
1. Navigate to http://localhost:8080
2. Click "Create / Reset Database" button at bottom
3. Login with admin/password
4. Set security level: DVWA Security → Low (easiest to demonstrate)

**Stop:**

```bash
docker stop $(docker ps -q --filter ancestor=vulnerables/web-dvwa)
```

#### Method 2: Manual Installation (LAMP Stack)

**Prerequisites:**
- Apache web server
- PHP 7.x or 8.x
- MySQL/MariaDB
- Git

**Installation Steps:**

```bash
# Clone repository
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git

# Set permissions
sudo chown -R www-data:www-data DVWA
sudo chmod -R 755 DVWA

# Configure database
cd DVWA/config
sudo cp config.inc.php.dist config.inc.php

# Edit config.inc.php to set MySQL credentials
sudo nano config.inc.php
# Update:
# $_DVWA['db_user'] = 'root';
# $_DVWA['db_password'] = 'your_mysql_password';

# Restart Apache
sudo systemctl restart apache2
```

**Access:** http://localhost/DVWA

**Setup Database:**
1. Navigate to http://localhost/DVWA/setup.php
2. Click "Create / Reset Database"
3. Login with admin/password

### DVWA Features for Demo

**Recommended Scenarios:**

1. **SQL Injection (Highest visibility)**
   - Navigate to: DVWA Security → Set to "Low"
   - Go to: SQL Injection page
   - Input: `1' OR '1'='1`
   - Shows all user data

2. **Command Injection**
   - Page: Command Injection
   - Input: `127.0.0.1; ls -la`
   - Shows arbitrary command execution

3. **File Upload Vulnerability**
   - Page: File Upload
   - Upload PHP shell disguised as image
   - Demonstrates remote code execution risk

4. **XSS (Reflected)**
   - Page: XSS (Reflected)
   - Input: `<script>alert('XSS')</script>`
   - Shows client-side injection

**Security Levels:**
- **Low:** No security (best for demo)
- **Medium:** Some protection (still bypassable)
- **High:** Strong protection (harder to exploit)
- **Impossible:** Secure implementation (reference)

### Configuration

**Port Change:**

```bash
docker run -d -p 9090:80 vulnerables/web-dvwa
```

Access at: http://localhost:9090

**Persistent Database:**

```bash
docker run -d -p 8080:80 \
  -v $(pwd)/dvwa-data:/var/lib/mysql \
  vulnerables/web-dvwa
```

---

## Browser Proxy Configuration

Configure your browser to route traffic through 0xGen's proxy (default: `127.0.0.1:8080`).

### Firefox (Recommended for Demos)

**Why Firefox?**
- Easy proxy configuration
- Built-in certificate management
- Doesn't affect system-wide settings

**Steps:**

1. Open Firefox
2. Click menu (☰) → **Settings**
3. Scroll to **Network Settings** → Click **Settings...**
4. Select **Manual proxy configuration**
5. Enter:
   - HTTP Proxy: `127.0.0.1`
   - Port: `8080`
   - Check: "Also use this proxy for HTTPS"
6. Clear "No proxy for:" (optional, for intercepting localhost)
7. Click **OK**

**Verify:**
- Start 0xGen proxy in Flows panel
- Navigate to http://example.com
- Request should appear in 0xGen Flows

**Disable Proxy:**
- Network Settings → **No proxy**

### Chrome/Chromium

**Note:** Chrome uses system proxy settings on most platforms.

**macOS:**

```bash
# Set proxy (run in terminal)
networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8080
networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8080

# Disable proxy when done
networksetup -setwebproxystate "Wi-Fi" off
networksetup -setsecurewebproxystate "Wi-Fi" off
```

**Windows:**

1. Settings → Network & Internet → Proxy
2. Manual proxy setup → Enable
3. Address: `127.0.0.1`, Port: `8080`
4. Save

**Linux:**

```bash
# Set environment variables
export http_proxy="http://127.0.0.1:8080"
export https_proxy="http://127.0.0.1:8080"

# Launch Chrome
google-chrome --proxy-server="http://127.0.0.1:8080"

# Or use system settings (GNOME)
gsettings set org.gnome.system.proxy mode 'manual'
gsettings set org.gnome.system.proxy.http host '127.0.0.1'
gsettings set org.gnome.system.proxy.http port 8080
```

**Disable:**

```bash
# Unset environment variables
unset http_proxy https_proxy

# Or system settings (GNOME)
gsettings set org.gnome.system.proxy mode 'none'
```

### Browser Extensions (Alternative)

**FoxyProxy (Firefox/Chrome):**
- Install: [FoxyProxy](https://getfoxyproxy.org/)
- Create profile: "0xGen Proxy"
- Host: `127.0.0.1`, Port: `8080`
- Enable/disable with one click

---

## SSL/TLS Certificate Setup

To intercept HTTPS traffic, you need to install and trust 0xGen's certificate authority (CA).

### Generate CA Certificate (0xGen)

**In 0xGen GUI:**

1. Navigate to **Flows** panel
2. Click **Certificate** or **Settings** button
3. Click **Generate CA Certificate**
4. Click **Export CA Certificate**
5. Save as: `0xgen-ca.crt` (or `0xgen-ca.pem`)

**Or via CLI (if available):**

```bash
0xgenctl proxy generate-ca --output ~/.0xgen/ca.crt
```

### Install & Trust Certificate

#### macOS

```bash
# Add to keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.0xgen/ca.crt
```

**Or via GUI:**
1. Double-click `0xgen-ca.crt`
2. Keychain Access opens
3. Find certificate → Double-click
4. Expand **Trust** section
5. Set "When using this certificate" to **Always Trust**
6. Close and enter password

#### Windows

```powershell
# Import certificate (PowerShell as Administrator)
Import-Certificate -FilePath "$env:USERPROFILE\.0xgen\ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

**Or via GUI:**
1. Double-click `0xgen-ca.crt`
2. Click **Install Certificate...**
3. Store Location: **Local Machine**
4. Certificate Store: **Trusted Root Certification Authorities**
5. Click **Finish**

#### Linux (Ubuntu/Debian)

```bash
# Copy certificate
sudo cp ~/.0xgen/ca.crt /usr/local/share/ca-certificates/0xgen-ca.crt

# Update certificate store
sudo update-ca-certificates
```

#### Firefox (Application-specific)

1. Firefox → **Settings**
2. Search: **Certificates**
3. Click **View Certificates...**
4. **Authorities** tab
5. Click **Import...**
6. Select `0xgen-ca.crt`
7. Check: "Trust this CA to identify websites"
8. Click **OK**

### Verify HTTPS Interception

1. Start 0xGen proxy
2. Configure browser proxy
3. Navigate to: https://example.com
4. In 0xGen Flows panel, you should see:
   - CONNECT request to example.com:443
   - GET request to https://example.com (decrypted content)

**If not working:**
- Check certificate is trusted (no browser warnings)
- Verify proxy is running and listening on correct port
- Check browser proxy settings
- Restart browser after certificate installation

---

## Test Scenarios

### Scenario 1: SQL Injection (Juice Shop)

**Demonstration:**

1. Navigate to: http://localhost:3000/#/login
2. Enter in email field: `admin'--`
3. Enter any password
4. Intercept request in 0xGen
5. Show modified SQL query in explanation
6. Forward request → Login successful (authentication bypass)

**Expected Findings:**
- SQL Injection vulnerability
- Authentication bypass
- Severity: High
- CVSS: 8.0+

### Scenario 2: XSS (DVWA)

**Demonstration:**

1. Navigate to: DVWA → XSS (Reflected)
2. Enter: `<script>alert('XSS')</script>`
3. Intercept request in 0xGen
4. Show payload in request parameters
5. Forward request → Alert appears
6. Scan with Hydra → XSS finding

**Expected Findings:**
- Reflected XSS
- Severity: Medium
- CVSS: 6.1

### Scenario 3: API Enumeration (Juice Shop)

**Demonstration:**

1. Browse Juice Shop homepage
2. Open 0xGen Flows panel
3. Show captured API requests:
   - GET `/api/Products`
   - GET `/rest/basket/4`
   - GET `/rest/user/whoami`
4. Right-click → "Scan with Hydra"
5. Show findings: Broken access control, information disclosure

**Expected Findings:**
- Information Disclosure
- Broken Access Control
- Severity: Low-Medium

---

## Troubleshooting

### Issue: Docker container won't start

**Solution:**

```bash
# Check if port is already in use
lsof -i :3000    # macOS/Linux
netstat -ano | findstr :3000    # Windows

# Use different port
docker run -d -p 3001:3000 bkimminich/juice-shop
```

### Issue: Browser shows "Connection Refused"

**Causes:**
- Container not running
- Wrong port
- Firewall blocking localhost

**Solution:**

```bash
# Verify container is running
docker ps

# Check container logs
docker logs [container-id]

# Restart container
docker restart [container-id]
```

### Issue: HTTPS sites show certificate warnings

**Causes:**
- CA certificate not installed
- Certificate not trusted
- Browser using different certificate store (Firefox)

**Solution:**
- Reinstall CA certificate
- Restart browser after installation
- For Firefox: Import certificate specifically into Firefox (see above)

### Issue: Proxy not intercepting localhost requests

**Cause:**
- Browser bypasses proxy for localhost by default

**Solution (Firefox):**

1. Type in address bar: `about:config`
2. Accept warning
3. Search: `network.proxy.allow_hijacking_localhost`
4. Set to: `true`
5. Restart Firefox

**Solution (Chrome):**

```bash
# Launch with flag
google-chrome --proxy-bypass-list="" --proxy-server="http://127.0.0.1:8080"
```

### Issue: 0xGen proxy won't start

**Causes:**
- Port 8080 already in use
- Permission denied

**Solution:**

```bash
# Check what's using port 8080
lsof -i :8080    # macOS/Linux
netstat -ano | findstr :8080    # Windows

# Kill process or use different port in 0xGen settings
```

---

## Cleanup

### Stop All Containers

```bash
# Stop Juice Shop
docker stop $(docker ps -q --filter ancestor=bkimminich/juice-shop)

# Stop DVWA
docker stop $(docker ps -q --filter ancestor=vulnerables/web-dvwa)

# Remove all stopped containers
docker container prune -f
```

### Remove CA Certificate

**macOS:**

```bash
sudo security delete-certificate -c "0xGen CA" /Library/Keychains/System.keychain
```

**Windows (PowerShell as Admin):**

```powershell
Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -match "0xGen"} | Remove-Item
```

**Linux:**

```bash
sudo rm /usr/local/share/ca-certificates/0xgen-ca.crt
sudo update-ca-certificates --fresh
```

**Firefox:**

1. Firefox → Settings → Certificates → View Certificates
2. Authorities tab
3. Find "0xGen CA"
4. Click Delete or Distrust

### Reset Browser Proxy

**Firefox:**
- Network Settings → **No proxy**

**Chrome/System:**
- Disable proxy in system settings (see Browser Proxy Configuration sections above)

---

## Additional Resources

### Official Documentation

- **OWASP Juice Shop:** https://pwning.owasp-juice.shop/
- **DVWA:** https://github.com/digininja/DVWA/blob/master/README.md
- **Docker:** https://docs.docker.com/

### Alternative Test Targets

- **WebGoat:** https://github.com/WebGoat/WebGoat (OWASP educational platform)
- **Mutillidae:** https://github.com/webpwnized/mutillidae (OWASP vulnerable web app)
- **bWAPP:** http://www.itsecgames.com/ (Buggy Web Application)
- **Hack The Box Academy:** https://academy.hackthebox.com/ (online labs)

### Learning Resources

- **PortSwigger Web Security Academy:** https://portswigger.net/web-security
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **Burp Suite Documentation:** https://portswigger.net/burp/documentation

---

## Quick Reference

### Commands Cheat Sheet

```bash
# Launch Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# Launch DVWA
docker run -d -p 8080:80 vulnerables/web-dvwa

# Check running containers
docker ps

# View container logs
docker logs [container-id]

# Stop container
docker stop [container-id]

# Start 0xGen daemon
0xgenctl daemon start

# Launch desktop shell
cd apps/desktop-shell && pnpm tauri:dev

# Check proxy port in use
lsof -i :8080    # macOS/Linux
netstat -ano | findstr :8080    # Windows
```

### Default Credentials

| Application | URL | Username | Password |
|-------------|-----|----------|----------|
| Juice Shop | http://localhost:3000 | admin@juice-sh.op | admin123 |
| DVWA | http://localhost:8080 | admin | password |

### Default Ports

| Service | Port |
|---------|------|
| Juice Shop | 3000 |
| DVWA | 8080 (Docker), 80 (manual) |
| 0xGen Proxy | 8080 (default, configurable) |
| 0xGen API | 8713 (default) |

---

**Document Version:** 1.0
**Last Updated:** 2025-11-13
**Related Files:** `DEMO_VIDEO_PRODUCTION_GUIDE.md`, `DEMO_VIDEO_SCRIPT.md`
