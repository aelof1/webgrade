# webgrade

Website security checker. It analyses a site's **HTTP headers**, **cookies** and **TLS certificate**, then gives a grade from **A to F** with the fix to apply for each point.

It only sends normal requests (like a browser). It is **not** an attack scanner: you can use it on any public website.

## Why I built this

Lots of websites miss simple protections that only take one line of configuration: HSTS, CSP, clickjacking protection… Services like Mozilla Observatory or securityheaders.com do this online. I wanted to understand what each header is for, and have a command-line tool I can use in a script or in CI.

## Checks

| Check | Why it matters | Points lost if missing |
|---|---|---|
| HTTPS | without encryption, everything travels in clear text | 40 |
| Valid certificate, not about to expire | an expired certificate blocks visitors | 10 to 20 |
| TLS version (1.2 or 1.3) | TLS 1.0 and 1.1 are obsolete and vulnerable | 20 |
| HTTP to HTTPS redirect | otherwise visitors can stay on the unencrypted version | 10 |
| `Strict-Transport-Security` (HSTS) | forces the browser to always use HTTPS | 15 |
| `Content-Security-Policy` (CSP) | greatly reduces XSS attacks | 20 (5 if too permissive) |
| `X-Frame-Options` or `frame-ancestors` | prevents clickjacking | 10 |
| `X-Content-Type-Options: nosniff` | stops the browser from guessing file types | 5 |
| `Referrer-Policy` | avoids leaking URLs to other sites | 5 |
| `Permissions-Policy` | turns off camera, microphone, geolocation when not needed | 5 |
| No version disclosure | `Server: Apache/2.4.29` or `X-Powered-By: PHP/7.2` help an attacker | 5 |
| Cookies with `Secure`, `HttpOnly`, `SameSite` | protects sessions against theft and CSRF | 5 per cookie |

Grade: **A** ≥ 90, **B** ≥ 75, **C** ≥ 60, **D** ≥ 45, **E** ≥ 30, otherwise **F**.

## Compatibility

| System | Works? |
|---|---|
| Linux (all distributions) | Yes |
| macOS | Yes |
| Windows 10 / 11 | Yes |

## Requirements

- **Python 3.9 or newer**
- An Internet connection (for public websites)
- No external libraries

> **macOS**: if you get a certificate error with the python.org Python, run the *Install Certificates.command* script once; it's in the `/Applications/Python 3.x/` folder.

## Installation

### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv pipx git ca-certificates
git clone https://github.com/aelof1/webgrade.git
cd webgrade
pipx install .
```

### Fedora

```bash
sudo dnf install -y python3 pipx git ca-certificates
```

### macOS

```bash
brew install python pipx git
```

### Windows

Install [Python](https://www.python.org/downloads/) (tick "Add python.exe to PATH"), then in the project folder: `pip install .`

## Usage

```bash
webgrade example.com                    # https:// is added automatically
webgrade https://site1.com https://site2.com
webgrade http://192.168.1.10:8080       # internal site over HTTP
webgrade example.com --json             # JSON output
```

### Example output

For a badly configured site:

```
http://127.0.0.1:8080/  (HTTP 200)
  ✘ HTTPS                        site served over plain HTTP
      -> Enable HTTPS (Let's Encrypt is free)
  ✘ Content-Security-Policy      missing
      -> Define a CSP, e.g. default-src 'self' (start with Content-Security-Policy-Report-Only)
  ✔ Clickjacking protection      X-Frame-Options: DENY
  ✘ X-Content-Type-Options       missing
      -> Add: X-Content-Type-Options: nosniff
  ✘ No version disclosure        Server: Apache/2.4.29
      -> Hide versions (nginx: server_tokens off; PHP: expose_php = Off)
  ✘ Cookie 'PHPSESSID'           no HttpOnly, no SameSite
      -> Set the cookie with: Secure; HttpOnly; SameSite=Lax
  ...
  Score 15/100   Grade F
```

## Fixing the problems (Nginx example)

```nginx
server_tokens off;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

Careful: a CSP that is too strict can break a site (external scripts, fonts…). Test it first with `Content-Security-Policy-Report-Only`.

## Project layout

```
webgrade/
├── webgrade/
│   ├── checks.py   # analysis of headers, cookies, certificate (no network)
│   ├── fetch.py    # HTTP requests and TLS connection
│   └── cli.py
└── tests/          # unit tests + a tiny local web server
```

The analysis is kept separate from the network requests, so all the logic can be tested without Internet.

## Tests

```bash
pip install pytest
python3 -m pytest
```

## Limitations

- Only the requested page is analysed (no crawling).
- No testing of cipher suites or TLS vulnerabilities (for that: `testssl.sh` or SSL Labs).
- Cookies set by JavaScript are not visible.

## License

MIT
