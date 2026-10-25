# SecureScan — Automated Website Security Checker

A beginner-friendly Python web application that checks publicly accessible websites
for common HTTP security-header configurations and generates a downloadable report.

Built for the **IBM SkillsBuild National Cybersecurity Bootcamp**.

---

## ⚠️ Responsible Use

> **Only scan websites you own or have explicit written permission to test.**
> Scanning third-party websites without permission may violate computer-access laws
> and terms of service.
>
> SecureScan performs only ordinary HTTP GET requests. It does **not** exploit
> vulnerabilities, brute-force logins, perform port scans, or collect personal data.
> This tool is for educational and defensive security awareness purposes only.
> Results do **not** replace a professional security audit.

---

## Features

| Feature | Details |
|---|---|
| HTTPS check | Verifies the final connection uses HTTPS |
| Strict-Transport-Security | Checks HSTS header presence |
| Content-Security-Policy | Checks CSP header presence |
| X-Content-Type-Options | Checks presence and `nosniff` value |
| X-Frame-Options | Checks header presence |
| Referrer-Policy | Checks header presence |
| Permissions-Policy | Checks header presence |
| HTTP status | Displays the server response code |
| Redirect detection | Shows the final URL and redirect path |
| Recommendations | Short guidance for each missing/misconfigured header |
| CSV download | Machine-readable report |
| Text download | Human-readable report |

---

## Project Structure

```
SecureScan/
├── app.py               # Streamlit user interface
├── scanner.py           # Security-checking logic
├── report_generator.py  # CSV and text report generation
├── requirements.txt     # Python dependencies
├── README.md            # This file
├── .gitignore           # Files excluded from version control
└── tests/
    └── test_scanner.py  # Unit tests (no network required)
```

---

## Requirements

- **Python 3.10 or later** (type-hint syntax used)
- Internet connection (for scanning public websites)

---

## Setup and Installation

### 1 — Clone or download the project

```bash
git clone <your-repo-url>
cd SecureScan
```

Or simply place the project folder wherever you like and open a terminal there.

### 2 — Create a virtual environment (recommended)

```bash
python -m venv venv
```

Activate it:

- **Windows (PowerShell):** `.\venv\Scripts\Activate.ps1`
- **Windows (Command Prompt):** `venv\Scripts\activate.bat`
- **macOS / Linux:** `source venv/bin/activate`

### 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### 4 — Run the application

```bash
streamlit run app.py
```

Streamlit will open the application automatically in your default browser at
`http://localhost:8501`.

---

## How to Use

1. Open the application in your browser.
2. Read the responsible-use notice.
3. Enter a public URL you own or have permission to test (e.g. `https://example.com`).
4. Click **Scan Website**.
5. Review the findings dashboard and per-header results.
6. Download a CSV or plain-text report if needed.

---

## Running the Tests

No internet connection is required for the tests — they use mock data only.

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## Limitations

- Checks only HTTP response headers visible in the initial GET response.
- Does not analyse HTML content, JavaScript, cookies, or server-side configuration.
- Cannot detect all classes of vulnerability.
- Results reflect one point in time; configurations can change.
- Some websites return different headers to automated requests than to browsers.
- A `WARNING` does not confirm a vulnerability exists.
- A `PASS` does not confirm the website is secure.

---

## Security Checks Reference

| Header | Purpose |
|---|---|
| `Strict-Transport-Security` | Instructs browsers to use HTTPS only |
| `Content-Security-Policy` | Controls resources the browser may load |
| `X-Content-Type-Options` | Prevents MIME-type sniffing |
| `X-Frame-Options` | Controls whether the page can be embedded in a frame |
| `Referrer-Policy` | Controls how much referrer information is sent |
| `Permissions-Policy` | Controls browser feature access (camera, mic, etc.) |

Reference: [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

---

## Files to Submit

For the bootcamp submission, include all files in the `SecureScan/` folder:

```
app.py
scanner.py
report_generator.py
requirements.txt
README.md
.gitignore
tests/test_scanner.py
```

---

## Submission Checklist

- [ ] All five Python files are present and complete
- [ ] `requirements.txt` lists all dependencies
- [ ] `README.md` explains setup, features, and limitations
- [ ] Application starts with `streamlit run app.py`
- [ ] Tests pass with `python -m pytest tests/ -v`
- [ ] Responsible-use notice is visible in the application
- [ ] Disclaimer is shown in the results dashboard
- [ ] No API keys, passwords, or personal data committed
- [ ] `.gitignore` excludes `venv/`, `__pycache__/`, and `.env`

---

## License

This project was created for educational purposes as part of the IBM SkillsBuild
National Cybersecurity Bootcamp. Reuse is permitted for personal learning only.
