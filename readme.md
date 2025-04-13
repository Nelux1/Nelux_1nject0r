# Nelux 1nject0r

Nelux 1nject0r is an offensive Python tool designed to detect potential **XSS** and **SQL Injection** vulnerabilities. It performs crawling, Wayback Machine scraping, and fuzzing with special characters to discover exploitable parameters.

---

## Features

- 🔍 Extracts parameterized URLs using **Wayback Machine** and **site crawling**.
- ⚔️ Tests for injections using special characters (`<`, `>`, `"`, `'`, `;`, `--`, etc.).
- 🧠 Removes duplicate parameters (same domain + same parameter name).
- 🚫 Skips URLs that auto-redirect, as they can't be reliably tested.
- 📂 Outputs organized results for further analysis.

---

## Project Structure

```
nelux_injector/
├── main.py              # Main execution script
├── injector.py          # Manages the injection logic
│── fuzzer.py        # Fuzzer for special character testing
├── utils/
│   └── param.py         # Crawling and parameter extraction
├── requirements.txt     # Python dependencies
```

---

## Installation

```bash
git clone https://github.com/yourusername/nelux_injector.git
cd nelux_injector
pip install -r requirements.txt
```

> ✅ Requires Python 3.8 or higher.

---

## Usage

### Scan a single domain:

```bash
python3 main.py -u https://example.com
```

### Scan multiple domains from a file:

```bash
python3 main.py -l urls.txt
```

### Use multi-threading to speed up scanning:

```bash
python3 main.py -l urls.txt -t 10
```

---

## Output Files

- `parameters.txt`: URLs whose parameters allowed at least one special character (potentially vulnerable).
- `vulnerables.txt`: URLs clearly vulnerable to XSS or SQLi.

---

## Example Output

```bash
python3 main.py -u http://testphp.vulnweb.com
```

```
🎩 Nelux 1nject0r – Scan started

[*] Fetching from Wayback Machine: http://testphp.vulnweb.com
[*] Crawling site: http://testphp.vulnweb.com

[+] Param URL found: http://testphp.vulnweb.com/item?id=1
[*] Testing parameter: id
[⚠️] Possible SQLi – id allows character: '

[+] Param URL found: http://testphp.vulnweb.com/search.php?q=test
[*] Testing parameter: q
[⚠️] Possible XSS – q allows character: <
```

---

## Disclaimer

> This tool is intended for **educational and authorized security testing only**.  
> Unauthorized use against systems you do not own or have explicit permission to test is **strictly forbidden**.

---

## License

MIT License

---

## Author

**Nelux**  
GitHub: https://github.com/Nelux1/Nelux_1nject0r/

