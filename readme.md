# Nelux 1nject0r

Nelux 1nject0r is an offensive Python tool designed to detect potential **XSS** and **SQL Injection** vulnerabilities. It performs crawling, Wayback Machine scraping, and fuzzing with special characters to discover exploitable parameters.

---

## Features

🔍 Extracts parameterized URLs from a target domain using the Wayback Machine and site crawling.

🎯 Filters and keeps only URLs that contain parameters.

⚔️ Injects special characters (<, >, ", ', ;, --, etc.) into parameters to test if the site properly sanitizes input.

🧠 Stores URLs that do not sanitize inputs in a file called parameters.txt for manual testing or further fuzzing.

🔁 Allows the user to either stop after gathering unsanitized parameters, or continue with a second phase of fuzzing using a custom payload list.

💥 If any injection payload triggers a vulnerability, the affected URL is saved in vulnerables.txt.

🚫 Automatically skips URLs that perform redirects, as they can't be reliably tested.

📂 Organizes and outputs results for streamlined vulnerability analysis.

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
git clone https://github.com/Nelux1/Nelux_1nject0r.git
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


<a href='https://cafecito.app/nelux' rel='noopener' target='_blank'><img srcset='https://cdn.cafecito.app/imgs/buttons/button_6.png 1x, https://cdn.cafecito.app/imgs/buttons/button_6_2x.png 2x, https://cdn.cafecito.app/imgs/buttons/button_6_3.75x.png 3.75x' src='https://cdn.cafecito.app/imgs/buttons/button_6.png' alt='Invitame un café en cafecito.app' /></a>

