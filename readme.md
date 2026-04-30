# Nelux 1nject0r

Nelux 1nject0r is an offensive Python tool designed to detect potential **XSS** and **SQL Injection** vulnerabilities. It performs crawling, Wayback Machine scraping, and fuzzing with special characters to discover exploitable parameters.

---

## Features

🔍 Extracts parameterized URLs from a target domain using the Wayback Machine and site crawling.

🎯 Filters and keeps only URLs that contain parameters.

⚔️ Injects special characters (<, >, ", ', ;, --, etc.) into parameters to test if the site properly sanitizes input.

🧠 Stores URLs that do not sanitize inputs in a file called `*_parameters.txt` for manual testing or further fuzzing.

⚡ **Immediate Fuzzing**: Automatically attacks parameters on-the-fly right after discovering an unsafe filter. By default it uses optimized payloads tailored to the unfiltered chars, but you can pass your own wordlist with `-w`.

💾 **Cache & Resume**: Maintains a `.nelux_cache.txt` file registering any already-tested parameters. If the execution stops, you can simply run it again and it will pick up right where it left off, avoiding duplicate work!

💥 If any injection payload triggers a vulnerability, the affected URL is instantly saved in `*_vulnerables.txt`.

🚫 Automatically skips URLs that perform redirects, as they can't be reliably tested.

📂 Organizes and outputs results dynamically per domain for streamlined vulnerability analysis.

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

The easiest way to install Nelux 1nject0r globally is using the provided installation script, which compiles the tool into a standalone binary and places it in your PATH so you can call it from anywhere.

```bash
git clone https://github.com/Nelux1/Nelux_1nject0r.git
cd Nelux_1nject0r
chmod +x install.sh
./install.sh
```

If you prefer to run it manually without the binary wrapper:
```bash
pip install -r requirements.txt
python3 nelux_injector.py -h
```

> ✅ Requires Python 3.8 or higher.

---

## Usage

Once installed globally, you can invoke the tool simply with `nelux1nject0r`.

### Scan a single domain:

```bash
nelux1nject0r -u https://example.com
```

### Scan multiple domains from a file:

```bash
nelux1nject0r -l urls.txt
```

### Advanced Usage (Wordlist, Threads, and Custom User-Agent):

You can speed up the scan and pass custom parameters easily:

```bash
nelux1nject0r -pl params_list.txt -t 5 -ra -w /path/to/wordlist.txt
```

> **Note**: Even if you do *not* provide a wordlist (`-w`), 1nject0r will automatically use contextual default payloads for XSS/SQLi whenever it detects unsanitized parameters!

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

