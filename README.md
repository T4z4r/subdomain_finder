# Subdomain Finder

A Python tool for passive and optional active subdomain enumeration.

## Features

- **Passive enumeration** using Certificate Transparency (crt.sh)
- **Optional Google dork** for additional subdomains (may be slow/rate-limited)
- **Optional DNS brute-force** with custom wordlist support
- **JSON output** support
- **Progress bars** for brute-force operations

## Installation

1. Clone or download the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Basic passive enumeration:
```bash
python subdomain_finder.py example.com
```

With Google dork (slow, may be blocked):
```bash
python subdomain_finder.py example.com --google
```

With DNS brute-force:
```bash
python subdomain_finder.py example.com --bruteforce
```

Full enumeration (passive + Google + brute-force):
```bash
python subdomain_finder.py example.com --google --bruteforce
```

Save results to JSON:
```bash
python subdomain_finder.py example.com -o results.json
```

Custom wordlist for brute-force:
```bash
python subdomain_finder.py example.com --bruteforce --wordlist mywordlist.txt
```

## Arguments

- `domain`: Target domain (required)
- `-b, --bruteforce`: Enable DNS brute-force
- `-w, --wordlist`: Wordlist file for brute-force (default: subdomains-top1million-5000.txt)
- `-o, --output`: Save results to JSON file
- `-g, --google`: Enable Google dork search

## Dependencies

- requests
- beautifulsoup4
- tqdm
- dnspython (only required for brute-force)

## Author

T4z4r (2025)