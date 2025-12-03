# NoSQLi Password Dumper 🚀

An automated tool designed to exploit NoSQL Injection vulnerabilities and extract user passwords through blind boolean-based techniques.  
Perfect for pentesting demonstrations, and learning advanced NoSQL exploitation methods.

---

## 🔥 Features

- Automatic detection using $ne and $regex payloads  
- Blind boolean-based password extraction  
- Configurable username and password field names  
- High-speed or slow mode (delay parameter to avoid rate limits)  
- Saving extracted credentials to file  
- Verbose debugging mode  
- Clean, professional terminal output using pwntools  

---

## 🛠 Installation

1. Clone the repository
```bash
git clone https://github.com/dnxploit/NoSQLI.git
```

2. Install required dependencies
- [requests](https://www.agiratech.com/blog/install-requests-library-in-python/)
- [pwntools](https://docs.pwntools.com/en/stable/install.html)  

---

## 💻 Usage Examples

Basic extraction:  
```bash
python3 nosqli.py --url http://target/login --user admin
```
Using a custom success detection string:  
```bash
python3 nosqli.py --url http://target/api/auth --user admin --success-string welcome --check-mode success
```

Custom field names: 
```bash 
python3 nosqli.py --url http://target/login --user-field email --pass-field passwd --user admin@admin.com
```

Verbose debugging mode: 
```bash 
python3 nosqli.py --url http://target/login --user admin --verbose
```

Skipping vulnerability testing:  
```bash
python3 nosqli.py --url http://target/login --user admin --skip-test
```

---

## ⚠️ Legal Disclaimer

This software is intended strictly for authorized penetration testing and educational purposes.  
Do NOT use it on systems you do not own or lack explicit permission to test.  
The author assumes no responsibility for misuse or damages caused by this tool.

---

## 📜 License

This project is distributed under the MIT License.  
See the LICENSE file for full details.

---

## ⭐ Portfolio Message

If you find this project useful, consider starring the repo on GitHub.  
This tool is part of my cybersecurity learning portfolio.