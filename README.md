# Auto-Enum

Auto-Enum is an automated enumeration tool designed to assist penetration testers in quickly identifying vulnerabilities within a target system. It leverages Nmap for service discovery and integrates with Searchsploit to find potential exploits.

## Features

- **Automated Enumeration:** Runs multiple Nmap scans simultaneously to gather extensive information about open ports and services.
- **Service Version Detection:** Identifies running service versions to assist in further exploitation.
- **Searchsploit Integration:** Matches detected services with known exploits from Exploit-DB.
- **Customizable Scanning Options:** Users can specify additional Nmap parameters as needed.

## Installation

Clone the repository:
```bash
git clone https://github.com/Dishant-Chaudhary/Auto-Enum.git
cd Auto-Enum
```

Ensure you have the required dependencies installed:
```bash
sudo apt update && sudo apt install nmap exploitdb
```

## Usage

Run the script with root privileges:
```bash
python3 auto_enum.py <target-ip>
```

Example:
```bash
python3 auto_enum.py 192.168.1.1
```

### Options:
- `<target-ip>`: IP address of the target machine.
- Modify the script to include additional scanning flags if needed.

## Requirements

- Linux (Kali, ParrotOS, or any Debian-based distro preferred)
- Python 3
- Nmap
- Searchsploit (Exploit-DB)

## Disclaimer

This tool is intended for educational and ethical penetration testing purposes only. **Do not use it on unauthorized systems.** The author is not responsible for any misuse of this tool.

## Contributions

Contributions are welcome! Feel free to submit pull requests or report issues in the [GitHub repository](https://github.com/Dishant-Chaudhary/Auto-Enum).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
### Author
Developed by [Dishant Chaudhary](https://github.com/Dishant-Chaudhary)

