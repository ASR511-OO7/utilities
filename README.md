<details>
<summary>Details for the multimum.py</summary>

# Multimum
This Python script allows you to execute a specified command template on multiple IP pairs concurrently. It uses multithreading to run the commands on multiple targets at once, making it a powerful tool for automated tasks such as scanning, network tests, or service checks across a range of hosts.

# Features
Concurrent Execution: The script uses multithreading to execute commands on multiple IP
pairs simultaneously, allowing for faster completion.
Custom Command Template: You can specify a custom command with placeholders for IP and PORT, enabling flexibility in the commands you run.
Error Handling: The script captures both standard output and error output from the command, providing comprehensive feedback on the execution.
Input Validation: The script skips invalid lines in the input file that do not conform to the expected IP
format.

## Prerequisites
**Python 3.x:** This script is written in Python 3 and requires Python 3.x to run.

## Required Modules
The script uses the standard libraries ```argparse```, ```subprocess```, ```threading```, and ```queue```. No external modules are needed.

# Installation
**Clone the Repository:**
```bash
git clone https://github.com/ASR511-OO7/multimum.git
cd multimum
```

**Ensure Python 3 is Installed:**
Make sure Python 3 is installed on your system. You can check by running:
```python
python3 --version
```
# Usage
**Prepare the IP List:**
Create a text file that contains a list of IP pairs, each on a new line. For example:
```text
192.168.1.1:22
192.168.1.2:80
10.0.0.1:443
```
**Run the Script:**
Use the following command to execute the script:
```bash
python3 multimum.py -l path/to/ip_port_list.txt -c "your_command_template" [-t number_of_threads]
-l, --list: Path to the file containing IP pairs.
-c, --command: Command template to run, with "IP" and "PORT" as placeholders.
-t, --threads: Number of concurrent threads to use (default is 4).
```
# Example:
```bash
python3 multimum.py -l targets.txt -c "nmap -p PORT IP" -t 10
```
This command would run Nmap scans on all the IP pairs listed in targets.txt using 10/defined concurrent threads.
**Output:**
The script prints the output of the command for each IP pair. If any errors occur during command execution, they will also be displayed.
# Example Commands
**Ping Test:**
```bash
python3 multimum.py -l ips.txt -c "ping -c 3 IP" -t 5
```
**Port Scan with Nmap:**
```bash
python3 multimum.py -l targets.txt -c "nmap -p PORT IP" -t 10
```
**HTTP GET Request:**
```bash
python3 multimum.py -l web_servers.txt -c "curl http://IP:PORT" -t 8
```
**Notes:**
Ensure that the command template you use is valid for the type of target you're running it against.
Adjust the number of threads (-t) based on your system's capability and the number of targets to balance performance and resource usage.
</details>

<details>
<summary>Details for the nmap_scanner.py</summary>

  # Multithreaded Nmap Scanner with Dynamic Display

A powerful, highly concurrent Python script for running comprehensive Nmap scans across multiple IP addresses. Designed to handle continuous performance tracking and dynamic real-time reporting via the terminal and HTML simultaneously.

## Features
- **Concurrent Execution:** Scan multiple target IPs accurately through multithreading capabilities. Limit threading efficiently or perform continuous concurrent processing on all target instances.
- **Dynamic Terminal Display:** The scanner provides a visually clean, constantly updating view inside the command line. Instead of producing messy iterative logs over numerous blank lines, it refreshes seamlessly inline to detail accurate progression per IP.
- **Two-Phase Architecture:**
    - **Phase 1 (Port Discovery):** Finds open ports rapidly (`-p-`). Incorporates auto-retry parsing logic for unpingable targets using the `-Pn` option transparently.
    - **Phase 2 (Detailed Service / Script Scans):** Only iterates over found ports. Sequentially executes in-depth default scripts, version detection, TCP connect, and OS detection logic.
- **Port-Specific Vulnerability Scripting:** Automatically queries each *open port individually* for related `vuln` scripts.
    - **Targeted Executions:** When open, standard ports like *22 (SSH)* or *443 (HTTPS)* additionally trigger dedicated internal Nmap scripts (`ssh*`, `ssl*`) individually!
- **Real-Time HTML Documentation:** A stunning webpage report dynamically regenerates behind the scenes as the script gathers output—view the ongoing status instantly alongside open port details!
- **Organized Workspace Logic:** Centralizes all logs effectively into an exclusive result directory (e.g., `nmap_scan_results`).
    - Raw Phase 1 generic `-p-` scanning logs per active IP.
    - Aggregated port-specific script outputs per type (e.g., SSH vs. SSL outputs globally joined).

## Prerequisites
- **Python 3.x**
- **Nmap** - Ensure Nmap is correctly installed and accessible through your environmental variables/system path.

## General Usage
The script is lightweight and simply requires an input list of IP addresses (separated by line breaks).

```bash
python3 nmap_scanner.py -f ips.txt -t 5
```

### Options
| Argument | Description | Required | Default |
|----------|-------------|----------|---------|
| `-f, --file` | Text file containing target IPs separated by new lines | **Yes** | None |
| `-t, --threads` | Total number of multithreaded workers to instantiate. Use `"all"` for concurrent total. | No | `5` |
| `--no-pn` | Suppress autonomous re-execution of `--Pn` ping-less port scans when a host initially blocks pings and returns "down". | No | `False` |

## Result Logs
On completion (or while running), the script builds a dedicated folder called `nmap_scan_results`. Inside you will find:
* `nmap_scan_report.html` - The stylish, structured live HTML report overviewing all nodes.
* `nmap_scan_ports.txt` - Plain-text comprehensive summary formatting all open ports mapping per IP globally.
* `nmap_scan_<ip>_phase1.txt` - The specific `-p-` core discovery verbose log strictly attached to that target index.
* `nmap_scan_port_<port>_<script>.txt` - Port-specifically appended script outputs logging specific vulnerability triggers (e.g. `vuln`, `ssh_all`, `ssl_all`) over all found IPs dynamically.
</details>
