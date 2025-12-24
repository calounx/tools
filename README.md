# Fail2Ban Report Tool

A comprehensive, user-friendly bash script for generating detailed fail2ban reports with colored output, statistics, and export capabilities.

## Features

- **System Status Check** - Verifies fail2ban installation and service status
- **Active Jails Overview** - Displays all active jails with statistics in a formatted table
- **Banned IP Management** - Lists currently banned IPs across all jails
- **Detailed Jail Information** - Deep dive into specific jail configurations and stats
- **Recent Ban History** - Shows recently banned IPs with timestamps
- **Ban Statistics** - Historical data including top banned IPs and jail-specific statistics
- **Multi-Log Scanning** - Automatically scans current and rotated log files (including .gz compressed)
- **Export Capability** - Save reports to text files for documentation
- **Color-Coded Output** - Enhanced readability with automatic color detection
- **Flexible Options** - Combine multiple report sections as needed

## Requirements

- fail2ban installed and running
- Root or sudo privileges
- Bash 4.0 or higher
- Access to fail2ban log file (usually `/var/log/fail2ban.log`)

## Installation

1. Download the script:
```bash
wget https://raw.githubusercontent.com/calounx/tools/master/fail2ban-report.sh
```

Or clone the entire repository:
```bash
git clone https://github.com/calounx/tools.git
cd tools
```

2. Make it executable:
```bash
chmod +x fail2ban-report.sh
```

3. Run with sudo:
```bash
sudo ./fail2ban-report.sh
```

## Usage

### Basic Usage

```bash
# Show default overview (status, jails, and statistics)
sudo ./fail2ban-report.sh

# Show complete report with all information
sudo ./fail2ban-report.sh --all

# Display help
./fail2ban-report.sh --help
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit |
| `-v, --version` | Show version information |
| `-s, --status` | Display system status and overview |
| `-j, --jails` | Display active jails with statistics |
| `-b, --banned` | Show all currently banned IP addresses |
| `-d, --details JAIL` | Show detailed information for a specific jail |
| `-r, --recent [COUNT]` | Display recently banned IPs (default: 20) |
| `-H, --history` | Show ban history statistics |
| `-S, --stats` | Display global statistics |
| `-a, --all` | Display complete report (all information) |
| `-e, --export [FILE]` | Export report to file |
| `-l, --list-jails` | List all active jail names (one per line) |

### Examples

```bash
# Show details for SSH jail
sudo ./fail2ban-report.sh --details sshd

# Show last 50 recent bans
sudo ./fail2ban-report.sh --recent 50

# Export complete report
sudo ./fail2ban-report.sh --all --export

# Export to specific file
sudo ./fail2ban-report.sh --all --export /tmp/my_report.txt

# Show only banned IPs
sudo ./fail2ban-report.sh --banned

# Combine multiple options
sudo ./fail2ban-report.sh --jails --banned --stats
```

## Sample Output

The script provides color-coded, formatted output including:

```
╔════════════════════════════════════════════════════════════════════════════╗
║                     FAIL2BAN COMPREHENSIVE REPORT                          ║
╚════════════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ACTIVE JAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

JAIL NAME            CURR BANNED     TOTAL BANNED    CURR FAILED     TOTAL FAILED
──────────────────────────────────────────────────────────────────────────────────
sshd                 5               142             12              3421
nginx-limit-req      2               87              8               1256
```

## Report Sections

### System Status
- Fail2ban version
- Service status
- Log file information (current and rotated files)
- Number of log files being scanned

### Active Jails
- Total active jails count
- Per-jail statistics table with:
  - Currently banned IPs
  - Total banned count (all time)
  - Currently failed attempts
  - Total failed attempts

### Banned IPs
- Currently banned IP addresses grouped by jail
- Total count across all jails

### Jail Details
- Filter configuration
- Actions configured
- Detailed statistics
- Currently banned IPs for the specific jail

### Recent Bans
- Timestamped list of recently banned IPs
- Jail name for each ban
- Configurable count (default: 20)

### Ban History
- Total bans (all time)
- Bans today
- Top 10 most banned IPs
- Ban counts by jail

### Global Statistics
- Summary across all jails
- Total currently banned IPs
- Total ban count
- Failed attempt statistics

## Export Functionality

Reports can be exported to text files:

```bash
# Default export location: /tmp/fail2ban-reports/fail2ban_report_TIMESTAMP.txt
sudo ./fail2ban-report.sh --all --export

# Custom export location
sudo ./fail2ban-report.sh --all --export /var/reports/fail2ban.txt
```

Exported reports include:
- All report sections
- Plain text formatting (colors removed)
- Timestamp and generation date
- File size information

## Configuration

The script uses the following default locations:
- Log file: `/var/log/fail2ban.log`
- Export directory: `/tmp/fail2ban-reports/`
- Maximum log files: `5` (current + 4 rotated logs)

These can be modified in the script configuration section if needed.

## Log File Scanning

The script automatically discovers and scans multiple log files for comprehensive historical data:

### Supported Log Files
- **Current log**: `/var/log/fail2ban.log`
- **Rotated logs**: `fail2ban.log.1`, `fail2ban.log.2`, etc.
- **Compressed logs**: `fail2ban.log.1.gz`, `fail2ban.log.2.gz`, etc.

### How It Works
1. Automatically detects up to 5 log files (configurable via `MAX_LOG_FILES`)
2. Reads both regular and gzip-compressed rotated logs
3. Combines data from all files for historical analysis
4. Displays which log files are being scanned in the report

### Benefits
- **More complete ban history** - See bans from rotated logs
- **Better statistics** - Top banned IPs across all available logs
- **Historical trends** - Analyze patterns over longer time periods
- **No manual work** - Automatically finds and processes all log files

### Example Output
```
Log files:    5 file(s) found (max: 5)
Main log:     /var/log/fail2ban.log (2.3M)
Rotated logs: 4 file(s)
              - fail2ban.log.1 (3.1M)
              - fail2ban.log.2.gz (1.2M)
              - fail2ban.log.3.gz (1.5M)
              - fail2ban.log.4.gz (1.4M)
```

## Exit Codes

- `0` - Success
- `1` - Error (fail2ban not installed/running, permission denied, etc.)

## Troubleshooting

### Permission Denied
The script requires root or sudo privileges to access fail2ban-client:
```bash
sudo ./fail2ban-report.sh
```

### fail2ban-client Not Found
Install fail2ban:
```bash
# Debian/Ubuntu
sudo apt-get install fail2ban

# RHEL/CentOS
sudo yum install fail2ban
```

### Service Not Running
Start fail2ban service:
```bash
sudo systemctl start fail2ban
sudo systemctl enable fail2ban
```

### Log File Not Found
Check your fail2ban configuration for log file location:
```bash
sudo fail2ban-client get loglevel
sudo fail2ban-client get logtarget
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - feel free to use and modify as needed.

## Author

Generated with Claude Code

## Version

Current version: 1.0.0

## Acknowledgments

- fail2ban project for the excellent intrusion prevention framework
- Community contributors and testers
