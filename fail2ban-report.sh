#!/bin/bash

################################################################################
# fail2ban-report.sh - Comprehensive Fail2Ban Reporting Tool
#
# Description:
#   A user-friendly script to generate detailed fail2ban reports including
#   active jails, banned IPs, statistics, and historical data.
#
# Usage:
#   ./fail2ban-report.sh [OPTIONS]
#
# Requirements:
#   - fail2ban installed and running
#   - Root/sudo privileges (for accessing fail2ban-client)
#
# Author: Generated with Claude Code
# Version: 1.0.0
# Date: 2025-12-24
################################################################################

set -euo pipefail

# Script configuration
SCRIPT_NAME=$(basename "$0")
SCRIPT_VERSION="1.0.0"
FAIL2BAN_LOG="/var/log/fail2ban.log"
EXPORT_DIR="/tmp/fail2ban-reports"
F2B_TIMEOUT=10  # Timeout for fail2ban-client commands in seconds

# Cleanup trap
TEMP_FILES=()

cleanup() {
    local exit_code=$?

    # Clean up temporary files
    for file in "${TEMP_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            rm -f "$file" 2>/dev/null || true
        fi
    done

    # Restore terminal state if needed
    tput cnorm 2>/dev/null || true  # Show cursor

    exit "$exit_code"
}

trap cleanup EXIT INT TERM

# Color definitions
if [[ -t 1 ]]; then
    COLOR_RESET='\033[0m'
    COLOR_BOLD='\033[1m'
    COLOR_RED='\033[0;31m'
    COLOR_GREEN='\033[0;32m'
    COLOR_YELLOW='\033[0;33m'
    COLOR_BLUE='\033[0;34m'
    COLOR_MAGENTA='\033[0;35m'
    COLOR_CYAN='\033[0;36m'
    COLOR_WHITE='\033[0;37m'
    COLOR_BOLD_RED='\033[1;31m'
    COLOR_BOLD_GREEN='\033[1;32m'
    COLOR_BOLD_YELLOW='\033[1;33m'
    COLOR_BOLD_BLUE='\033[1;34m'
    COLOR_BOLD_MAGENTA='\033[1;35m'
    COLOR_BOLD_CYAN='\033[1;36m'
else
    COLOR_RESET=''
    COLOR_BOLD=''
    COLOR_RED=''
    COLOR_GREEN=''
    COLOR_YELLOW=''
    COLOR_BLUE=''
    COLOR_MAGENTA=''
    COLOR_CYAN=''
    COLOR_WHITE=''
    COLOR_BOLD_RED=''
    COLOR_BOLD_GREEN=''
    COLOR_BOLD_YELLOW=''
    COLOR_BOLD_BLUE=''
    COLOR_BOLD_MAGENTA=''
    COLOR_BOLD_CYAN=''
fi

################################################################################
# Helper Functions
################################################################################

# Print colored output
print_color() {
    local color=$1
    shift
    echo -e "${color}$*${COLOR_RESET}"
}

# Print section header
print_header() {
    echo
    print_color "${COLOR_BOLD_BLUE}" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color "${COLOR_BOLD_CYAN}" "$1"
    print_color "${COLOR_BOLD_BLUE}" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Print success message
print_success() {
    print_color "${COLOR_BOLD_GREEN}" "✓ $*"
}

# Print warning message
print_warning() {
    print_color "${COLOR_BOLD_YELLOW}" "⚠ $*"
}

# Print error message
print_error() {
    print_color "${COLOR_BOLD_RED}" "✗ $*" >&2
}

# Print info message
print_info() {
    print_color "${COLOR_CYAN}" "ℹ $*"
}

################################################################################
# Validation Functions
################################################################################

# Check if running with sufficient privileges
check_privileges() {
    # Try to run actual command we need instead of generic sudo check
    if ! f2b_cmd ping &>/dev/null; then
        print_error "This script requires privileges to run fail2ban-client"
        print_info "Please run with: sudo $SCRIPT_NAME"

        # Provide helpful diagnostic
        if [[ $EUID -ne 0 ]]; then
            if command -v sudo &>/dev/null; then
                print_info "Or configure sudo access for fail2ban-client"
            fi
        fi
        exit 1
    fi
}

# Check if fail2ban is installed
check_fail2ban_installed() {
    if ! command -v fail2ban-client &> /dev/null; then
        print_error "fail2ban-client not found"
        print_info "Please install fail2ban: apt-get install fail2ban (Debian/Ubuntu) or yum install fail2ban (RHEL/CentOS)"
        exit 1
    fi
}

# Check if fail2ban service is running
check_fail2ban_running() {
    local status
    if [[ $EUID -eq 0 ]]; then
        status=$(fail2ban-client ping 2>&1 || echo "failed")
    else
        status=$(sudo fail2ban-client ping 2>&1 || echo "failed")
    fi

    if [[ "$status" != "Server replied: pong" ]]; then
        print_error "fail2ban service is not running"
        print_info "Start the service: systemctl start fail2ban"
        exit 1
    fi
}

# Execute fail2ban-client command with proper privileges and timeout
f2b_cmd() {
    local cmd_timeout="$F2B_TIMEOUT"

    if command -v timeout &>/dev/null; then
        if [[ $EUID -eq 0 ]]; then
            timeout "$cmd_timeout" fail2ban-client "$@"
        else
            timeout "$cmd_timeout" sudo fail2ban-client "$@"
        fi
    else
        # Fallback without timeout command
        if [[ $EUID -eq 0 ]]; then
            fail2ban-client "$@"
        else
            sudo fail2ban-client "$@"
        fi
    fi
}

################################################################################
# Core Functions
################################################################################

# Get list of active jails
get_active_jails() {
    f2b_cmd status | grep "Jail list:" | sed 's/.*Jail list:\s*//' | tr ',' '\n' | sed 's/^\s*//' | sed 's/\s*$//' | grep -v '^$'
}

# Get banned IPs for a specific jail
get_banned_ips() {
    local jail=$1
    f2b_cmd status "$jail" | grep "Banned IP list:" | sed 's/.*Banned IP list:\s*//' | tr ' ' '\n' | grep -v '^$'
}

# Get total banned count for a jail
get_total_banned() {
    local jail=$1
    f2b_cmd status "$jail" | grep "Total banned:" | awk '{print $NF}'
}

# Get currently banned count for a jail
get_currently_banned() {
    local jail=$1
    f2b_cmd status "$jail" | grep "Currently banned:" | awk '{print $NF}'
}

# Get total failed count for a jail
get_total_failed() {
    local jail=$1
    f2b_cmd status "$jail" | grep "Total failed:" | awk '{print $NF}'
}

# Get currently failed count for a jail
get_currently_failed() {
    local jail=$1
    f2b_cmd status "$jail" | grep "Currently failed:" | awk '{print $NF}'
}

################################################################################
# Display Functions
################################################################################

# Display system status
display_system_status() {
    print_header "FAIL2BAN SYSTEM STATUS"

    local version
    version=$(fail2ban-client version 2>/dev/null || echo "Unknown")

    print_color "${COLOR_BOLD}" "Version:      ${COLOR_GREEN}${version}"
    print_success "fail2ban is installed and running"

    if [[ -f "$FAIL2BAN_LOG" ]]; then
        local log_size
        log_size=$(du -h "$FAIL2BAN_LOG" 2>/dev/null | cut -f1 || echo "Unknown")
        print_color "${COLOR_BOLD}" "Log file:     ${COLOR_WHITE}${FAIL2BAN_LOG} (${log_size})"
    fi

    echo
}

# Display active jails overview
display_active_jails() {
    print_header "ACTIVE JAILS"

    local jails
    jails=$(get_active_jails)

    if [[ -z "$jails" ]]; then
        print_warning "No active jails found"
        return
    fi

    local jail_count
    jail_count=$(echo "$jails" | wc -l)
    print_color "${COLOR_BOLD}" "Total Active Jails: ${COLOR_GREEN}${jail_count}"
    echo

    # Table header
    printf "${COLOR_BOLD}%-20s %-15s %-15s %-15s %-15s${COLOR_RESET}\n" \
        "JAIL NAME" "CURR BANNED" "TOTAL BANNED" "CURR FAILED" "TOTAL FAILED"
    print_color "${COLOR_BLUE}" "$(printf '%.0s─' {1..90})"

    # Table rows
    while IFS= read -r jail; do
        [[ -z "$jail" ]] && continue

        local curr_banned total_banned curr_failed total_failed
        curr_banned=$(get_currently_banned "$jail" 2>/dev/null || echo "0")
        total_banned=$(get_total_banned "$jail" 2>/dev/null || echo "0")
        curr_failed=$(get_currently_failed "$jail" 2>/dev/null || echo "0")
        total_failed=$(get_total_failed "$jail" 2>/dev/null || echo "0")

        # Color code based on current bans
        local color="${COLOR_WHITE}"
        if [[ $curr_banned -gt 0 ]]; then
            color="${COLOR_YELLOW}"
        fi
        if [[ $curr_banned -gt 10 ]]; then
            color="${COLOR_RED}"
        fi

        printf "${color}%-20s %-15s %-15s %-15s %-15s${COLOR_RESET}\n" \
            "$jail" "$curr_banned" "$total_banned" "$curr_failed" "$total_failed"
    done <<< "$jails"

    echo
}

# Display banned IPs for all jails
display_banned_ips() {
    print_header "CURRENTLY BANNED IP ADDRESSES"

    local jails
    jails=$(get_active_jails)

    if [[ -z "$jails" ]]; then
        print_warning "No active jails found"
        return
    fi

    local total_ips=0

    while IFS= read -r jail; do
        [[ -z "$jail" ]] && continue

        local banned_ips
        banned_ips=$(get_banned_ips "$jail" 2>/dev/null || echo "")

        if [[ -n "$banned_ips" ]]; then
            local ip_count
            ip_count=$(echo "$banned_ips" | wc -l)
            total_ips=$((total_ips + ip_count))

            print_color "${COLOR_BOLD_YELLOW}" "\n[$jail] - ${ip_count} banned IP(s)"
            print_color "${COLOR_BLUE}" "$(printf '%.0s─' {1..80})"

            echo "$banned_ips" | while IFS= read -r ip; do
                [[ -z "$ip" ]] && continue
                print_color "${COLOR_RED}" "  • $ip"
            done
        fi
    done <<< "$jails"

    echo
    print_color "${COLOR_BOLD}" "Total Banned IPs across all jails: ${COLOR_RED}${total_ips}"
    echo
}

# Display detailed information for a specific jail
display_jail_details() {
    local jail=$1

    print_header "DETAILED INFORMATION: $jail"

    if ! f2b_cmd status "$jail" &>/dev/null; then
        print_error "Jail '$jail' not found or not active"
        return 1
    fi

    local status_output
    status_output=$(f2b_cmd status "$jail")

    print_color "${COLOR_BOLD_CYAN}" "Filter Configuration:"
    echo "$status_output" | grep -E "Filter|Actions|logpath|maxretry|findtime|bantime" | while IFS= read -r line; do
        print_color "${COLOR_WHITE}" "  $line"
    done

    echo
    print_color "${COLOR_BOLD_CYAN}" "Statistics:"
    echo "$status_output" | grep -E "Currently failed|Total failed|Currently banned|Total banned" | while IFS= read -r line; do
        print_color "${COLOR_WHITE}" "  $line"
    done

    echo
    print_color "${COLOR_BOLD_CYAN}" "Currently Banned IPs:"
    local banned_ips
    banned_ips=$(get_banned_ips "$jail")

    if [[ -n "$banned_ips" ]]; then
        echo "$banned_ips" | while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            print_color "${COLOR_RED}" "  • $ip"
        done
    else
        print_info "  No currently banned IPs"
    fi

    echo
}

# Display recently banned IPs with timestamps
display_recent_bans() {
    local count=${1:-20}

    print_header "RECENTLY BANNED IPs (Last $count)"

    if [[ ! -f "$FAIL2BAN_LOG" ]]; then
        print_error "Log file not found: $FAIL2BAN_LOG"
        return 1
    fi

    print_color "${COLOR_BOLD}" "Format: [Timestamp] [Jail] IP Address"
    print_color "${COLOR_BLUE}" "$(printf '%.0s─' {1..80})"

    if grep -q "Ban" "$FAIL2BAN_LOG" 2>/dev/null; then
        grep "Ban" "$FAIL2BAN_LOG" | tail -n "$count" | while IFS= read -r line; do
            # Extract timestamp, jail, and IP
            local timestamp jail ip
            timestamp=$(echo "$line" | awk '{print $1, $2}')
            jail=$(echo "$line" | grep -oP '\[\K[^\]]+(?=\])' | head -1)
            ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)

            if [[ -n "$ip" ]]; then
                print_color "${COLOR_YELLOW}" "[$timestamp] ${COLOR_MAGENTA}[$jail]${COLOR_RESET} ${COLOR_RED}$ip"
            fi
        done
    else
        print_warning "No ban records found in log file"
    fi

    echo
}

# Display ban history statistics
display_ban_history() {
    print_header "BAN HISTORY STATISTICS"

    if [[ ! -f "$FAIL2BAN_LOG" ]]; then
        print_error "Log file not found: $FAIL2BAN_LOG"
        return 1
    fi

    local total_bans today_bans
    total_bans=$(grep -c "Ban" "$FAIL2BAN_LOG" 2>/dev/null || echo "0")
    today_bans=$(grep "Ban" "$FAIL2BAN_LOG" | grep -c "$(date +%Y-%m-%d)" 2>/dev/null || echo "0")

    print_color "${COLOR_BOLD}" "Total Bans (all time):     ${COLOR_RED}${total_bans}"
    print_color "${COLOR_BOLD}" "Bans Today:                ${COLOR_YELLOW}${today_bans}"

    echo
    print_color "${COLOR_BOLD_CYAN}" "Top 10 Most Banned IPs:"
    print_color "${COLOR_BLUE}" "$(printf '%.0s─' {1..80})"

    if grep -q "Ban" "$FAIL2BAN_LOG" 2>/dev/null; then
        grep "Ban" "$FAIL2BAN_LOG" | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | head -10 | while read -r count ip; do
            print_color "${COLOR_WHITE}" "  ${COLOR_RED}$ip${COLOR_RESET} - ${COLOR_YELLOW}$count${COLOR_RESET} ban(s)"
        done
    else
        print_warning "No ban records found"
    fi

    echo
    print_color "${COLOR_BOLD_CYAN}" "Bans by Jail:"
    print_color "${COLOR_BLUE}" "$(printf '%.0s─' {1..80})"

    if grep -q "Ban" "$FAIL2BAN_LOG" 2>/dev/null; then
        grep "Ban" "$FAIL2BAN_LOG" | grep -oP '\[\K[^\]]+(?=\])' | sort | uniq -c | sort -rn | while read -r count jail; do
            print_color "${COLOR_WHITE}" "  ${COLOR_MAGENTA}$jail${COLOR_RESET} - ${COLOR_YELLOW}$count${COLOR_RESET} ban(s)"
        done
    else
        print_warning "No ban records found"
    fi

    echo
}

# Display global statistics
display_statistics() {
    print_header "GLOBAL STATISTICS"

    local jails
    jails=$(get_active_jails)

    if [[ -z "$jails" ]]; then
        print_warning "No active jails found"
        return
    fi

    local total_curr_banned=0 total_all_banned=0 total_curr_failed=0 total_all_failed=0

    while IFS= read -r jail; do
        [[ -z "$jail" ]] && continue

        local curr_banned total_banned curr_failed total_failed
        curr_banned=$(get_currently_banned "$jail" 2>/dev/null || echo "0")
        total_banned=$(get_total_banned "$jail" 2>/dev/null || echo "0")
        curr_failed=$(get_currently_failed "$jail" 2>/dev/null || echo "0")
        total_failed=$(get_total_failed "$jail" 2>/dev/null || echo "0")

        total_curr_banned=$((total_curr_banned + curr_banned))
        total_all_banned=$((total_all_banned + total_banned))
        total_curr_failed=$((total_curr_failed + curr_failed))
        total_all_failed=$((total_all_failed + total_failed))
    done <<< "$jails"

    local jail_count
    jail_count=$(echo "$jails" | wc -l)

    print_color "${COLOR_BOLD}" "Active Jails:              ${COLOR_GREEN}${jail_count}"
    print_color "${COLOR_BOLD}" "Currently Banned IPs:      ${COLOR_RED}${total_curr_banned}"
    print_color "${COLOR_BOLD}" "Total Bans (all time):     ${COLOR_YELLOW}${total_all_banned}"
    print_color "${COLOR_BOLD}" "Currently Failed:          ${COLOR_MAGENTA}${total_curr_failed}"
    print_color "${COLOR_BOLD}" "Total Failed (all time):   ${COLOR_CYAN}${total_all_failed}"

    echo
}

# Export report to file
export_report() {
    local output_file=$1
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)

    # Create export directory if it doesn't exist
    if [[ ! -d "$EXPORT_DIR" ]]; then
        mkdir -p "$EXPORT_DIR" || {
            print_error "Failed to create export directory: $EXPORT_DIR"
            return 1
        }
        chmod 700 "$EXPORT_DIR"  # Owner only
    fi

    # Sanitize filename
    if [[ -n "$output_file" ]]; then
        # Check for path traversal
        if [[ "$output_file" == *".."* ]]; then
            print_error "Path traversal detected in filename"
            return 1
        fi

        # Ensure absolute path or relative to EXPORT_DIR
        if [[ "$output_file" != /* ]]; then
            output_file="${EXPORT_DIR}/${output_file}"
        fi

        # Verify write permissions
        local dir
        dir=$(dirname "$output_file")
        if [[ ! -w "$dir" ]]; then
            print_error "No write permission to directory: $dir"
            return 1
        fi

        # Blacklist critical paths
        case "$output_file" in
            /etc/*|/boot/*|/sys/*|/proc/*|/dev/*)
                print_error "Cannot write to system directory"
                return 1
                ;;
        esac
    else
        output_file="${EXPORT_DIR}/fail2ban_report_${timestamp}.txt"
    fi

    print_info "Generating report..."

    # Set secure umask for file creation
    local old_umask
    old_umask=$(umask)
    umask 077  # Create file as 0600 (owner only)

    # Run in subshell to avoid polluting global color variables
    (
        # Disable colors for file export
        COLOR_RESET=''
        COLOR_BOLD=''
        COLOR_RED=''
        COLOR_GREEN=''
        COLOR_YELLOW=''
        COLOR_BLUE=''
        COLOR_MAGENTA=''
        COLOR_CYAN=''
        COLOR_WHITE=''
        COLOR_BOLD_RED=''
        COLOR_BOLD_GREEN=''
        COLOR_BOLD_YELLOW=''
        COLOR_BOLD_BLUE=''
        COLOR_BOLD_CYAN=''

        echo "FAIL2BAN REPORT"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "========================================"
        echo

        display_system_status
        display_statistics
        display_active_jails
        display_banned_ips
        display_ban_history
    ) > "$output_file"

    umask "$old_umask"

    print_success "Report exported to: $output_file"

    local file_size
    file_size=$(du -h "$output_file" | cut -f1)
    print_info "File size: $file_size"
}

################################################################################
# Help and Usage
################################################################################

show_help() {
    cat << EOF
${COLOR_BOLD_CYAN}FAIL2BAN REPORT - Comprehensive Fail2Ban Reporting Tool${COLOR_RESET}
Version: $SCRIPT_VERSION

${COLOR_BOLD}USAGE:${COLOR_RESET}
    $SCRIPT_NAME [OPTIONS]

${COLOR_BOLD}DESCRIPTION:${COLOR_RESET}
    Generate comprehensive reports about fail2ban status, including active jails,
    banned IPs, statistics, and historical data.

${COLOR_BOLD}OPTIONS:${COLOR_RESET}
    ${COLOR_GREEN}-h, --help${COLOR_RESET}
        Show this help message and exit

    ${COLOR_GREEN}-v, --version${COLOR_RESET}
        Show version information

    ${COLOR_GREEN}-s, --status${COLOR_RESET}
        Display system status and overview (default if no options)

    ${COLOR_GREEN}-j, --jails${COLOR_RESET}
        Display active jails with statistics

    ${COLOR_GREEN}-b, --banned${COLOR_RESET}
        Show all currently banned IP addresses

    ${COLOR_GREEN}-d, --details JAIL${COLOR_RESET}
        Show detailed information for a specific jail

    ${COLOR_GREEN}-r, --recent [COUNT]${COLOR_RESET}
        Display recently banned IPs (default: 20)

    ${COLOR_GREEN}-H, --history${COLOR_RESET}
        Show ban history statistics

    ${COLOR_GREEN}-S, --stats${COLOR_RESET}
        Display global statistics

    ${COLOR_GREEN}-a, --all${COLOR_RESET}
        Display complete report (all information)

    ${COLOR_GREEN}-e, --export [FILE]${COLOR_RESET}
        Export report to file (default: /tmp/fail2ban-reports/fail2ban_report_TIMESTAMP.txt)

    ${COLOR_GREEN}-l, --list-jails${COLOR_RESET}
        List all active jail names (one per line)

${COLOR_BOLD}EXAMPLES:${COLOR_RESET}
    # Show default overview
    $SCRIPT_NAME

    # Show complete report
    $SCRIPT_NAME --all

    # Show details for SSH jail
    $SCRIPT_NAME --details sshd

    # Show last 50 recent bans
    $SCRIPT_NAME --recent 50

    # Export complete report
    $SCRIPT_NAME --all --export

    # Export to specific file
    $SCRIPT_NAME --all --export /tmp/my_report.txt

    # Show only banned IPs
    $SCRIPT_NAME --banned

    # Combine multiple options
    $SCRIPT_NAME --jails --banned --stats

${COLOR_BOLD}REQUIREMENTS:${COLOR_RESET}
    - fail2ban installed and running
    - Root or sudo privileges
    - Access to fail2ban log file (usually /var/log/fail2ban.log)

${COLOR_BOLD}EXIT CODES:${COLOR_RESET}
    0 - Success
    1 - General error (fail2ban not installed/running, permission denied, etc.)

${COLOR_BOLD}NOTES:${COLOR_RESET}
    - The script requires sudo/root access to query fail2ban status
    - Log file location may vary depending on your system configuration
    - Colors are automatically disabled when output is not a terminal

${COLOR_BOLD}AUTHOR:${COLOR_RESET}
    Generated with Claude Code

${COLOR_BOLD}REPORTING BUGS:${COLOR_RESET}
    Please report issues with system information and error messages

EOF
}

show_version() {
    echo "$SCRIPT_NAME version $SCRIPT_VERSION"
}

################################################################################
# Main Function
################################################################################

main() {
    local show_status=false
    local show_jails=false
    local show_banned=false
    local show_details=false
    local show_recent=false
    local show_history=false
    local show_stats=false
    local show_all=false
    local export_report_flag=false
    local list_jails=false

    local jail_name=""
    local recent_count=20
    local export_file=""

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            -s|--status)
                show_status=true
                shift
                ;;
            -j|--jails)
                show_jails=true
                shift
                ;;
            -b|--banned)
                show_banned=true
                shift
                ;;
            -d|--details)
                show_details=true
                if [[ -n "${2:-}" && ! "$2" =~ ^- ]]; then
                    jail_name=$2
                    shift 2
                else
                    print_error "Option --details requires a jail name"
                    exit 1
                fi
                ;;
            -r|--recent)
                show_recent=true
                if [[ -n "${2:-}" && "$2" =~ ^[0-9]+$ ]]; then
                    recent_count=$2
                    shift 2
                else
                    shift
                fi
                ;;
            -H|--history)
                show_history=true
                shift
                ;;
            -S|--stats)
                show_stats=true
                shift
                ;;
            -a|--all)
                show_all=true
                shift
                ;;
            -e|--export)
                export_report_flag=true
                if [[ -n "${2:-}" && ! "$2" =~ ^- ]]; then
                    export_file=$2
                    shift 2
                else
                    shift
                fi
                ;;
            -l|--list-jails)
                list_jails=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Check prerequisites
    check_privileges
    check_fail2ban_installed
    check_fail2ban_running

    # If no options specified, show default overview
    if ! $show_status && ! $show_jails && ! $show_banned && ! $show_details && \
       ! $show_recent && ! $show_history && ! $show_stats && ! $show_all && \
       ! $export_report_flag && ! $list_jails; then
        show_status=true
        show_jails=true
        show_stats=true
    fi

    # Handle list-jails separately (simple output)
    if $list_jails; then
        get_active_jails
        exit 0
    fi

    # Display report header
    echo
    print_color "${COLOR_BOLD_MAGENTA}" "╔════════════════════════════════════════════════════════════════════════════╗"
    print_color "${COLOR_BOLD_MAGENTA}" "║                     FAIL2BAN COMPREHENSIVE REPORT                          ║"
    print_color "${COLOR_BOLD_MAGENTA}" "╚════════════════════════════════════════════════════════════════════════════╝"
    print_color "${COLOR_WHITE}" "Generated: $(date '+%Y-%m-%d %H:%M:%S')"

    # Execute requested displays
    if $show_all; then
        display_system_status
        display_statistics
        display_active_jails
        display_banned_ips
        display_recent_bans "$recent_count"
        display_ban_history
    else
        $show_status && display_system_status
        $show_stats && display_statistics
        $show_jails && display_active_jails
        $show_banned && display_banned_ips
        $show_details && display_jail_details "$jail_name"
        $show_recent && display_recent_bans "$recent_count"
        $show_history && display_ban_history
    fi

    # Export if requested
    if $export_report_flag; then
        echo
        export_report "$export_file"
    fi

    # Footer
    echo
    print_color "${COLOR_BOLD_BLUE}" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_info "Report complete. Use --help for more options."
    echo
}

# Run main function
main "$@"
