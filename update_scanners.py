#!/usr/bin/env python3
"""
Script to add url parameter to all create_finding calls in scanners
"""

import re
import os

def add_url_to_finding(content, url_var="self.client.url"):
    """Add url parameter to create_finding calls"""
    
    # Pattern to match create_finding calls
    pattern = r'(create_finding\([^)]+?)(evidence=\{[^}]+?\})(\s*\))'
    
    # Replace with url added
    def replacer(match):
        before = match.group(1)
        evidence = match.group(2)
        after = match.group(3)
        
        # Check if url already exists
        if 'url=' in before or 'url=' in evidence:
            return match.group(0)
        
        # Check if poc exists
        if 'poc=' in before:
            # Add url after poc
            return f"{before}{evidence},\n                url={url_var}{after}"
        else:
            # Just add after evidence
            return f"{before}{evidence},\n                url={url_var}{after}"
    
    return re.sub(pattern, replacer, content, flags=re.DOTALL)

# Test on auth_bypass_scanner.py
scanner_file = r"D:\HAK\graphql-hunter\scanners\auth_bypass_scanner.py"
with open(scanner_file, 'r', encoding='utf-8') as f:
    content = f.read()

updated = add_url_to_finding(content)

print("Preview of changes:")
print("=" * 80)
# Find first change
for i, (old_line, new_line) in enumerate(zip(content.split('\n'), updated.split('\n'))):
    if old_line != new_line:
        print(f"Line {i+1}:")
        print(f"  OLD: {old_line[:100]}")
        print(f"  NEW: {new_line[:100]}")
        if i > 5:
            break

