#!/usr/bin/env python3
"""
Add url parameter and POCs to all scanners
"""

import re
import glob

def update_scanner_file(filepath):
    """Update a scanner file to include url parameter"""
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find all create_finding calls and add url if missing
    # Pattern: create_finding( ... evidence={...} ) or create_finding( ... cwe="..." )
    
    pattern = r'(create_finding\(\s*title=.*?(?:evidence=\{[^}]*?\}|cwe="[^"]*"))\s*\)'
    
    def add_url_param(match):
        finding_content = match.group(1)
        
        # Skip if url already present
        if ',\n                url=' in finding_content or ', url=' in finding_content:
            return match.group(0)
        
        # Add url parameter before closing
        return finding_content + ',\n                url=self.client.url\n            )'
    
    updated_content = re.sub(pattern, add_url_param, content, flags=re.DOTALL)
    
    # Only write if changed
    if updated_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(updated_content)
        return True
    return False

# Process all scanner files
scanner_files = glob.glob(r'D:\HAK\graphql-hunter\scanners\*.py')
updated_count = 0

for scanner_file in scanner_files:
    if '__init__' in scanner_file:
        continue
    
    filename = scanner_file.split('\\')[-1]
    if update_scanner_file(scanner_file):
        print(f"[+] Updated {filename}")
        updated_count += 1
    else:
        print(f"[-] Skipped {filename} (already updated or no findings)")

print(f"\n{updated_count} files updated")

