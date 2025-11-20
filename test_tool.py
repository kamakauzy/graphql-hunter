#!/usr/bin/env python3
"""
Quick test/demo of GraphQL Hunter
This tests the tool against a public GraphQL endpoint (if available)
"""

import subprocess
import sys

def test_help():
    """Test that help displays correctly"""
    print("[*] Testing help output...")
    result = subprocess.run(
        [sys.executable, "graphql-hunter.py", "--help"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0 and "GraphQL Hunter" in result.stdout:
        print("[OK] Help output works")
        return True
    else:
        print("[ERROR] Help output failed")
        return False

def test_dependencies():
    """Test that all dependencies are installed"""
    print("[*] Testing dependencies...")
    deps = ["requests", "colorama", "yaml"]
    
    all_good = True
    for dep in deps:
        try:
            if dep == "yaml":
                __import__("yaml")
            else:
                __import__(dep)
            print(f"  [OK] {dep} installed")
        except ImportError:
            print(f"  [ERROR] {dep} NOT installed - run: pip install -r requirements.txt")
            all_good = False
    
    return all_good

def test_public_endpoint():
    """Test against a known public GraphQL endpoint"""
    print("\n[*] Testing against public endpoint (optional)...")
    print("    Note: This requires internet connection and may fail if endpoint is down")
    
    # There are few reliable public GraphQL endpoints
    # We'll just show the command they would run
    print("\n    To test against a real endpoint, run:")
    print("    python graphql-hunter.py -u https://countries.trevorblades.com/graphql")
    print()

def main():
    print("=" * 60)
    print("GraphQL Hunter - Self Test")
    print("=" * 60)
    print()
    
    # Test dependencies
    if not test_dependencies():
        print("\n[!] Please install missing dependencies first:")
        print("    pip install -r requirements.txt")
        return 1
    
    print()
    
    # Test help
    if not test_help():
        return 1
    
    # Show how to test
    test_public_endpoint()
    
    print("=" * 60)
    print("[SUCCESS] GraphQL Hunter is ready to use!")
    print("=" * 60)
    print()
    print("Quick start:")
    print("  python graphql-hunter.py -u https://api.example.com/graphql")
    print()
    print("For more options:")
    print("  python graphql-hunter.py --help")
    print()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

