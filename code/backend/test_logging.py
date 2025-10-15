#!/usr/bin/env python3
"""
Test script to verify logging functionality in both development and packaged environments
"""

import os
import sys
import json
from logs import log_operation, get_log_stats

def test_logging():
    """Test logging functionality"""
    print("Testing logging functionality...")
    
    # Log a test operation
    log_operation("TEST_OPERATION", "STARTED", {"test": "value"})
    log_operation("TEST_OPERATION", "SUCCESS", {"test": "value", "result": "passed"})
    
    # Get log stats
    stats = get_log_stats()
    
    print("Log stats:")
    print(json.dumps(stats, indent=2))
    
    # Verify logs were created
    if stats["total_operations"] >= 2:
        print("SUCCESS: Logging is working correctly")
        return True
    else:
        print("ERROR: Logging may not be working correctly")
        return False

if __name__ == "__main__":
    test_logging()