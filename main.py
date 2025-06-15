#!/usr/bin/env python3
"""
Red Team Platform - Main Entry Point
Use ghost_startup.py for secure ghost mode operations
"""

import os
import sys
from app import app

def main():
    """Main application entry point"""
    # Check if ghost mode is requested
    if '--ghost' in sys.argv or os.environ.get('GHOST_MODE', '').lower() == 'true':
        print("Starting in Ghost Mode...")
        from ghost_startup import main as ghost_main
        ghost_main()
    else:
        print("Starting in Standard Mode...")
        print("For enhanced security, use: python ghost_startup.py")
        
        # Standard mode with basic security
        app.config['DEBUG'] = False
        app.config['GHOST_MODE'] = False
        
        app.run(
            host='127.0.0.1',  # Localhost only for security
            port=5000,
            debug=False,
            threaded=True
        )

if __name__ == '__main__':
    main()
