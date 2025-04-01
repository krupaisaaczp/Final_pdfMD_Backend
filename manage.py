#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    
    # Check if no arguments are provided or if 'runserver' is explicitly called
    if len(sys.argv) == 1 or sys.argv[1] == 'runserver':
        # Default to port 8000 locally, use PORT env var on Render
        port = os.environ.get('PORT', '8000')
        # Modify argv to include runserver with the correct port if not already specified
        if len(sys.argv) == 1:
            sys.argv = ['manage.py', 'runserver', f'0.0.0.0:{port}']
        elif sys.argv[1] == 'runserver' and len(sys.argv) == 2:
            sys.argv.append(f'0.0.0.0:{port}')
    
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()