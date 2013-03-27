import sys

path = '/var/www/html/api/dm'

if path not in sys.path:
    sys.path.insert(0, path)

from dm import dm as application
