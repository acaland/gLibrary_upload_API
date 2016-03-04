import sys, logging

path = '/var/www/html/api/dm'

if path not in sys.path:
    sys.path.insert(0, path)

from dm import dm as application

print "setting logger handler"
handler = logging.FileHandler('/var/www/html/api/glibrary.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
application.logger.setLevel(logging.DEBUG)
application.logger.addHandler(handler)
