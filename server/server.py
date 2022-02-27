# need to pip install pyftpdlib
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
ENCRYPTED_DATA_DIR = BASE_DIR / 'server' / 'data'

authorizer = DummyAuthorizer() # handle permission and user
authorizer.add_anonymous("D:/SP School/Y1 SEM2/ACG/Assignment 2/assignment_base/source/server/data" , perm='adfmwM')
handler = FTPHandler #  understand FTP protocol
handler.authorizer = authorizer
server = FTPServer(("127.0.0.1", 2121), handler) # bind to high port, port 21 need root permission
server.serve_forever()
