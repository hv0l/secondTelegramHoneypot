import configparser
import socket
import threading
import logging
from flask import Flask, request
from paramiko import ServerInterface
from telegram import Update
from telegram.ext import Updater, CommandHandler, CallbackContext
import matplotlib.pyplot as plt
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import sqlite3






def print_honeypot_ascii_art():
    art = r"""
 _                                        _        _           ___   ___  
 | |                                      | |      | |         / _ \ / _ \ 
 | |__   ___  _ __   ___ _   _ _ __   ___ | |_     | |____   _| | | | | | |
 | '_ \ / _ \| '_ \ / _ \ | | | '_ \ / _ \| __|    | '_ \ \ / / | | | | | |
 | | | | (_) | | | |  __/ |_| | |_) | (_) | |_     | | | \ V /| |_| | |_| |
 |_| |_|\___/|_| |_|\___|\__, | .__/ \___/ \__|    |_| |_|\_/  \___/ \___/ 
                          __/ | |           ______                      
                         |___/|_|          |______|                     
    """
    print(art)





print_honeypot_ascii_art()







config = configparser.ConfigParser()
config.read('config.ini')
telegram_token = config['Telegram']['token']



updater = Updater(token=telegram_token)
dispatcher = updater.dispatcher



logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    logger.info(f'Tentativo di login: {username}:{password}')
    return "Accesso non riuscito", 401


def create_database():
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS connections (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                     ip TEXT,
                     port INTEGER,
                     username TEXT,
                     password TEXT
                 )''')
    conn.commit()
    conn.close()

create_database()




def start_http_server():
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')

class DummySSHServer(SSHServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

def handle_ssh_connection(client_socket, address):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(paramiko.RSAKey.generate(1024))
    server = DummySSHServer()
    transport.start_server(server=server)

def start_ssh_server():
    ssh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssh_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssh_socket.bind(('0.0.0.0', 22))
    ssh_socket.listen(1)

    while True:
        client_socket, address = ssh_socket.accept()
        logger.info(f'Connessione SSH da {address}')
        threading.Thread(target=handle_ssh_connection, args=(client_socket, address)).start()


def handle_http_request(client, address):
    global logger
    request = client.recv(1024).decode()
    timestamp = datetime.datetime.now()

 

    if username and password:

        conn = sqlite3.connect('honeypot.db')
        c = conn.cursor()
        c.execute("INSERT INTO connections (ip, port, username, password) VALUES (?, ?, ?, ?)",
                  (address[0], address[1], username, password))
        conn.commit()
        conn.close()



def handle_ssh_connection(client, address):
    global logger
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    c.execute("INSERT INTO connections (ip, port) VALUES (?, ?)", (address[0], address[1]))
    conn.commit()
    conn.close()



def start_ftp_server():
    authorizer = DummyAuthorizer()
    handler = FTPHandler
    handler.authorizer = authorizer
    server = FTPServer(('0.0.0.0', 21), handler)
    server.serve_forever()
    
    
    
def log_to_telegram(update, context):

    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    c.execute("SELECT timestamp, ip, port, username, password FROM connections")
    rows = c.fetchall()
    conn.close()




    log_output = ""
    for row in rows:
        timestamp, ip, port, username, password = row
        log_entry = f"[{timestamp}] Connection from {ip}:{port}"
        if username and password:
            log_entry += f" - Attempted login with {username}:{password}"
        log_output += log_entry + "\n"

    context.bot.send_message(chat_id=update.message.chat_id, text=log_output)




def graph(bot, update):
    dates = [log.date for log in logger.handlers[0].stream.getvalue().splitlines()]
    plt.hist(dates, bins=len(set(dates)))
    plt.xlabel('Date')
    plt.ylabel('Numero di connessioni')
    plt.title('Connessioni al honeypot')
    plt.savefig('graph.png')
    with open('graph.png', 'rb') as f:
        bot.send_photo(chat_id=update.message.chat_id, photo=f)



dispatcher.add_handler(CommandHandler('log', log_to_telegram))
dispatcher.add_handler(CommandHandler('graph', graph))



def main():
    print("Sto per aprire le porte 21 (FTP), 443 (HTTP) e 22 (SSH).")
    choice = input("Vuoi continuare? (sì/no): ").lower()

    if choice == "sì" or choice == "si":
        # Avvia il server FTP in un thread separato
        ftp_thread = threading.Thread(target=start_ftp_server)
        ftp_thread.start()

        # Avvia il server HTTP e SSH in thread separati
        http_thread = threading.Thread(target=start_http_server)
        http_thread.start()

        ssh_thread = threading.Thread(target=start_ssh_server)
        ssh_thread.start()

        # Avvia il bot Telegram
        updater.start_polling()
        updater.idle()
    else:
        print("Operazione annullata.")



if __name__ == '__main__':
    main()
