import os
from ftplib import FTP, FTP_TLS
import config_data
from log_helper import log, ERROR_LOG, INFO_LOG

class FTPClient:
	def __init__(self, host, port, username, password, tls = False):
		self.host = host
		self.port = port
		self.username = username
		self.password = password
		self.tls = tls
		
		self.client = None
		
	def __enter__(self):
		if self.tls:
			FTP_TLS.port = self.port
			self.client = FTP_TLS(self.host)
			self.client.prot_p()
		else:
			self.client = FTP(self.host)

		self.client.login(self.username, self.password)
		
	def __exit__(self, exc_type, exc_value, traceback):
		self.client.quit()

	def has_directory(self, directory):
		return directory in self.client.nlst()

	def create_directory(self, directory):
		return self.client.mkd(directory)

	def upload_file(self, local_path, remote_path):
		with open(local_path, 'rb') as f:
			self.client.storbinary(f'STOR {remote_path}', f)

def initialize():
	if not config_data.ftp_hosts:
		log(INFO_LOG, "No sftp hosts found!")
		return True # FTP is optional

	for host in config_data.ftp_hosts:
		if "endpoint" not in host or "port" not in host or "username" not in host:
			log(ERROR_LOG, "Invalid sftp host configuration!")
			continue

		if "password" not in host and "private_key" not in host:
			log(ERROR_LOG, "Missing sftp host password or private key!")
			continue

		client = None
		if "password" in host:
			client = FTPClient(host["endpoint"], host["port"], host["username"], host["password"])
		else:
			client = FTPClient(host["endpoint"], host["port"], host["username"], host["private_key"], True)

		idx = config_data.ftp_hosts.index(host)
		config_data.ftp_hosts[idx]["client"] = client
		log(INFO_LOG, f"Initialized sftp host: {host['name']}")
		
	return True