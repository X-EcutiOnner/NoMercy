import os, sys, zlib, subprocess, hashlib
from ftplib import FTP, FTP_TLS

MAJOR_VERSION = 1
HOST = "storage.bunnycdn.com"
PORT = 21
USERNAME = "nomercy-standart"
PASSWORD = "47bae25b-309f-4464-8454bec7e00b-7fbb-4861"

FILE_LIST = [
	# Local -						 						Remote - 									Optional		Listed
	["Bin\\NoMercy_Module_x86.dll",							"NoMercy_Module_x86.dll", 					False,			True],
	["extern\\bin\\CrashHandler\\crashpad_handler_x86.exe",	"NoMercy/NoMercy_Crash_Handler_x86.exe", 	False, 			True],
	["extern\\cert\\game_client_server\\public_key.pem", 	"NoMercy/NoMercy_Game.key",					False, 			False],
	["Bin\\NoMercy.cdb",									"NoMercy/NoMercy.cdb",						False, 			True],
	["Bin\\NoMercy_Game.dat",								"NoMercy/NoMercy_Game.dat",					False, 			False],
	["Bin\\NoMercy_Game.fdb",								"NoMercy/NoMercy_Game.fdb",					False, 			False],
	# ["Bin\\nomercy.pak",									"NoMercy/NoMercy.pak",						False, 			False],
	# ["document\\i18n_files\\en.json", 					"NoMercy/I18n/en.json", 					False, 			False],
	# ["document\\i18n_files\\tr.json", 					"NoMercy/I18n/tr.json", 					False, 			False],
]

def make_path(a, b):
	return os.path.normpath(os.path.join(a, b)).replace("\\", "/")

def get_crc32(filename):
	crc = 0
	with open(filename, "rb") as f:
		crc = zlib.crc32(f.read())
	return "%x" % (crc & 0xffFFffFF)

def get_sha256(filename):
	sha256_hash = hashlib.sha256()
	with open(filename, "rb") as f:
		for byte_block in iter(lambda: f.read(4096), b""):
			sha256_hash.update(byte_block)
	return sha256_hash.hexdigest()

def get_mtime(filename):
	# http://support.microsoft.com/kb/167296
	# How To Convert a UNIX time_t to a Win32 FILETIME or SYSTEMTIME
	EPOCH_AS_FILETIME = 116444736000000000 # January 1, 1970 as MS file time
	HUNDREDS_OF_NANOSECONDS = 10000000
	return EPOCH_AS_FILETIME + os.path.getmtime(filename) * HUNDREDS_OF_NANOSECONDS

class FTPClient:
	def __init__(self, host, port, username, password, tls = False):
		self.host = host
		self.port = port
		self.username = username
		self.password = password
		self.tls = tls
		
		self.client = None

		if self.tls:
			FTP_TLS.port = self.port
			self.client = FTP_TLS(self.host)
			self.client.prot_p()
		else:
			self.client = FTP(self.host)

		print(f"Client: {self.client}")

		res = self.client.login(self.username, self.password)
		print(f"Login result: {res}")		
  
	def __del__(self):
		self.client.quit()

	def has_directory(self, directory):
		return directory in self.client.nlst()

	def folder_exists(self, folder_path):
		currPath = self.client.pwd()
		try:
			self.client.cwd(folder_path)
			return True
		except Exception as e:
			# An exception will be raised if the folder doesn't exist
			return False
		finally:
			self.client.cwd(currPath)
   
	def create_directory(self, directory):
		return self.client.mkd(directory)

	def upload_file(self, local_path, remote_path):
		with open(local_path, 'rb') as f:
			self.client.storbinary(f'STOR {remote_path}', f)

	def exists(self, path):
		try:
			self.client.size(path)
			return True
		except:
			return False

	def delete(self, path):
		self.client.delete(path)

def main(args):
	if len(args) < 1:
		print("Usage: python upload_nomercy.py <version>")
		sys.exit(1)
  
	if not args[0].isdigit():
		print("Invalid version!")
		sys.exit(1)
  
	target_version = f"{MAJOR_VERSION}.0.0.{args[0]}"
	print(f"Target version: {target_version}")
 
	root = os.getcwd()
	print(f"Root: {root}")
  
	print("Generating list file...")

	file_list = []
	for file in FILE_LIST:
		fileLocalName = file[0]
		fileRemoteName = file[1]
		fileOptional = file[2]
		fileListed = file[3]
  
		print(f"Current file {fileLocalName} Target: {fileRemoteName}...")
  
		if not os.path.exists(fileLocalName):
			if not fileOptional:
				print(f"File {fileLocalName} not found!")
				sys.exit(1)
			else:
				print(f"File {fileLocalName} not found! Skipping...")
				continue
			
		file_elem = {}
		file_elem["path"] = make_path(root, fileLocalName)
		file_elem["real_path"] = fileRemoteName
		# crc32 calculation
		file_elem["crc32"] = get_crc32(file_elem["path"])
		# size calculation
		file_elem["size"] = os.path.getsize(file_elem["path"])
		# mtime calculation
		mtime = get_mtime(file_elem["path"])
		file_elem["mtime1"] = int(mtime) >> 32
		file_elem["mtime2"] = int(mtime) & 0xFFffFFff
		# mark as listed
		file_elem["listed"] = fileListed
		# add in list
		file_list.append(file_elem)
  
	tempPath = "temp"
	if os.path.exists(tempPath):
		os.system("rmdir /s /q %s" % tempPath)
	os.mkdir(tempPath)
 
	print("Generating crclist...")
 
	crclist = "temp\\crclist"
	if os.path.exists(crclist):
		os.remove(crclist)
 
	with open(crclist, "w") as f:
		for elem in file_list:
			if not elem["listed"]:
				continue
			buf = "%s %d %d %d %s\n" % (elem["crc32"], elem["size"], elem["mtime1"], elem["mtime2"], elem["real_path"])
			f.write(buf)
			print(buf.replace("\n", ""))
		
	print("Generating .lz files...")
 
	for elem in file_list:
		filepath_in = elem["path"]
		filepath_out = tempPath + "\\" + os.path.basename(elem["path"]) + ".lz"
  
		# create lz
		cmd = 'extern\\bin\\mt2lz.exe pack "%s" "%s"' % (filepath_in, filepath_out)
		subprocess.call(cmd, shell=True)
		# print("lz: " + cmd)
  
	client = FTPClient(HOST, PORT, USERNAME, PASSWORD)
	if not client:
		print("Failed to connect!")
		sys.exit(1)
  
	# Create version folder
	if not client.folder_exists(target_version):
		print(f"Creating version folder {target_version}...")
		client.create_directory(target_version)
  
	# Create latest folder
	if not client.folder_exists("latest"):
		print("Creating latest folder...")
		client.create_directory("latest")
    
	for file in FILE_LIST:
		fileLocalName = file[0]
		fileRemoteNameRaw = file[1]
		fileRemoteName = fileRemoteNameRaw + ".lz"
		fileOptional = file[2]
	
		print(f"Current file {fileLocalName} Target: {fileRemoteName}...")
	
		fileLocalNameRaw = fileLocalName
		fileLocalName = tempPath + "\\" + os.path.basename(fileLocalName) + ".lz"
		print(f"Packed file: {fileLocalName}")

		# Upload file to version folder
		target_file = make_path(target_version, fileRemoteName)
		print(f"#1 Target file: {target_file}")

		if client.exists(fileRemoteName):
			print(f"#1 Deleting existing file {fileRemoteName}...")
			client.delete(fileRemoteName)

		print(f"#1 Uploading file {fileLocalName}...")
		client.upload_file(fileLocalName, target_file)
		print("#1 Upload done!")
  
		# Upload non-lz variant to version folder
		target_file = make_path(target_version, fileRemoteNameRaw)
		print(f"#2 Target file: {target_file}")
		
		if client.exists(fileRemoteNameRaw):
			print(f"#2 Deleting existing file {fileRemoteNameRaw}...")
			client.delete(fileRemoteNameRaw)
   
		print(f"#2 Uploading file {fileRemoteNameRaw}...")
		client.upload_file(fileLocalNameRaw, target_file)
		print("#2 Upload done!")
  
		# Upload file to latest folder
		target_file = make_path("latest", fileRemoteName)
		print(f"#3 Target file: {target_file}")

		if client.exists(fileRemoteName):
			print(f"#3 Deleting existing file {fileRemoteName}...")
			client.delete(fileRemoteName)
   
		print(f"#3 Uploading file {fileLocalName}...")
		client.upload_file(fileLocalName, target_file)
		print("#3 Upload done!")
  
		# Upload non-lz variant to latest folder
		target_file = make_path("latest", fileRemoteNameRaw)
		print(f"#4 Target file: {target_file}")
  
		if client.exists(fileRemoteNameRaw):
			print(f"#4 Deleting existing file {fileRemoteNameRaw}...")
			client.delete(fileRemoteNameRaw)
   
		print(f"#4 Uploading file {fileRemoteNameRaw}...")
		client.upload_file(fileLocalNameRaw, target_file)
		print("#4 Upload done!")
	
	# Upload crclist file to version folder
	print("#1 Uploading crclist...")
	crclistRemote = make_path(target_version, "crclist")
	if client.exists(crclistRemote):
		print("#1 Deleting existing crclist...")
		client.delete(crclistRemote)
  
	print("#1 Uploading crclist...")
	client.upload_file(crclist, crclistRemote)
	print("#1 Upload done!")
 
	# Upload crclist file to latest folder
	print("#2 Uploading crclist...")
	crclistRemote = make_path("latest", "crclist")
	if client.exists(crclistRemote):
		print("#2 Deleting existing crclist...")
		client.delete(crclistRemote)
  
	print("#2 Uploading crclist...")
	client.upload_file(crclist, crclistRemote)
	print("#2 Upload done!")
 
	# Write current version to current file
	print("Writing current version...")
	with open("current", "w") as f:
		f.write(target_version)
  
  	# Upload current version
	print("Writing current version...")
	if client.exists("current"):
		print("Deleting existing current version file...")
		client.delete("current")
	
	client.upload_file("current", "current")

 	# Compute SHA-256 and write to latest_sha256 file
	sha256_hash = get_sha256("Bin\\NoMercy_Module_x86.dll")
	print(f"SHA-256: {sha256_hash}")
	with open("latest_sha256", "w") as f:
		f.write(sha256_hash)

	sha256Remote = make_path("latest", "NoMercy_Module_x86.hash")
	if client.exists(sha256Remote):
		print("Deleting existing sha256 hashfile...")
		client.delete(sha256Remote)

	client.upload_file("latest_sha256", sha256Remote)
	print("Uploaded latest_sha256 with SHA-256 hash.")

	print("Done!")

if __name__ == "__main__":
	main(sys.argv[1:])
