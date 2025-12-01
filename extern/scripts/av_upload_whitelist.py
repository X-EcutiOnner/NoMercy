import os
try:
	import zipfile
except ImportError:
	print("Installing zipfile package...")
	os.system("python -m pip install zipfile")
try:
	import ftplib
except ImportError:
	print("Installing ftplib package...")
	os.system("python -m pip install ftplib")

import sys, time, smtplib, fnmatch, zipfile, smtplib
from ftplib import FTP, FTP_TLS

BIN_PATH = f'{os.getcwd()}{os.path.sep}Bin'
SCAN_WHITELIST = [
	"NoMercy_Launcher_x*.exe",
	"NoMercy_Loader_x*.dll",
	"NoMercy_Module_x*.dll",
	"NoMercy_Service_x*.exe",
	"NoMercy_Setup_x*.exe",
	"NoMercy_SystemModule_x*.sys",
	"NoMercy_Telemetry_x*.exe",
	"NoMercy_Uninstall.exe"
]

AV_VENDORS = [

]

def main(args):
	if not len(AV_VENDORS):
		return 0
    
	fileList = args
	print('Uploading anti-cheat components... Path: {} Args: {}'.format(os.getcwd(), fileList))
 
	if not fileList:
		fileList = [f for f in os.listdir(BIN_PATH)]
		if fileList:
			matched_objects = []
			for pattern in SCAN_WHITELIST:
				matched_objects.extend(fnmatch.filter(fileList, pattern))
			fileList = matched_objects

	print('Files to be upload: {}'.format(fileList))
 
	if not fileList:
		print('No files to be upload.')
		return 1

	# Add BIN_PATH to file list
	fileList = [os.path.join(BIN_PATH, file) for file in fileList]
	
	# Upload files to vendors
	for vendor in AV_VENDORS:
		print('Uploading files to {}...'.format(vendor['NAME']))

		if vendor['ZIP'] is not None:
			print('Zipping files... Path: {}'.format(vendor['ZIP']))
			if os.path.exists(vendor['ZIP']):
				os.remove(vendor['ZIP'])

			zipFile = zipfile.ZipFile(vendor['ZIP'], 'w')
			for file in fileList:
				zipFile.write(file, os.path.basename(file), zipfile.ZIP_DEFLATED)
			zipFile.close()
			print('Zipping files done.')
			fileList = [os.path.join(os.getcwd(), vendor['ZIP'])]
			
		if vendor['SERVER']['TYPE'] == 'FTP' or vendor['SERVER']['TYPE'] == 'FTPS':
			remotePath = time.strftime("%Y%m%d-%H%M%S")
			print('Uploading files to {} via FTP...'.format(remotePath))
			if vendor['SERVER']['TYPE'] == 'FTPS':
				FTP_TLS.port = vendor['SERVER']['PORT']
				ftp = FTP_TLS(vendor['SERVER']['HOST'])
			else:
				ftp = FTP(vendor['SERVER']['HOST'])
			ftp.login(vendor['SERVER']['USER'], vendor['SERVER']['PWD'])
			if vendor['SERVER']['TYPE'] == 'FTPS':
				ftp.prot_p()
			# create destination directory with current timestamp
			ftp.mkd(remotePath)
			ftp.cwd(remotePath)
			for fileName in fileList:
				print('Uploading file via FTP... File: {}'.format(fileName))
				with open(fileName, 'rb') as file:
					ftp.storbinary('STOR ' + os.path.basename(fileName), file)
				print('Uploading file via FTP done.')
			ftp.quit()
			print('Uploading files via FTP done.')
			os.remove(vendor['ZIP'])
		elif vendor['SERVER']['TYPE'] == 'SMTP':
			print('Uploading files via SMTP...')
			server = smtplib.SMTP(vendor['SERVER']['HOST'], 587)
			server.starttls()
			server.login(vendor['SERVER']['USER'], vendor['SERVER']['PWD'])
			for fileName in fileList:
				print('Uploading file via SMTP... File: {}'.format(fileName))
				with open(fileName, 'rb') as file:
					msg = file.read()
					server.sendmail(vendor['SERVER']['USER'], vendor['SERVER']['USER'], msg)
				print('Uploading file via SMTP done.')
			server.quit()
			print('Uploading files via SMTP done.')
		else:
			print('Unknown server type: {}'.format(vendor['SERVER']['TYPE']))
			return 1
	return 0

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
