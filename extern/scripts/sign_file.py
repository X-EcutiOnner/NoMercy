import os, sys, subprocess, time, glob

try:
	import requests
except ImportError:
	print("Installing requests package...")
	os.system("python -m pip install requests")
 
import requests

SIGNTOOL_BASE_PATH = "C:\\Program Files (x86)\\Windows Kits\\10\\bin"
SIGN_SHA_HASH = "0a9fd5add9222ccbff19334875057e961706a140"
CA_CERT_PATH = ""

def signFile(signtoolExecutable, timestampServer, filePath):
	global CA_CERT_PATH
	print(f"Signing file: {filePath} with timestamp server: {timestampServer}")
 
	cmd = f"{signtoolExecutable} sign /debug /v /ac {CA_CERT_PATH} /sha1 {SIGN_SHA_HASH} /tr {timestampServer} /td SHA256 /fd SHA256 /d \"NoMercy Anti Cheat\" /a {filePath}"
	print(f"Sign command: {cmd}")
	
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	out, err = p.communicate()
 
	if (p.returncode != 0):
		err = err.decode("utf-8")
		print(f"Sign error: [{p.returncode}] {err}")
		print(f"Sign response: {out}")
		return 1
 
	out = out.decode("utf-8")
	print(f"Succesfully signed, Out: {out}")
 
	return 0

def main(args):
	print(f"[sign_file.py] Current working directory: {os.getcwd()}")

	global CA_CERT_PATH
	CA_CERT_PATH = os.getcwd().split(".build")[0] + "extern\\cert\\GlobalSign_Root_R45-Cross.crt"
	print(f"CA_CERT_PATH: {CA_CERT_PATH}")
 
	if (not CA_CERT_PATH or not os.path.exists(CA_CERT_PATH)):
		print(f"CA certificate not found: {CA_CERT_PATH}")
		return 1
 
	# Sanity check
	targetFile = args[0]
	if not targetFile or not os.path.exists(targetFile):
		print(f"Target file: {targetFile} is invalid")
		return 1

	if not os.path.exists(SIGNTOOL_BASE_PATH):
		print("ERROR: Windows 10 SDK not installed")
		return 1
  
	# Sort SIGNTOOL_BASE_PATH folders by creation date (newest first)
	signtoolExecutable = None
	for sign_tool_path in sorted(glob.glob(SIGNTOOL_BASE_PATH + "\\*"), key=os.path.getctime, reverse=True):
		signtoolExecutable = f"{sign_tool_path}{os.path.sep}x64{os.path.sep}signtool.exe"
		print(f"Checking signtool: {signtoolExecutable}")
  
		if os.path.exists(signtoolExecutable):
			print(f"Found signtool.exe at: {signtoolExecutable}")
			signtoolExecutable = f"\"{signtoolExecutable}\""
			break
	
	if not signtoolExecutable:
		print("ERROR: Could not find signtool.exe")
		return 1
 
	# Try to run Signtool.exe
	cmd = f"{signtoolExecutable} /?"
	
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	out, err = p.communicate()
 
	if (p.returncode != 0):
		err = err.decode("utf-8")
		print("SignTool.exe test call failed: [{0}] {1}".format(p.returncode, err))
		return 1

	timestampServers = [
		"http://timestamp.digicert.com",
		"http://timestamp.globalsign.com/tsa/r6advanced1",
		"http://timestamp.sectigo.com"
	]
 
	print("Checking timestamp server availability...")
 
	attemptCountLimit = 40
	attemptIntervalSec = 3
	for i in range(len(timestampServers)):
		print(f"[{i}] Timestamp server: {timestampServers[i]}")
 
		for j in range(attemptCountLimit):
			print(f"[{j}/{attemptCountLimit}] Attempting to query timestamp server...")
   
			"""
			canSign = False
			try:
				r = requests.get(timestampServers[i])
				if r.status_code == 200:
					print(f"Timestamp server: {timestampServers[i]} is available")
					canSign = True
				else:
					print(f"Timestamp server: {timestampServers[i]} returned status code: {r.status_code}")
			except Exception as e:
				print(f"Timestamp server: {timestampServers[i]} failed with exception: {e}")
			"""
			canSign = True
 
			if canSign:
				signRet = signFile(signtoolExecutable, timestampServers[i], targetFile)
				if signRet == 0:
					print("Successfully signed file!")
					return 0

			print(f"Sign failed, Waiting {attemptIntervalSec} seconds for next attempt!")
			time.sleep(attemptIntervalSec)
	
	print("All timestamp attempts are failed!")
	return 1

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
 