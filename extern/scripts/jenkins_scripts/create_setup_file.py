import os, sys, subprocess

SETUP_FILE_NAME = "extern\\scripts\\nomercy.iss"
INNO_SETUP_CLI = "C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe"

def __fix_version(version):
	# Open the file
	fp = open(SETUP_FILE_NAME, "r+")
	if not fp:
		print("Could not open setup script file!")
		return False

	# Read the file
	lines = fp.readlines()
	if not lines:
		print("Could not read setup script file!")
		return False

	# Find version line
	for i in range(len(lines)):
		if lines[i].startswith("#define MyAppVersion"):
			oldVersion = lines[i].split()[2]
			print(f"Found version line: ${lines[i]} (old version: {oldVersion})")
			lines[i] = lines[i].replace(oldVersion, f"\"1.{version}\"")
			print(f"New version line: ${lines[i]}")
			break

	# Save changes
	fp.seek(0)
	fp.truncate()
	fp.writelines(lines)
	fp.close()

	return True

def __run_setup_compiler():
	print("Creating setup file...")
	
	cmd = f"\"{INNO_SETUP_CLI}\" {SETUP_FILE_NAME}"
	print("cmd: {0}".format(cmd))
  
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	out, err = p.communicate()

	if (p.returncode != 0):
		err = err.decode("utf-8")
		print("[__run_setup_compiler] Error: [{0}] {1}".format(p.returncode, err))
		return False
	
	out = out.decode("utf-8")
	print("[__run_setup_compiler] out: {0}".format(out))
	return True

def main(args):
	version = 25000 + int(os.getenv('BUILD_NUMBER'))
	print(f"[create_setup_file.py] Current working directory: {os.getcwd()} Version: {version}")
    
    # Check if the setup file exists
	if not os.path.exists(SETUP_FILE_NAME):
		print("Setup script file does not exist!")
		return 1

	# Check if the Inno Setup CLI exists
	if not os.path.exists(INNO_SETUP_CLI):
		print("Inno Setup CLI does not exist!")
		return 1

	# Fix setup file version
	if not __fix_version(version):
		print("Failed to fix version from setup script file!")
		return 1

	# Run Inno Setup CLI
	if not __run_setup_compiler():
		print("Failed to run Inno Setup CLI!")
		__fix_version(0)
		return 1

	__fix_version(0)
	return 0

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
