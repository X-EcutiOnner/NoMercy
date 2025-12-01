import os, sys, subprocess, shutil

def main(args):
	print(f"[build.py] Current working directory: {os.getcwd()}")
 
	# Sanity check
	argCount = len(args)
	if not args or argCount < 4:
		print(f"Usage: {sys.argv[0]} <arch> <build_mode> <driver_only> <rebuild> <branch_name>")
		return 1
 
	allowedArchs = ["x86", "x64"]
	arch = args[0]
	if arch not in allowedArchs:
		print(f"Invalid arch: {arch}, allowed: {allowedArchs}")
		return 1

	allowedBuildModes = ["Debug", "Release", "RelWithDebInfo", "MinSizeRel"]
	buildMode = args[1]
	if buildMode not in allowedBuildModes:
		print(f"Invalid build mode: {buildMode}, allowed: {allowedBuildModes}")
		return 1
	
	driverOnly = args[2]
	if driverOnly != "0" and driverOnly != "1":
		print(f"Invalid driver only: {driverOnly}, allowed: 0 or 1")
		return 1

	isRebuild = args[3]
	if isRebuild != "0" and isRebuild != "1":
		print(f"Invalid rebuild: {isRebuild}, allowed: 0 or 1")
		return 1
	isRebuild = isRebuild == "1"
	
	stageDict = {
		"develop": "dev",
		"staging": "beta",
		"master": "live",
	}
 
	branchName = args[4] if argCount > 4 else None
	if not branchName:
		branchName = os.getenv('GIT_BRANCH')
	if not branchName:
		print(f"Undefined branch name!")
		return 1

	if "/" in branchName:
		branchName = branchName.split("/")[1]
 
	if branchName not in stageDict:
		print(f"Invalid branch name: {branchName}, allowed: {stageDict.keys()}")
		return 1
	stage = stageDict[branchName]
 
	targetPath = f"{os.getcwd()}{os.path.sep}.build"
	print(f"Target path: {targetPath}")
 
	buildPathExist = False
	if os.path.exists(targetPath):
		buildPathExist = True
		print(f"Path: {targetPath} already exists")
		if isRebuild:
			shutil.rmtree(targetPath)
			if os.path.exists(targetPath):
				print(f"Old path: {targetPath} still exists")
				return 1
			else:
				buildPathExist = False
	
	# Create path
	if not buildPathExist:
		try:
			os.makedirs(targetPath)
		except Exception as e:
			print(f"Failed to create path: {targetPath}, error: {e}")
			return 1

	# Set working directory to target path
	os.chdir(targetPath)
 
	# Create project
	commands = []
	if arch == "x86":
		cmd = f"cmake .. -A Win32 -DCMAKE_BUILD_TYPE={buildMode} -DCI_BUILD=1 -DBRANCH_NAME={stage}"
		if driverOnly == "1":
			cmd += " -DBUILD_ONLY_DRIVER=1"
		commands.append(cmd)
	else:
		cmd = f"cmake .. -DCMAKE_BUILD_TYPE={buildMode} -DCI_BUILD=1 -DBRANCH_NAME={stage}"
		if driverOnly == "1":
			cmd += " -DBUILD_ONLY_DRIVER=1"
		commands.append(cmd)
  
	commands.append(f"cmake --build . --config {buildMode} --target ALL_BUILD -- /m /property:GenerateFullPaths=true /property:CharacterSet=Unicode")
  
	# Build project
	for cmd in commands:
		print(f"Executing command: {cmd}")
		# Run command
		proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding=None, shell=True)

		while proc.poll() is None:
			output = proc.stdout.readline().strip()
			try:
				output = output.decode("utf-8")
			except UnicodeDecodeError:
				print("\n*Output has invalid (non utf-8) characters! Invalid output: {}\n".format(output))
				# raise
			if output:
				print(output)

		# Check return code
		if proc.returncode:
			return proc.returncode

	return 0

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
 