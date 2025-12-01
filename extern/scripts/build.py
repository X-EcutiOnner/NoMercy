import os, sys, subprocess, shutil, argparse

def main(args):
	print(f"[build.py] Current working directory: {os.getcwd()}")

	# Sanity check
	argCount = len(args)
	if not args or argCount < 4:
		print(f"Not enough arguments: {argCount}, expected: 4")
		return 1
 
	parser = argparse.ArgumentParser(description="Build script with command-line arguments")
	parser.add_argument("--arch", choices=["x86", "x64"], help="Architecture (x86 or x64)")
	parser.add_argument("--build_mode", choices=["Debug", "Release", "RelWithDebInfo", "MinSizeRel"], help="Build mode")
	parser.add_argument("--driver_only", nargs='?', const=True, default=False, help="Build only driver")
	parser.add_argument("--rebuild", nargs='?', const=True, default=False, help="Rebuild option")
	parser.add_argument("--branch_name", help="Branch name")

	args = parser.parse_args(args)

	stageDict = {
		"develop": "dev",
		"staging": "beta",
		"master": "live",
		"lite": "live"
	}
 
	branchName = args.branch_name
	if not branchName:
		branchName = os.getenv('GIT_BRANCH')
	if not branchName:
		print(f"Undefined branch name!")
		return 1

	if "/" in branchName:
		branchName = branchName.split("/")[-1]
 
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
		if args.rebuild:
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
	if args.arch == "x86":
		cmd = f"cmake .. -A Win32 -DCMAKE_BUILD_TYPE={args.build_mode} -DCI_BUILD=1 -DBRANCH_NAME={stage}"
		if args.driver_only:
			cmd += " -DBUILD_ONLY_DRIVER=1"
		commands.append(cmd)
	else:
		cmd = f"cmake .. -DCMAKE_BUILD_TYPE={args.build_mode} -DCI_BUILD=1 -DBRANCH_NAME={stage}"
		if args.driver_only:
			cmd += " -DBUILD_ONLY_DRIVER=1"
		commands.append(cmd)
	
	commands.append(f"cmake --build . --config {args.build_mode} --target ALL_BUILD -- /m /property:GenerateFullPaths=true /property:CharacterSet=Unicode")
	
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
 