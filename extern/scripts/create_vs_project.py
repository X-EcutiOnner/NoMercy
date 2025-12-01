import os, sys, subprocess

def main(args):
	print(f"[create_vs_project.py] Current working directory: {os.getcwd()}")
 
	# Sanity check
	if not args:
		print(f"Usage: {sys.argv[0]} <arch> <build_mode>")
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
	
	buildModeSuffix = "d" if buildMode == "Debug" else "r"
 
	targetPath = f"{os.getcwd()}{os.path.sep}.vs_proj_{arch}_{buildModeSuffix}"
	print(f"Target path: {targetPath}")
 
	if os.path.exists(targetPath):
		print(f"Path: {targetPath} already exists")
		try:
			os.rename(targetPath, f"{targetPath}.old")
		except Exception as e:
			print(f"Failed to rename: {targetPath}, error: {e}")
		if os.path.exists(targetPath):
			print(f"Old path: {targetPath} still exists")
			return 1

	# Create path
	try:
		os.makedirs(targetPath)
	except Exception as e:
		print(f"Failed to create path: {targetPath}, error: {e}")
		return 1

	# Set working directory to target path
	os.chdir(targetPath)
 
	# Create project
	cmd = ""
	if arch == "x86":
		cmd = f"cmake .. -A Win32 -DCMAKE_BUILD_TYPE={buildMode}"
	else:
		cmd = f"cmake .. -DCMAKE_BUILD_TYPE={buildMode}"
  
	print(f"Running command: {cmd}")
 
	# Run command
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	out, err = p.communicate()
	
	# Print output
	if (p.returncode != 0):
		err = err.decode("utf-8")
		print(f"Error: {err}")
		return 1

	out = out.decode("utf-8")
	print(f"Output: {out}")
	return 0

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
 