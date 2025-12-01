import os, sys, subprocess

def main(args):
	# Sanity check
	if not args:
		print("Usage: move_debug_symbols.py <arch>")
		return 1

	# Get the version and validate it
	arch = args[0]
	if not arch or arch not in ("x86", "x64"):
		print(f"Invalid arch: {arch}")
		return 1
	
	# Get the path to the debug symbols
	workPath = f"{os.path.dirname(os.path.realpath(__file__))}{os.path.sep}..{os.path.sep}debug_symbols{os.path.sep}{arch}{os.path.sep}"
	print(f"Work path: {workPath}")
 
	if not os.path.exists(workPath):
		print("Debug symbols path does not exist")
		return 1

	# Declare the list of files to move
	targetDir = f"{os.path.dirname(os.path.realpath(__file__))}{os.path.sep}..{os.path.sep}..{os.path.sep}bin{os.path.sep}"
	print(f"Target dir: {targetDir}")
 
	if not os.path.exists(targetDir):
		print("Target dir does not exist")
		# Create the target dir
		os.makedirs(targetDir)
		# Check if the target dir was created
		if not os.path.exists(targetDir):
			print("Failed to create target dir")
			return 1

	# Move the files
	for file in os.listdir(workPath):
		if file.endswith(".pdb"):
			print(f"Moving {file}")
			os.rename(f"{workPath}{file}", f"{targetDir}{file}")
   
	return 0

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
