import os, sys, subprocess

def main(args):
	print(f"[upload_patch_files.py] Current working directory: {os.getcwd()}")

	# Sanity check
	if not args:
		print("Any arguments were provided")
		return 1

	for i in range(len(args)):
		print(f"[{i}] Argument: {args[i]}")
  
	# Convert arg list to string
	argsStr = " ".join(args)
  
	# Run the script
	cmd = f"{os.getcwd()}{os.path.sep}extern{os.path.sep}sub_projects{os.path.sep}PatchUploader.exe {argsStr}"
	print("cmd: {0}".format(cmd))
  
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	out, err = p.communicate()
	
	if err:
		err = err.strip()
		try:
			err = err.decode("utf-8")
		except UnicodeDecodeError:
			print("\n*Error has invalid (non utf-8) characters! Invalid error: {}\n".format(err))
			raise
	if out:
		out = out.strip()
		try:
			out = out.decode("utf-8")
		except UnicodeDecodeError:
			print("\n*Output has invalid (non utf-8) characters! Invalid output: {}\n".format(out))
			raise
	
	out = str(out)

	if "\n" in out:
		for line in out.split('\n'):
			print("{0}\n".format(line))
	else:
		print("{0}".format(out))

	if (p.returncode != 0):
		print("Error: Process return code: [{0}]".format(p.returncode))
		err = str(err)
		if "\n" in err:
			for line in err.split('\n'):
				print("{0}\n".format(line))
		else:
			print("{0}".format(err))
		return 1

	return 0

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
