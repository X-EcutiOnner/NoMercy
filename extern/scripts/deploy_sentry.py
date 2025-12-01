from operator import contains
import os, sys, subprocess, shutil, hashlib, re

EXPIRE_TIME_AS_HOUR = 24 * 7 # 7 days

class SentryWorker:
	def __init__(self, argv):
		self.__argv = argv
		
		self.__sentry_log_level = None
		self.__sentry_url = None
		self.__sentry_auth_token = None
		self.__sentry_organization = None
		self.__sentry_project = None
		self.__sentry_environment = None
		self.__pipeline_version = None

		self.__parse_args()

	def __parse_args(self):
		if (len(self.__argv) < 2 or self.__argv[1] == "--help"):
			print("Usage: py {0} [--log_level level] [--url url] [--auth_token token] [--organization org] [--project p] [--environment env]".format(sys.argv[0]))
			sys.exit(1)

		if (self.__argv.__contains__("--log_level")):
			if (self.__argv.index("--log_level") + 1 > len(self.__argv)):
				print("Error: log_level is missing.")
				sys.exit(1)
			self.__sentry_log_level = self.__argv[self.__argv.index("--log_level") + 1]
			print("log_level: {0}".format(self.__sentry_log_level))
		else:
			print("'log_level' key missing!")
			sys.exit(1)
   
		if (self.__argv.__contains__("--url")):
			if (self.__argv.index("--url") + 1 > len(self.__argv)):
				print("Error: url is missing.")
				sys.exit(1)
			self.__sentry_url = self.__argv[self.__argv.index("--url") + 1]
			print("url: {0}".format(self.__sentry_url))
		else:
			print("'url' key missing!")
			# sys.exit(1)
   
		if (self.__argv.__contains__("--auth_token")):
			if (self.__argv.index("--auth_token") + 1 > len(self.__argv)):
				print("Error: auth_token is missing.")
				sys.exit(1)
			self.__sentry_auth_token = self.__argv[self.__argv.index("--auth_token") + 1]
			print("auth_token: {0}".format(self.__sentry_auth_token))
		else:
			print("'auth_token' key missing!")
			sys.exit(1)
   
		if (self.__argv.__contains__("--organization")):
			if (self.__argv.index("--organization") + 1 > len(self.__argv)):
				print("Error: organization is missing.")
				sys.exit(1)
			self.__sentry_organization = self.__argv[self.__argv.index("--organization") + 1]
			print("organization: {0}".format(self.__sentry_organization))
		else:
			print("'organization' key missing!")
			sys.exit(1)
   
		if (self.__argv.__contains__("--project")):
			if (self.__argv.index("--project") + 1 > len(self.__argv)):
				print("Error: project is missing.")
				sys.exit(1)
			self.__sentry_project = self.__argv[self.__argv.index("--project") + 1]
			print("project: {0}".format(self.__sentry_project))
		else:
			print("'project' key missing!")
			sys.exit(1)
   
		if (self.__argv.__contains__("--environment")):
			if (self.__argv.index("--environment") + 1 > len(self.__argv)):
				print("Error: environment is missing.")
				sys.exit(1)
			self.__sentry_environment = self.__argv[self.__argv.index("--environment") + 1]
			print("environment: {0}".format(self.__sentry_environment))
		else:
			print("'environment' key missing!")
			sys.exit(1)
   
		if (self.__argv.__contains__("--pipeline_version")):
			if (self.__argv.index("--pipeline_version") + 1 > len(self.__argv)):
				print("Error: pipeline_version is missing.")
				sys.exit(1)
			self.__pipeline_version = self.__argv[self.__argv.index("--pipeline_version") + 1]
			print("pipeline_version: {0}".format(self.__pipeline_version))
		else:
			print("'pipeline_version' key missing!")
			sys.exit(1)
   
	def run(self):
		self.__auth_sentry()
		if self.__sentry_project != "nomercy-setup":
			self.__list_bin_packages()
			# self.__get_sentry_info()
		self.__clear_old_releases()
		self.__create_release()
		self.__deploy_debug_symbols()
		self.__finalize_release()
		return 0
  
	def __get_md5(self, file_path):
		with open(file_path, 'rb') as f:
			return hashlib.md5(f.read()).hexdigest()

	def __auth_sentry(self):
		print("Authenticating sentry...")

		cmd = f"{os.getcwd()}{os.path.sep}extern{os.path.sep}bin{os.path.sep}sentry-cli.exe --log-level {self.__sentry_log_level} --auth-token {self.__sentry_auth_token} login"
		print("cmd: {0}".format(cmd))
  
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		out, err = p.communicate()

		if (p.returncode != 0):
			err = err.decode("utf-8")
			print("[__auth_sentry] Error: [{0}] {1}".format(p.returncode, err))
			sys.exit(1)
   
		out = out.decode("utf-8")
		print("[__auth_sentry] out: {0}".format(out))
  
	def __clear_old_releases(self):
		print("Getting sentry releases...")

		cmd = f"{os.getcwd()}{os.path.sep}extern{os.path.sep}bin{os.path.sep}sentry-cli.exe releases --org {self.__sentry_organization} --project {self.__sentry_project} list"
		print("cmd: {0}".format(cmd))
  
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		out, err = p.communicate()

		if (p.returncode != 0):
			err = err.decode("utf-8")
			print("[__clear_old_releases] Error: [{0}] {1}".format(p.returncode, err))
			sys.exit(1)
   
		out = out.decode("utf-8")
		# print("[__clear_old_releases] out: {0}".format(out))
  
		idx = 0
		# create a list of releases
		releases = out.split("\n")
		# remove first 3 lines (header)
		releases = releases[3:]
		# create a list of expired releases
		expired_releases = []
  
		for release in releases:
			idx += 1
   
			if not release:
				continue
			if not release.__contains__("|"):
				continue
   
			release = release.split("|")
			# remove first element
			release.pop(0)
   
			release_date = release[0].strip()
			release_version = release[1].strip()

			print("[{0}] release: {1} {2}".format(idx, release_version, release_date))
   
			is_expired = False
			if (release_date == "(unreleased)"):
				is_expired = True
			elif (release_date.__contains__("minutes ago")):
				continue
			elif (release_date.__contains__("hour ago")):
				continue
			elif (release_date.__contains__("hours ago")):
				release_date_hour = int(release_date.split(" hours ago")[0])
				if (release_date_hour > EXPIRE_TIME_AS_HOUR):
					is_expired = True
			else:
				print("[__clear_old_releases] Error: unknown release date format: {0}".format(release_date))
				# sys.exit(1)	

			if (is_expired):
				expired_releases.append(release_version)
				# print("[__clear_old_releases] expired release: {0}".format(release_version))
    
		print("[__clear_old_releases] expired releases: {0}".format(expired_releases))
  
		# delete expired releases
		for expired_release in expired_releases:
			cmd = f"{os.getcwd()}{os.path.sep}extern{os.path.sep}bin{os.path.sep}sentry-cli.exe releases --org {self.__sentry_organization} --project {self.__sentry_project} delete {expired_release}"
			print("cmd: {0}".format(cmd))
  
			p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
			out, err = p.communicate()

			if (p.returncode != 0):
				err = err.decode("utf-8")
				print("[__clear_old_releases] Error: [{0}] {1}".format(p.returncode, err))
				continue
    
			print("[__clear_old_releases] out: {0}".format(out))
  
	def __list_bin_packages(self):
		print("Listing binary packages...")
  
		for root, dirs, files in os.walk(f"{os.getcwd()}{os.path.sep}Bin"):
			for file in files:
				# Print file details
				currFile = f"{os.path.join(root, file)}"
	
				print("{0}".format(currFile))
				print("\tSize: {0}".format(os.path.getsize(currFile)))
				print("\tLast modified time: {0}".format(os.path.getmtime(currFile)))
				print("\tLast accessed time: {0}".format(os.path.getatime(currFile)))
				print("\tCreated time: {0}".format(os.path.getctime(currFile)))
				print("\tMD5: {0}".format(self.__get_md5(currFile)))
  
	def __get_sentry_info(self):
		print("Getting sentry info...")
  
		cmd = f"{os.getcwd()}{os.path.sep}extern{os.path.sep}bin{os.path.sep}sentry-cli.exe info"
		print("cmd: {0}".format(cmd))
  
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		out, err = p.communicate()
  
		if (p.returncode != 0):
			err = err.decode("utf-8")
			print("[__get_sentry_info] Error: [{0}] {1}".format(p.returncode, err))
			sys.exit(1)
   
		out = out.decode("utf-8")
		print("[__get_sentry_info] out: {0}".format(out))
  
	def __create_release(self):
		print("Creating release...")
  
		cmd = [
	  		f"{os.getcwd()}{os.path.sep}extern{os.path.sep}bin{os.path.sep}sentry-cli.exe releases --org {self.__sentry_organization} --project {self.__sentry_project} new 1.{self.__pipeline_version}",
			f"{os.getcwd()}{os.path.sep}extern{os.path.sep}bin{os.path.sep}sentry-cli.exe releases --org {self.__sentry_organization} --project {self.__sentry_project} set-commits 1.{self.__pipeline_version} --local --ignore-missing"	
		]
		for c in cmd:
			print("cmd: {0}".format(c))
	
			p = subprocess.Popen(c, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
			out, err = p.communicate()
	
			if (p.returncode != 0):
				err = err.decode("utf-8")
				print("[__create_release] Error: [{0}] {1}".format(p.returncode, err))
				sys.exit(1)
	
			out = out.decode("utf-8")
			print("[__create_release] out: {0}".format(out))
	
	def __deploy_debug_symbols(self):
		print("Deploying debug symbols...")
  
		workPath = os.path.join(os.getcwd(), "Bin")
		for root, dirs, files in os.walk(workPath):
			for file in files:
				if self.__sentry_project == "nomercy-setup":
					lowerFile = file.lower()

					if not "setup" in lowerFile:
						os.remove(os.path.join(root, file))
				else:
					if file.endswith(".dll") or file.endswith(".bak"):
						print("Current file: {0}...".format(file))
		 
						targetFile = file
						if (re.search('NoMercy_Module_x.+.dll', targetFile) and targetFile.endswith(".dll")): 
							targetFile = targetFile.replace(".dll", "_protected.dll")
		  
						if (re.search('NoMercy_Module_x.+.bak', targetFile) and "_non_rtti" in targetFile): 
							targetFile = targetFile.replace("_non_rtti.dll.bak", ".dll")
		  
						if (targetFile.endswith(".bak") and not "_non_rtti" in targetFile):
							print("Skipping {0}...".format(targetFile))
							os.remove(os.path.join(root, targetFile))
							continue;
	  
						if (targetFile != file):
							print("Renaming {0} to {1}...".format(file, targetFile))
							os.rename(os.path.join(root, file), os.path.join(root, targetFile))

		cmd = [
	  		f"{os.getcwd()}{os.path.sep}extern{os.path.sep}bin{os.path.sep}sentry-cli.exe releases --org {self.__sentry_organization} --project {self.__sentry_project} files 1.{self.__pipeline_version} upload-sourcemaps {os.getcwd()}{os.path.sep}Bin",
			f"{os.getcwd()}{os.path.sep}extern{os.path.sep}bin{os.path.sep}sentry-cli.exe upload-dif --org {self.__sentry_organization} --project {self.__sentry_project} --include-sources --wait {os.getcwd()}{os.path.sep}Bin"
		]
  
		for c in cmd:
			print("cmd: {0}".format(c))
  
			p = subprocess.Popen(c, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
			out, err = p.communicate()
  
			if (p.returncode != 0):
				err = err.decode("utf-8")
				print("[__deploy_debug_symbols] Error: [{0}] {1}".format(p.returncode, err))
				sys.exit(1)
  
			out = out.decode("utf-8")
			print("[__deploy_debug_symbols] out: {0}".format(out))
  
	def __finalize_release(self):
		print("Finalizing release...")
  
		cmd = [
			f"{os.getcwd()}{os.path.sep}extern{os.path.sep}bin{os.path.sep}sentry-cli.exe releases --org {self.__sentry_organization} --project {self.__sentry_project} finalize 1.{self.__pipeline_version}",
			f"{os.getcwd()}{os.path.sep}extern{os.path.sep}bin{os.path.sep}sentry-cli.exe releases --org {self.__sentry_organization} --project {self.__sentry_project} deploys 1.{self.__pipeline_version} new -e {self.__sentry_environment}"
		]

		for c in cmd:
			print("cmd: {0}".format(c))
  
			p = subprocess.Popen(c, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
			out, err = p.communicate()
  
			if (p.returncode != 0):
				err = err.decode("utf-8")
				print("[__finalize_release] Error: [{0}] {1}".format(p.returncode, err))
				sys.exit(1)
  
			out = out.decode("utf-8")
			print("[__finalize_release] out: {0}".format(out))

if __name__ == "__main__":
	worker = SentryWorker(sys.argv[1:])
	sys.exit(worker.run())
 