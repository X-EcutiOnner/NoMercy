import os
import jstyleson
import glob
import config_data
import data
from log_helper import log, ERROR_LOG, INFO_LOG

def process_config_file(doc):
	if "hosts" not in doc or not isinstance(doc["hosts"], dict):
		log(ERROR_LOG, "hosts key is not valid!")
		return False

	for hostname, host in doc["hosts"].items():
		hostCtx = {}
		hostCtx["hostname"] = hostname

		if not isinstance(host, dict):
			log(ERROR_LOG, "hosts value is not valid!")
			return False
			
		if "endpoint" in host and isinstance(host["endpoint"], str):
			hostCtx["endpoint"] = host["endpoint"]

		if "access_key" in host and isinstance(host["access_key"], str):
			hostCtx["access_key"] = host["access_key"]

		if "secret_key" in host and isinstance(host["secret_key"], str):
			hostCtx["secret_key"] = host["secret_key"]
   
		if "region" in host and isinstance(host["region"], str):
			hostCtx["region"] = host["region"]

		config_data.hosts.append(hostCtx)
	
	if "ftp_hosts" in doc and isinstance(doc["ftp_hosts"], dict):
		for sftp_host in doc["ftp_hosts"]:
			hostData = doc["ftp_hosts"][sftp_host]		
   
			sftpHostCtx = {}
			sftpHostCtx["name"] = sftp_host
   
			if "hostname" in hostData and isinstance(hostData["hostname"], str):
				sftpHostCtx["hostname"] = hostData["hostname"]
		
			if "endpoint" in hostData and isinstance(hostData["endpoint"], str):
				sftpHostCtx["endpoint"] = hostData["endpoint"]

			if "port" in hostData and isinstance(hostData["port"], int):
				sftpHostCtx["port"] = hostData["port"]

			if "username" in hostData and isinstance(hostData["username"], str):
				sftpHostCtx["username"] = hostData["username"]

			if "password" in hostData and isinstance(hostData["password"], str):
				sftpHostCtx["password"] = hostData["password"]

			if "private_key" in hostData and isinstance(hostData["private_key"], str):
				sftpHostCtx["private_key"] = hostData["private_key"]

			config_data.ftp_hosts.append(sftpHostCtx)

	# Config version
	if "version" in doc and isinstance(doc["version"], int):
		config_data.version = doc["version"]
		log(INFO_LOG, f"Config version: {config_data.version}")

	# Root path
	config_data.target_path = f"{config_data.root_path}{os.path.sep}1.{config_data.patch_version}"
	log(INFO_LOG, f"Target path: {config_data.target_path}")
 
	if not os.path.exists(config_data.target_path):
		log(ERROR_LOG, f"Target path does not exist: {config_data.target_path}")
		return False

	# Single file
	if config_data.update_file:
		update_file_with_path = f"{config_data.target_path}{os.path.sep}{config_data.update_file}"
		log(INFO_LOG, f"Update file: {update_file_with_path}")
	
		if not os.path.exists(update_file_with_path):
			log(ERROR_LOG, f"Update file does not exist: {update_file_with_path}")
			return False

		if config_data.update_file == "NoMercy_SystemModule_x64.sys":
			spFileContainerCtx = data.SFileContainerCtx(id="ac_files", method="md5", files=[])

			spFileCtx = data.SFileCtx(name=config_data.update_file, local_path="", attr=data.EFileAttributes.FILE_ATTR_PATH_SYSTEM, optional=False)
			spFileContainerCtx.files.append(spFileCtx)

			config_data.file_containers.append(spFileContainerCtx)
			return True
		else:
			log(ERROR_LOG, f"Update file is not supported: {config_data.update_file}")
			return False

	# Multiple files
	if "sdk_files" not in doc or not isinstance(doc["sdk_files"], dict):
		log(ERROR_LOG, "sdk_files key is not valid!")
		return False
	elif "game_files" not in doc or not isinstance(doc["game_files"], dict):
		log(ERROR_LOG, "game_files key is not valid!")
		return False
	elif "ac_files" not in doc or not isinstance(doc["ac_files"], dict):
		log(ERROR_LOG, "ac_files key is not valid!")
		return False
 
	idx = 0
	for objFiles in [doc["sdk_files"], doc["game_files"], doc["ac_files"]]:
		idx += 1
  
		containerId = ""
		if idx == 1:
			containerId = "sdk_files"
		elif idx == 2:
			containerId = "game_files"
		elif idx == 3:
			containerId = "ac_files"
		else:
			log(ERROR_LOG, f"Invalid container id: {idx}")
			return False

		# log(INFO_LOG, f"Checking object: {idx} ({containerId}) > {objFiles}")

		spFileContainerCtx = data.SFileContainerCtx(containerId, method=objFiles["check_method"], files=[])
  
		file_idx = 0
		for fileName in objFiles["files"]:
			file_idx += 1
   
			fileData = objFiles["files"][fileName]
			log(INFO_LOG, f"Checking file: {file_idx} > {fileName} > {fileData}")
   
			fileAttr = data.EFileAttributes.FILE_ATTR_NONE.value
			localSourceFile = ""
      
			if "attr" in fileData:
				for attr in fileData["attr"]:
					if attr == "system":
						fileAttr |= data.EFileAttributes.FILE_ATTR_PATH_SYSTEM.value
					elif attr == "game":
						fileAttr |= data.EFileAttributes.FILE_ATTR_PATH_GAME.value
					elif attr == "local":
						fileAttr |= data.EFileAttributes.FILE_ATTR_PATH_LOCAL.value
					elif attr == "hidden":
						fileAttr |= data.EFileAttributes.FILE_ATTR_HIDDEN.value
					elif attr == "crypted_1":
						fileAttr |= data.EFileAttributes.FILE_ATTR_CRYPTED_1.value
					elif attr == "compressed_1":
						fileAttr |= data.EFileAttributes.FILE_ATTR_COMPRESSED_1.value
					else:
						log(ERROR_LOG, f"Invalid file attribute: {attr}")
						return False
				if not fileAttr:
					log(ERROR_LOG, f"Invalid file attribute: {fileData['attr']}")
					return False
			if "file_path" in fileData:
				log(INFO_LOG, f"Specific file path found: {fileData['file_path']} for {fileName}")
    
				localSourceFile = f"{config_data.target_path}{os.path.sep}{fileData['file_path']}{fileName}"
				if not "*" in localSourceFile:
					if not os.path.exists(localSourceFile):
						log(ERROR_LOG, f"Local source file does not exist: {localSourceFile}")
						return False
				else:
					matchedFiles = glob.glob(localSourceFile)
					if not matchedFiles:
						log(ERROR_LOG, f"Local source file does not exist: {localSourceFile}")
						return False
   
			fileCtx = data.SFileCtx(
       			name = fileName,
          		local_path = fileData["local_path"],
            	attr = fileAttr,
				preprocess = fileData["preprocess"] if "preprocess" in fileData else "",
             	optional = fileData["optional"],
				skip_pdb = fileData["skip_pdb"] if "skip_pdb" in fileData else False,
				new_name = fileData["rename"] if "rename" in fileData else "",
				local_source_file = localSourceFile
            )
   
			# log(INFO_LOG, f"File context: {fileName} >> {localSourceFile}")
			spFileContainerCtx.files.append(fileCtx)
		
		config_data.file_containers.append(spFileContainerCtx)
  
	# print(f"File containers: {config_data.file_containers}")
	log(INFO_LOG, f"Processed file container count: {len(config_data.file_containers)}")
	return True
				

def parse_config_file():
	log(INFO_LOG, f"Parsing config file: {config_data.config_file_name}")

	if not os.path.exists(config_data.config_file_name):
		log(ERROR_LOG, "Config file does not exist!")
		return False

	with open(config_data.config_file_name, 'r') as fp:
		buffer = fp.read()
		if not buffer:
			log(ERROR_LOG, "Config file could not read!")
			return False
		
		doc = jstyleson.loads(buffer)
	
		if "hosts" not in doc:
			log(ERROR_LOG, "Config 'hosts' key does not exist!")
			return False
		elif "ftp_hosts" not in doc:
			log(ERROR_LOG, "Config 'ftp_hosts' key does not exist!")
			return False
		elif "version" not in doc:
			log(ERROR_LOG, "Config 'version' key does not exist!")
			return False
		elif "sdk_files" not in doc:
			log(ERROR_LOG, "Config 'sdk_files' key does not exist!")
			return False
		elif "game_files" not in doc:
			log(ERROR_LOG, "Config 'game_files' key does not exist!")
			return False
		elif "ac_files" not in doc:
			log(ERROR_LOG, "Config 'ac_files' key does not exist!")
			return False

		if not isinstance(doc["hosts"], dict):
			log(ERROR_LOG, "Config 'hosts' key is not object!")
			return False
		elif not doc["hosts"]:
			log(ERROR_LOG, "Config 'hosts' value is not valid!")
			return False

		if not isinstance(doc["ftp_hosts"], dict):
			log(ERROR_LOG, "Config 'ftp_hosts' key is not object!")
			return False
		# elif not doc["ftp_hosts"]:
		# 	log(ERROR_LOG, "Config 'ftp_hosts' value is not valid!")
		# 	return False

		if not isinstance(doc["version"], int):
			log(ERROR_LOG, "Config 'version' key is not number!")
			return False
		elif not doc["version"]:
			log(ERROR_LOG, "Config 'version' value is not valid!")
			return False

		if not isinstance(doc["sdk_files"], dict):
			log(ERROR_LOG, "Config 'sdk_files' key is not object!")
			return False
		elif not doc["sdk_files"]:
			log(ERROR_LOG, "Config 'sdk_files' value is null!")
			return False

		if not isinstance(doc["game_files"], dict):
			log(ERROR_LOG, "Config 'game_files' key is not object!")
			return False
		elif not doc["game_files"]:
			log(ERROR_LOG, "Config 'game_files' value is null!")
			return False

		if not isinstance(doc["ac_files"], dict):
			log(ERROR_LOG, "Config 'ac_files' key is not object!")
			return False
		elif not doc["ac_files"]:
			log(ERROR_LOG, "Config 'ac_files' value is null!")
			return False

		log(INFO_LOG, "Config file parsed successfully, processing parsed data...")
		return process_config_file(doc)
