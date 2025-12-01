import os
import subprocess
import config_data
import requests
import utilities
import data
import s3_helper
import ftp_helper
from log_helper import log, ERROR_LOG, INFO_LOG
import lz4.frame
from Cryptodome.Cipher import AES # pycryptodomex
import zipfile
import bz2
import json
import errno
import asyncio
import aiohttp
import httpx

PATCH_URL           = "https://api-beta.nomercy.ac/v1/upload_patch_list";
PATCH_ACTIVATE_URL  = "https://api-beta.nomercy.ac/v1/active_patch_version";

async def process_file_list():
	log(INFO_LOG, f"Version: {config_data.version}")

	if config_data.version == 1:
		log(INFO_LOG, f"Current local file path {config_data.target_path}")

		for file_container in config_data.file_containers:
			log(INFO_LOG, f"Current container: {file_container.id}")

			for file in file_container.files:
				log(INFO_LOG, f"\tCurrent file: {file.name} ({file.local_source_file}) path: {config_data.target_path}")

				optional = False
				if "non_rtti" in file.name and config_data.patch_version < 10000:
					optional = True
				if "non_rtti" in file.name and config_data.branch_name != "release":
					optional = True

				full_path = config_data.target_path
				if not full_path:
					full_path = os.path.abspath(os.getcwd())
					log(INFO_LOG, f"\t\tTarget path is not defined! Adjusted with current working directory: {full_path}")

				full_name = file.local_source_file
				if full_name:
					full_path = os.path.dirname(full_name)
					log(INFO_LOG, f"\t\tTarget source file is defined, Target path will be adjusted to file source path: {full_path}")
				else:
					log(INFO_LOG, f"\t\tSpecific file is not defined!")

					# Apply path by attributes
					log(INFO_LOG, f"\t\tCurrent file exist in local path: {file.local_path}")

					if file.local_path == "I18n" or file.local_path == "NoMercy\\I18n":
						full_path = os.path.join(full_path, "..", "..", "document", "i18n_files")
					elif file.local_path == "License":
						full_path = os.path.join(full_path, "..", "..", "document", "license_files")

					if not full_path:
						log(ERROR_LOG, "\t\tUnsupported path attribute!")
						return False

					# Check path
					log(INFO_LOG, f"\t\tCurrent file target path: {full_path}")

					if not os.path.exists(full_path):
						log(INFO_LOG, f"\t\tTarget path: {full_path} does not exist!")
						return False

					full_name = os.path.join(full_path, file.name)
					log(INFO_LOG, f"\t\tCurrent file path: {full_name}")

				# Apply wildcard
				has_binary_wildcard = "*" in file.name
				bFoundBinaryWildcard = False
				has_symbol_wildcard = "*" in file.local_debug_symbol_file
				bFoundSymbolWildcard = False
				log(INFO_LOG, f"\t\tWildcard result: B:{has_binary_wildcard} / S:{has_symbol_wildcard}")

				if has_binary_wildcard or has_symbol_wildcard:
					for root, dirs, files in os.walk(full_path):
						for entry in files:
							file_name = os.path.basename(entry)
							file_extension = os.path.splitext(entry)[-1]

							log(INFO_LOG, f"\t\t\tChecking {file_name} with {file.name}/{file.local_debug_symbol_file}")

							skip_file = False
							if file_extension != ".json":
								if config_data.branch_name == "local":
									if "_d" not in file_name:
										skip_file = True
								else:
									if "_d" in file_name:
										skip_file = True

							if skip_file:
								log(ERROR_LOG, "\t\t\t\tSkipped debug file for current branch policies")
								continue
							
							# log(INFO_LOG, f"\t\tChecking binary Wildcard; {file_name} -> {file.name} -> {bFoundBinaryWildcard}")
							if has_binary_wildcard and utilities.WildcardMatch(file_name, file.name):
								log(INFO_LOG, f"\t\t+ Binary Wildcard matched; {file_name} -> {file.name} -> {bFoundBinaryWildcard}")
								if not bFoundBinaryWildcard:
									file.name = file_name
									bFoundBinaryWildcard = True

							if has_symbol_wildcard and utilities.WildcardMatch(file.local_debug_symbol_file, file_name):
								log(INFO_LOG, f"\t\t+ Symbol Wildcard matched; {file.local_debug_symbol_file} -> {file.name} {bFoundSymbolWildcard}")
								if not bFoundSymbolWildcard:
									file.name = file_name
									bFoundSymbolWildcard = True
									
							if (not has_binary_wildcard or (has_binary_wildcard and bFoundBinaryWildcard)) and \
								(not has_symbol_wildcard or (has_symbol_wildcard and bFoundSymbolWildcard)):
								log(INFO_LOG, "\t\t# Found wildcard matches!")
								break
		 
					if has_binary_wildcard and not bFoundBinaryWildcard:
						log(INFO_LOG if optional else ERROR_LOG, f"\t\tBinary wildcard not found! in {full_path}")
						
						if optional:
							continue
						else:
							return False
   
					if has_symbol_wildcard and not bFoundSymbolWildcard:
						log(ERROR_LOG, "\t\tSymbol wildcard not found!")
						return False
  
					full_name = os.path.join(full_path, file.name)
					log(INFO_LOG, f"\t\tCurrent file path: {full_name}")

				# Rename file
				if file.new_name:
					new_name = os.path.join(full_path, file.new_name)
					log(INFO_LOG, f"\t\tRenaming file: {full_name} -> {new_name}")
	 
					if os.path.exists(new_name):
						log(INFO_LOG, f"\t\t\tTarget file already exists!")
						# return False
					else:
						os.rename(full_name, new_name)
						log(INFO_LOG, f"\t\t\tFile renamed: {full_name}({file.name}) -> {new_name}({file.new_name})")
	  
					full_name = new_name
					file.name = file.new_name
	 
				# Debug symbol
				splitted_name = file.name.split(".")
				if splitted_name:
					extension = splitted_name[-1]
					if extension == "dll" or extension == "exe" or extension == "sys":
						debug_symbol_name = f"{splitted_name[0]}.pdb"
						file.local_debug_symbol_file = f"{full_path}{os.path.sep}Pdb{os.path.sep}{debug_symbol_name}"
						log(INFO_LOG, f"\t\tCurrent file debug symbol file: {file.local_debug_symbol_file}")
	  
						if not config_data.update_file or (config_data.update_file and file.name != config_data.update_file):
							if not os.path.exists(file.local_debug_symbol_file):
								log(INFO_LOG, f"\t\tDebug symbol file does not exist!")

								if not config_data.skip_if_not_exist and not file.optional and not file.skip_pdb:
									log(INFO_LOG, f"\t\t[ERROR] Debug symbol file is NOT optional, aborting!");
									return False
				
				# Preprocess
				if file.preprocess:
					final_param = ""

					bin_root = os.path.join(config_data.target_path, "..", "..", "Bin")
					log(INFO_LOG, f"\t\tBin output root path: {bin_root}")
	 
					if not os.path.exists(bin_root):
						log(ERROR_LOG, f"\t\tBin output root path: {bin_root} does not exist!")
						return False
  
					log(INFO_LOG, f"\t\tPreprocess data: {file.preprocess}")
	 
					parsed_preprocess_data = file.preprocess.split(" ")
					if len(parsed_preprocess_data) < 2:
						log(ERROR_LOG, f"\t\tSplit preprocess data: {file.preprocess} failed!")
						return False
  
					first_arg = parsed_preprocess_data[1]
					if ".json" in first_arg:
						log(INFO_LOG, f"\t\tPreprocess data first arg: {first_arg} looks like a file")
		 
						target_json = os.path.join(config_data.target_path, "..", first_arg)
						if not os.path.exists(target_json):
							log(ERROR_LOG, f"\t\tPreprocess first arg file: {target_json} does not exist!")
							return False
   
						preprocess_target = os.path.join(bin_root, parsed_preprocess_data[0])
						log(INFO_LOG, f"\t\tPreprocess target: {preprocess_target}")
	  
						if not os.path.exists(preprocess_target):
							log(ERROR_LOG, f"\t\tPreprocess target: {preprocess_target} does not exist")
							if config_data.skip_if_not_exist:
								log(INFO_LOG, "\t\t\tSkipping preprocess target")
								continue
							else:
								return False
						log(INFO_LOG, f"\t\tPreprocess target: {preprocess_target} exists")
	  
						final_param = f"{preprocess_target} {target_json}"
						log(INFO_LOG, f"\t\tFinal preprocess param: {final_param}")
					else:
						log(ERROR_LOG, f"\t\tUnknown preprocess data: {first_arg}")
						return False
  
					# Create the child process
					pi = subprocess.Popen(final_param, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
					pid = pi.pid
					log(INFO_LOG, f"\t\tChild process created! PID: {pid}")

					# Wait for the process to exit
					pi.communicate()
					return_code = pi.returncode
					log(INFO_LOG, f"\t\tChild process exit code handled: {return_code}")

					if return_code != 0:
						log(ERROR_LOG, f"\t\tChild process has failed! Exit code: {return_code}")
						return False

					# Forward output
					full_name = os.path.join(os.getcwd(), file.name)
					log(INFO_LOG, f"\t\tCurrent file preprocessor adjusted path: {full_name}")

				# Exist check
				if not os.path.exists(full_name):
					if file.optional:
						log(INFO_LOG, f"\t\tSkipped not exist optional file: {full_name}")
						continue
					else:
						log(ERROR_LOG, f"\t\tFinal file does not exist: '{full_name}' File: {file}")
						return False
  
				# Calculate hash
				file_hash = ""
				if file_container.method == "md5":
					file_hash = utilities.GetMd5(full_name)
				elif file_container.method == "sha1":
					file_hash = utilities.GetSha1(full_name)
				elif file_container.method == "sha256":
					file_hash = utilities.GetSha256(full_name)
	 
				if not file_hash:
					log(ERROR_LOG, f"\t\tFailed to calculate hash for file: {full_name} method: {file_container.method}")
					return False
 
				# Fill file informations
				file.local_source_file = full_name
				file.size = os.path.getsize(full_name)
				file.hash = file_hash
	
				# Egg check
				crypt_flag = data.EFileAttributes.FILE_ATTR_CRYPTED_1.value
				compress_flag = data.EFileAttributes.FILE_ATTR_COMPRESSED_1.value
				# log(INFO_LOG, f"\t\tFile attributes: {file.attr} type: {str(type(file.attr))}, crypt_flag: {crypt_flag} type: {str(type(crypt_flag))}, compress_flag: {compress_flag} type: {str(type(compress_flag))}")
				is_egg_file = False
				try:
					if file.attr & crypt_flag or file.attr & compress_flag:
						is_egg_file = True
				except:
					pass
				if is_egg_file:
					# Read file content
					pImage = None
					dwReadedBytes = 0
					with open(full_name, 'rb') as f:
						pImage = f.read()
						dwReadedBytes = len(pImage)
	  
					if not pImage or dwReadedBytes == 0:
						log(ERROR_LOG, f"\t\tFailed to read file content: {full_name}")
						return False

					# Compress
					if file.attr & data.EFileAttributes.FILE_ATTR_COMPRESSED_1.value:
						vCompressedBuffer = lz4.frame.compress(pImage, compression_level=16)
						nCompressedSize = len(vCompressedBuffer)
						if nCompressedSize == 0:
							log(ERROR_LOG, "\t\tCompression fail!")
							return False
					else:
						vCompressedBuffer = pImage
						nCompressedSize = dwReadedBytes

					# Encrypt
					if file.attr & data.EFileAttributes.FILE_ATTR_CRYPTED_1.value:
						try:
							aes_key = data.DefaultCryptionKey[:32]
							aes_iv = data.DefaultCryptionKey[32:]
							cipher = AES.new(aes_key, AES.MODE_CTR, nonce=aes_iv)
							vCryptedBuffer = cipher.encrypt(vCompressedBuffer)
						except Exception as e:
							log(ERROR_LOG, f"\t\tCaught exception on encryption: {str(e)}")
							return False
					else:
						vCryptedBuffer = vCompressedBuffer

					# Delete old file
					try:
						os.remove(full_name)
					except Exception as e:
						log(ERROR_LOG, f"\t\tFile: {full_name} delete failed with error: {str(e)}")
						return False

					# Write to file
					try:
						with open(full_name, 'wb') as f:
							f.write(vCryptedBuffer)
					except Exception as e:
						log(ERROR_LOG, f"\t\tWriteFile fail! Error: {str(e)}")
						return False

					# Calculate egg hash
					if file_container.method == "md5":
						stEggHash = utilities.GetMd5(vCryptedBuffer)
					elif file_container.method == "sha1":
						stEggHash = utilities.GetSha1(vCryptedBuffer)
					elif file_container.method == "sha256":
						stEggHash = utilities.GetSha256(vCryptedBuffer)
					else:
						log(ERROR_LOG, f"\t\tInvalid hash method: {file_container.method}")
						return False

					if not stEggHash:
						log(ERROR_LOG, f"\t\tFinal file: {full_name} egg hash calculate failed! Method: {file_container.method}")
						return False

					file.egg_hash = stEggHash
					log(INFO_LOG, f"\t\tFinal file: {full_name} egg hash calculated: {stEggHash}")

				log(INFO_LOG, f"\t\tFile: {file.name} -> {full_name} processed!")
				file.processed = True
				continue
   
	return True

async def create_zip_archive():
	log(INFO_LOG, f"Version: {config_data.version}")
	
	if config_data.version == 1:
		log(INFO_LOG, f"Current local file path {config_data.target_path}")

		for spFileContainer in config_data.file_containers:
			log(INFO_LOG, f"Current container: {spFileContainer.id}")

			# Remove old archive if exist
			stArchiveName = f"{spFileContainer.id}.zip"

			if os.path.exists(stArchiveName):
				try:
					os.remove(stArchiveName)
				except Exception as e:
					log(INFO_LOG, f"\tOld archive: {stArchiveName} remove failed with error: {e}")
					return False

			# Create the archive
			try:
				with zipfile.ZipFile(stArchiveName, "w") as spZipArchive:
					for spFile in spFileContainer.files:
						if not spFile.processed:
							log(INFO_LOG, f"\tFile: {spFile.name} not processed!")
							continue

						log(INFO_LOG, f"\tCurrent file: {spFile.name}")

						if not spFile.local_source_file:
							stFile = os.path.join(config_data.target_path, spFile.name)
						else:
							stFile = spFile.local_source_file

						with open(stFile, "rb") as file:
							stContent = file.read()

						# Compress the content using Bzip2
						compressed_data = bz2.compress(stContent, compresslevel=9)

						# Write the compressed content to the zip entry
						spZipArchive.writestr(spFile.name, compressed_data)

						log(INFO_LOG, f"\tZIP entry: {spFile.name} ({stFile}) created!")

			except Exception as e:
				log(INFO_LOG, f"ZIP file body could not be created! Last error: {e}")
				return False

			spFileContainer.archive_file = stArchiveName
			log(INFO_LOG, f"Archive: {stArchiveName} created!")

	return True

async def create_file_index():
	log(INFO_LOG, f"Version: {config_data.version}")
	
	if config_data.version == 1:
		log(INFO_LOG, f"Current local file path {config_data.target_path}")

		for spFileContainer in config_data.file_containers:
			log(INFO_LOG, f"Current container: {spFileContainer.id}")

			# Create index filename
			stIndexFileName = f"{spFileContainer.id}_index.json"

			# Remove file if already exists
			if os.path.exists(stIndexFileName):
				os.remove(stIndexFileName)

			# Create index file
			with open(stIndexFileName, "w") as fp:
				# Create JSON serializer
				data = {
					"files": {}
				}

				for spFile in spFileContainer.files:
					if not spFile.processed:
						log(ERROR_LOG, f"\tFile: {spFile.name} not processed!")
						continue

					log(INFO_LOG, f"\tCurrent file: {spFile.name}")

					attrValue = spFile.attr if type(spFile.attr) is int else spFile.attr.value
					file_data = {
						"local_path": spFile.local_path,
						"size": spFile.size,
						"attr": attrValue,
						"hash": spFile.hash,
						"egg_hash": spFile.egg_hash,
						"binary_metadata": '',
						"symbol_metadata": ''
					}

					if spFile.binary_metadata:
						log(INFO_LOG, f"\t\tBinary metadata found!")
						file_data["binary_metadata"] = spFile.binary_metadata

					if spFile.symbol_metadata:
						log(INFO_LOG, f"\t\tSymbol metadata found!")
						file_data["symbol_metadata"] = spFile.symbol_metadata

					data["files"][spFile.name] = file_data

				# Write serialized data to index file
				serialized_data = json.dumps(data, indent=4)
				fp.write(serialized_data)
				log(INFO_LOG, f"\tSerialized data written. Size: {len(serialized_data)}")

	return True

async def on_complete(object, result, to):
	# log(INFO_LOG, f"Upload binary object: {object} completed! Result: {result} to: {to}")
	# log(INFO_LOG, f"Upload binary object: {object} completed! Result: {result}")
	if not result:
		log(ERROR_LOG, f"Upload binary object: {object} failed!")
		return False
	else:
		log(INFO_LOG, f"Upload binary object: {object} succesfully, Metedata: {result}, to: {to}")
		extension = os.path.splitext(object)[1]
		if extension == ".zip":
			to.archive_metadata = result
		elif extension == ".pdb":
			to.symbol_metadata = result
		else:
			to.binary_metadata = result
		return True

async def upload_files():
	upload_jobs = []
	bucket_name = f"nomercy-client-files.v{config_data.version}"
	log(INFO_LOG, f"Bucket name: {bucket_name} Version: {config_data.version}")
 
	if config_data.version == 1:
		version_directory = f"v{config_data.version}.{config_data.patch_version}"
		log(INFO_LOG, f"Version directory: {version_directory}")
  
		for host in config_data.hosts:
			log(INFO_LOG, f"Current host: {host}")
			client = host["client"]
			if not client:
				log(ERROR_LOG, f"Host: {client} has no client!")
				return False

			# Create bucket for current version, if not exist
			if not await client.has_bucket(bucket_name):
				log(INFO_LOG, f"Bucket: {bucket_name} does not exist, creating...")
	
				if not await client.create_bucket(bucket_name):
					log(ERROR_LOG, f"Bucket: {bucket_name} could not be created!")
					return False

		for ftp_host in config_data.ftp_hosts:
			client : ftp_helper.FTPClient = ftp_host.client
			if not client:
				log(ERROR_LOG, f"Host: {client} has no client!")
				return False

			if not client.has_directory(version_directory):
				log(INFO_LOG, f"Directory: {version_directory} does not exist, creating...")
	
				if not client.create_directory(version_directory):
					log(ERROR_LOG, f"Directory: {version_directory} could not be created!")
					return False
 
		for spFileContainer in config_data.file_containers:
			log(INFO_LOG, f"Current container: {spFileContainer.id}, File count: {len(spFileContainer.files)}")
   
			has_processed_file = False
			for spFile in spFileContainer.files:
				if spFile.processed and not len(spFile.preprocess):
					has_processed_file = True
			
			if not has_processed_file:
				log(INFO_LOG, "\tContainer have not any processed file!")
				continue
			else:
				for spFile in spFileContainer.files:
					if not spFile.processed or (config_data.skip_if_not_exist and spFile.processed and len(spFile.preprocess)):
						spFileContainer.files.remove(spFile)

			if spFileContainer.archive_file:
				if not os.path.exists(spFileContainer.archive_file):
					log(ERROR_LOG, f"Archive file: {spFileContainer.archive_file} does not exist!")
					return False
 
				archive_hash = utilities.GetMd5(spFileContainer.archive_file)
	  
				for host in config_data.hosts:
					client : s3_helper.S3Client = host["client"]
					upload_jobs.append(client.put_object(bucket_name, spFileContainer.archive_file, spFileContainer.archive_file, config_data.patch_version, spFileContainer.id, archive_hash, on_complete, spFileContainer))

				for ftp_host in config_data.ftp_hosts:
					client : ftp_helper.FTPClient = ftp_host.client
					target_file_path = f"{version_directory}{os.path.sep}{spFileContainer.archive_file}"
					if not client.upload_file(spFileContainer.archive_file, target_file_path):
						log(ERROR_LOG, f"Upload binary object: {spFileContainer.archive_file} failed!")
						return False
					else:
						log(INFO_LOG, f"Upload binary object: {spFileContainer.archive_file} succesfully")
	  
			for spFile in spFileContainer.files:
				log(INFO_LOG, f"\tCurrent file: {spFile.name} ({spFile.local_source_file})")
	
				if not spFile.local_source_file:
					log(ERROR_LOG, f"Source file: {spFile.name} does not exist a local file name, skipped!")
					continue
 
				splitted_name = spFile.name.split(".")
				if splitted_name:
					extension = splitted_name[-1]
					# if extension == "exe" or extension == "dll" or extension == "sys" or extension == "pdb":
					if 1:
						if not os.path.exists(spFile.local_source_file):
							log(ERROR_LOG, f"Source file: {spFile.name} does not exist!")
							return False
   
						if extension == "dll":
							backup_path = os.path.join(config_data.target_path, "..", "..", "Bin")
							if os.path.exists(backup_path):
								backup_filename = f"{spFile.name}.bak"
								backup_file = os.path.join(backup_path, backup_filename)
		
								if os.path.exists(backup_file):
									log(INFO_LOG, f"Unprotected module file: {backup_file} found!")
		 
									for host in config_data.hosts:
										client : s3_helper.S3Client = host["client"]
										upload_jobs.append(client.put_object(bucket_name, backup_file, backup_file, config_data.patch_version, spFileContainer.id, "", on_complete, spFile))

									for ftp_host in config_data.ftp_hosts:
										client : ftp_helper.FTPClient = ftp_host.client
										target_file_path = f"{version_directory}{os.path.sep}{backup_filename}"
										if not client.upload_file(backup_file, target_file_path):
											log(ERROR_LOG, f"Upload binary object: {backup_filename} ({backup_file}) failed!")
											return False
										else:
											log(INFO_LOG, f"Upload binary object: {backup_filename} ({backup_file}) succesfully")

						for host in config_data.hosts:
							client : s3_helper.S3Client = host["client"]
							upload_jobs.append(client.put_object(bucket_name, spFile.name, spFile.local_source_file, config_data.patch_version, spFileContainer.id, "", on_complete, spFile))
		
						for ftp_host in config_data.ftp_hosts:
							client : ftp_helper.FTPClient = ftp_host.client
							target_file_path = f"{version_directory}{os.path.sep}{spFile.name}"
							if not client.upload_file(spFile.local_source_file, target_file_path):
								log(ERROR_LOG, f"Upload binary object: {spFile.name} ({spFile.local_source_file}) failed!")
								return False
							else:
								log(INFO_LOG, f"Upload binary object: {spFile.name} ({spFile.local_source_file}) succesfully")
		
						if spFile.local_debug_symbol_file:
							log(INFO_LOG, f"\tCurrent debug symbol file: ({spFile.local_debug_symbol_file})")
		  
							if not os.path.exists(spFile.local_debug_symbol_file):
								log(INFO_LOG, f"Debug symbol file: {spFile.local_debug_symbol_file} does not exist!")
							else:
								symbol_name = splitted_name[0] + ".pdb"
								for host in config_data.hosts:
									client : s3_helper.S3Client = host["client"]
									upload_jobs.append(client.put_object(bucket_name, symbol_name, spFile.local_debug_symbol_file, config_data.patch_version, spFileContainer.id, "", on_complete, spFile))
		  
								for ftp_host in config_data.ftp_hosts:
									client : ftp_helper.FTPClient = ftp_host.client
									target_file_path = f"{version_directory}{os.path.sep}{symbol_name}"
									if not client.upload_file(spFile.local_debug_symbol_file, target_file_path):
										log(ERROR_LOG, f"Upload binary object: {symbol_name} ({spFile.local_debug_symbol_file}) failed!")
										return False
									else:
										log(INFO_LOG, f"Upload binary object: {symbol_name} ({spFile.local_debug_symbol_file}) succesfully")
		  
			log(INFO_LOG, f"\t{len(spFileContainer.files)} files sent succesfully!")
    
	log(INFO_LOG, f"Upload started succesfully! Job count: {len(upload_jobs)}")
	jobs = []
	for upload_job in upload_jobs:
		jobs.append(asyncio.create_task(upload_job))
	await asyncio.gather(*jobs)
  
	log(INFO_LOG, f"Upload completed succesfully!")
	return True

async def upload_file_index():
	log(INFO_LOG, f"Version: {config_data.version}")
	
	if config_data.version == 1:
		log(INFO_LOG, f"Current local file path {config_data.target_path}")
  
		for spFileContainer in config_data.file_containers:
			log(INFO_LOG, f"Current container: {spFileContainer.id}, File count: {len(spFileContainer.files)}")
   
			has_processed_file = False
			for spFile in spFileContainer.files:
				if spFile.processed and not len(spFile.preprocess):
					has_processed_file = True
			
			if not has_processed_file:
				log(INFO_LOG, "\tContainer have not any processed file!")
				continue
			else:
				for spFile in spFileContainer.files:
					if not spFile.processed or (config_data.skip_if_not_exist and spFile.processed and len(spFile.preprocess)):
						spFileContainer.files.remove(spFile)
			log(INFO_LOG, f"\tContainer have {len(spFileContainer.files)} processed file!")
   
			executable_files = []
			for spFile in spFileContainer.files:
				extension = os.path.splitext(spFile.name)[1]
				if extension == ".exe" or extension == ".dll" or extension == ".sys":
					executable_files.append(spFile)
			log(INFO_LOG, f"\tContainer have {len(executable_files)} executable file!")
   
			index_data = ""
			index_filename = f"{spFileContainer.id}_index.json"
			with open(index_filename, "r") as index_file:
				index_data = json.load(index_file)
				index_file.close()
    
			# Modify index for driver only request
			if len(executable_files) == 1:
				spFile = executable_files[0]

				data = {
					"files": {}
				}

				if not spFile.processed:
					log(ERROR_LOG, f"\tFile: {spFile.name} is not processed!")
					continue

				log(INFO_LOG, f"\tCurrent file: {spFile.name}")

				file_data = {
					"local_path": spFile.local_path,
					"size": spFile.size,
					"attr": spFile.attr,
					"hash": spFile.hash,
					"egg_hash": spFile.egg_hash,
					"binary_metadata": {},
					"symbol_metadata": {}
				}

				if spFile.binary_metadata:
					file_data["binary_metadata"] = spFile.binary_metadata

				if spFile.symbol_metadata:
					file_data["symbol_metadata"] = spFile.symbol_metadata

				data["files"][spFile.name] = file_data

				# Replace index data for single file request
				index_data = json.dumps(data, indent=4)
	
			single_file = False
			if len(executable_files) == 1:
				single_file = True
			# Single file request by CLI
			if config_data.update_file:
				single_file = True
 
			log(INFO_LOG, f"\tFile container ID: '{spFileContainer.id}', Version: '{config_data.patch_version}', Single file: {single_file}")
			log(INFO_LOG, f"\tIndex data: '{index_data}'")
 
			# Append index file
			data_list = {
				"id": spFileContainer.id,
				"version": str(config_data.patch_version),
				"branch": config_data.branch_name,
				"data": index_data,
				"single_file": "1" if single_file else "0",
				"archive_file": spFileContainer.archive_file,
				"archive_metadata": spFileContainer.archive_metadata
			}
   
			# async with aiohttp.ClientSession() as session:
			# 	async with session.post(PATCH_URL, data=data_list) as resp:
			# 		res = await resp.text()
			# 		log(INFO_LOG, f"\t{data_list} sent successfully! Response: {res}")
     
			# 		if res != "1":
			# 			log(ERROR_LOG, f"\tCPR result text: '{res}' is not valid")
			# 			return False

			try:
				headers = {"Content-Type": "application/json"}
				response = requests.post(PATCH_URL, json=data_list, headers=headers)

				response.raise_for_status()  # Raise an exception for non-200 status codes

				err_code = response.status_code
				status_code = response.status_code
				res_text = response.text

				log(INFO_LOG, f"\tConnection result: err: {err_code} status: {status_code} response: {res_text}")

				if res_text != "1":
					log(ERROR_LOG, f"\tCPR result text: '{res_text}' is not valid")
					return False

				log(INFO_LOG, f"\t{data_list} sent successfully!")
			except requests.exceptions.Timeout:
				log(ERROR_LOG, f"\tRequest timed out!")
				return False
			except requests.exceptions.RequestException as e:
				log(ERROR_LOG, f"\tConnection result: {e}")
				return False

			# try:
			# 	async with httpx.AsyncClient(timeout=30) as client:
			# 		response = await client.post(PATCH_URL, data=data_list)

			# 		response.raise_for_status()  # Raise an exception for non-200 status codes

			# 		err_code = response.status_code
			# 		status_code = response.status_code
			# 		res_text = response.text

			# 		log(INFO_LOG, f"\tConnection result: err: {err_code} status: {status_code} response: {res_text}")

			# 		if res_text != "1":
			# 			log(ERROR_LOG, f"\tCPR result text: '{res_text}' is not valid")
			# 			return False

			# 		log(INFO_LOG, f"\t{data_list} sent successfully!")
			# except httpx.TimeoutException:
			# 	log(ERROR_LOG, f"\tRequest timed out!")
			# 	return False
			# except httpx.RequestError as e:
			# 	log(ERROR_LOG, f"\tConnection result: {e}")
			# 	return False

	return True

async def activate_release():
	log(INFO_LOG, "Activating release...")

	body = {
		"branch_name": config_data.branch_name,
		"patch_version": config_data.patch_version
	}

	try:
		response = requests.post(PATCH_ACTIVATE_URL, json=body, timeout=5)

		response.raise_for_status()  # Raise an exception for non-200 status codes

		res_text = response.text

		log(INFO_LOG, f"\tConnection result: status: {response.status_code} response: {res_text}")

		if res_text != "1":
			log(ERROR_LOG, f"\tCPR result text: '{res_text}' is not valid")
			return False

		log(INFO_LOG, "\tRelease has been activated!")
		return True
	except requests.exceptions.RequestException as e:
		log(ERROR_LOG, f"\tRequest error: {e}")
		return False

async def load_worker():
	if not await process_file_list():
		log(ERROR_LOG, "Failed to process file list!")
		return False
	
	if not await create_zip_archive():
		log(ERROR_LOG, "Failed to create zip archive!")
		return False
	
	if not await create_file_index():
		log(ERROR_LOG, "Failed to create (1) file index!")
		return False
	
	if not await upload_files():
		log(ERROR_LOG, "Failed to upload files!")
		return False
	
	if not await create_file_index():
		log(ERROR_LOG, "Failed to create (2) file index!")
		return False
	
	if not await upload_file_index():
		log(ERROR_LOG, "Failed to upload file index!")
		return False
	
	return True