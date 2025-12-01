import os
import sys
import sentry_sdk
import argparse
import asyncio

from log_helper import log, ERROR_LOG, INFO_LOG
import config_data
import config_parser
import s3_helper
import ftp_helper
import worker

# --branch=dev --config=C:\\Users\\PC\\NoMercy_git\\document\\internal\\patch_uploader_config.json --version=513 --root_path=C:\\Users\\PC\\NoMercy_git\\Bin_public

async def main(args):
	log(INFO_LOG, f"{args}")
	log(INFO_LOG, f"Path: {os.getcwd()}")
 
	# Initialize sentry
	sentry_sdk.init(dsn="http://33a2d1daf39d44cebc0667fde3ed8ff2@10.144.40.11:9000/8", traces_sample_rate=1.0)
	config_data.sentry_ready = True
	
	# Parse args
	parser = argparse.ArgumentParser()

	parser.add_argument('-a', '--activate_release', action='store', dest='activate_release', type=int, default=0,
						help='Activate uploaded release')
	parser.add_argument('-b', '--branch', action='store', dest='branch', type=str,
						help='Env branch name', required=True, choices=["master", "develop", "staging", "local"])
	parser.add_argument('-c', '--config', action='store', dest='config', type=str,
						help='PatchUpdater config file name', required=True)
	parser.add_argument('-v', '--version', action='store', dest='version', type=int,
						help='Patch version number', required=True)
	parser.add_argument('-r', '--root_path', action='store', dest='root_path', type=str,
						help='Bin_public path', required=True)
	parser.add_argument('-s', '--skip_if_not_exist', action='store', dest='skip_if_not_exist', type=int, default=0,
						help='Skip file if not exist')
	parser.add_argument('-u', '--update_file', action='store', dest='update_file', type=str,
						help='Update single file')
	args = parser.parse_args()

	if not os.path.exists(args.config):
		log(ERROR_LOG, f"Config file '{args.config}' does not exist!")
		return 1

	if not args.version or args.version > 100000:
		log(ERROR_LOG, f"Patch version '{args.version}' is not correct!")
		return 1

	if not os.path.exists(args.root_path):
		log(ERROR_LOG, f"Root path '{args.root_path}' does not exist!")
		return 1

	# Save args
	if args.branch == "master":
		config_data.branch_name = "release"
	elif args.branch == "develop":
		config_data.branch_name = "dev"
	elif args.branch == "staging":
		config_data.branch_name = "beta"
	elif args.branch != "local":
		log(ERROR_LOG, f"Invalid branch name '{args.branch}'")
		return 1
	else:
		config_data.branch_name = "local"

	config_data.activate_release = args.activate_release == 1
	config_data.config_file_name = args.config
	config_data.patch_version = args.version
	config_data.root_path = args.root_path
	
	if args.skip_if_not_exist == 1:
		config_data.skip_if_not_exist = True
	if args.update_file:
		config_data.update_file = args.update_file

	if config_data.activate_release:
		if not worker.activate_release():
			log(ERROR_LOG, "Failed to activate release!")
			return 1
		else:
			log(INFO_LOG, "Release activated successfully!")
			return 0

	if not config_parser.parse_config_file():
		log(ERROR_LOG, "Failed to parse config file!")
		return 1

	if not ftp_helper.initialize():
		log(ERROR_LOG, "Failed to initialize FTP helper!")
		return 1

	if not await s3_helper.initialize():
		log(ERROR_LOG, "Failed to initialize S3 helper!")
		return 1

	if not await worker.load_worker():
		log(ERROR_LOG, "Failed to load worker!")
		return 1

	log(INFO_LOG, "Patch updater successfully completed!")
	return 0

if __name__ == '__main__':
	asyncio.run(main(sys.argv[1:]))
