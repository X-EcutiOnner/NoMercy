import os
import aiofiles
import botocore.exceptions
import aioboto3
import config_data
import sys
from log_helper import log, ERROR_LOG, INFO_LOG

class S3Client:
	def __init__(self, endpoint, access_key, secret_key, region):
		self.endpoint = endpoint
		self.access_key = access_key
		self.secret_key = secret_key
		self.region = region
		# if not endpoint.startswith("http://") and not endpoint.startswith("https://"):
		# 	if "amazonaws.com" in endpoint:
		# 		self.endpoint = "https://" + endpoint
		# 	else:
		# 		self.endpoint = "http://" + endpoint
		self.endpoint = "https://" + endpoint
		self.secure = True

		log(INFO_LOG, "Connecting to S3 endpoint: %s" % self.endpoint)
		self.session = aioboto3.Session()
		self.futures = []
   
	async def has_bucket(self, bucket_name):
		try:
			async with self.session.client('s3', endpoint_url=self.endpoint, aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key, region_name=self.region, verify=self.secure) as s3_client:
				response = await s3_client.list_buckets()
				buckets = [bucket['Name'] for bucket in response['Buckets']]
				if bucket_name in buckets:
					log(INFO_LOG, f"Bucket {bucket_name} found! In: {buckets}")
					return True
				log(ERROR_LOG, f"Bucket {bucket_name} not found! In: {buckets}")
				return False
		except botocore.exceptions.ClientError as e:
			error_code = e.response['Error']['Code']
			error_message = e.response['Error']['Message']
			log(ERROR_LOG, f"Failed to check if bucket {bucket_name} exists! Error: {error_code} - {error_message}")
			return False
	
	async def create_bucket(self, bucket_name):
		try:
			async with self.session.client('s3', endpoint_url=self.endpoint, aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key, region_name=self.region, verify=self.secure) as s3_client:
				await s3_client.create_bucket(Bucket=bucket_name)
				log(INFO_LOG, "Bucket created successfully!")
				return True
		except botocore.exceptions.ClientError as e:
			error_code = e.response['Error']['Code']
			error_message = e.response['Error']['Message']
			if error_code == 'BucketAlreadyOwnedByYou':
				log(ERROR_LOG, "Bucket already exists and is owned by you.")
			elif error_code == 'BucketAlreadyExists':
				log(ERROR_LOG, "Bucket already exists and is owned by someone else.")
			else:
				log(ERROR_LOG, f"Failed to create bucket: {error_code} - {error_message}")
		except Exception as e:
			log(ERROR_LOG, f"Failed to create bucket: {e}")
		return False

	async def put_object(self, bucket_name, object_name, file_name, version, container, file_hash, on_complete=None, on_complete_args=None):
		log(INFO_LOG, f"Uploading file: {file_name} v({version}) as {object_name} to bucket: {bucket_name} from: {container} with hash: {file_hash}")
		metaData = ""

		if ".dll.bak" in file_name and "rtti" not in file_name:
			log(INFO_LOG, f"Skipping backup file: {file_name}")
			return metaData

		if not version or not container:
			log(ERROR_LOG, f"Skipping file: {file_name} because version or container is not set!")
			return metaData

		file_size = os.path.getsize(file_name)

		tags = f"version={version}&container={container}"
		if len(file_hash):
			tags += f"&hash={file_hash}"
		if file_size:
			tags += f"&size={file_size}"
  
		try:
			async with aiofiles.open(file_name, 'rb') as f:
				async with self.session.client('s3', endpoint_url=self.endpoint, aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key, region_name=self.region, verify=self.secure) as s3_client:
					await s3_client.put_object(Bucket=bucket_name, Key=object_name, Body=await f.read(), Tagging=tags)
					metadata = await self.find_object_latest_version_id(bucket_name, object_name)
					log(INFO_LOG, f"File {file_name} metadata: {metadata}")
					if on_complete:
						await on_complete(object_name, metadata, on_complete_args)
					else:
						log(INFO_LOG, f"File {file_name} uploaded successfully!")
		except botocore.exceptions.ClientError as e:
			error_code = e.response['Error']['Code']
			error_message = e.response['Error']['Message']
			log(ERROR_LOG, f"Failed to put object {object_name} ({file_name}) to bucket {bucket_name}! Error: {error_code} - {error_message} Tag list: {tags}")
			sys.exit(1)
		except Exception as e:
			log(ERROR_LOG, f"[Exception] Failed to put object {object_name} ({file_name}) to bucket {bucket_name}! Error: {e} Tag list: {tags}")
			sys.exit(1)

		return metaData

	async def find_object_latest_version_id(self, bucket_name, key):
		async with self.session.client('s3', endpoint_url=self.endpoint, aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key, region_name=self.region, verify=self.secure) as s3_client:
			response = await s3_client.list_object_versions(Bucket=bucket_name, Prefix=key)
			versions = response.get('Versions', [])
			if versions:
				latest_version = max(versions, key=lambda v: v['LastModified'])
				output = latest_version['VersionId']
				log(INFO_LOG, f"Found latest version id for {key} in bucket {bucket_name}: {output}")
				return output
			log(ERROR_LOG, f"Failed to find latest version id for {key} in bucket {bucket_name}!")
			return None

async def initialize():
	if not config_data.hosts:
		log(ERROR_LOG, "No s3 hosts found!")
		return False

	for host in config_data.hosts:
		log(INFO_LOG, f"Initializing s3 host: {host}")

		if "endpoint" not in host or "access_key" not in host or "secret_key" not in host or "region" not in host:
			log(ERROR_LOG, "Invalid s3 host configuration!")
			return False

		idx = config_data.hosts.index(host)
		config_data.hosts[idx]["client"] = S3Client(host["endpoint"], host["access_key"], host["secret_key"], host["region"])
		log(INFO_LOG, f"Initialized s3 host: {host['client']}")

		# if not await config_data.hosts[idx]["client"].has_bucket(config_data.bucket_name):
		# 	log(ERROR_LOG, f"Bucket {config_data.bucket_name} not found in s3 host: {host}")
		# 	return False

		# log(INFO_LOG, f"Bucket {config_data.bucket_name} found in s3 host: {host}")

	return True
