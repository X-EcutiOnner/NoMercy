import os, sys
import aioboto3, aiofiles
import botocore.exceptions
import asyncio
import jstyleson
import hashlib
from log_helper import log, ERROR_LOG, INFO_LOG

BUCKET_NAME = "nomercy-client-files"
FILELIST_FILE_NAME = "artifact_list.txt"

def get_container_name(file_name):
    # TODO: Parse container name from file name
    return "ac_files"

def get_file_sha1(file_name):
    sha1 = hashlib.sha1()
    with open(file_name, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha1.update(data)
    return sha1.hexdigest()

class S3Client:
	def __init__(self, endpoint, access_key, secret_key, region):
		self.endpoint = endpoint
		self.access_key = access_key
		self.secret_key = secret_key
		self.region = region
		self.endpoint = "https://" + endpoint
		self.secure = True

		log(INFO_LOG, "Connecting to S3 endpoint: %s" % self.endpoint)
		self.session = aioboto3.Session(aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key, region_name=self.region)
		self.futures = []
   
	async def has_bucket(self, bucket_name):
		try:
			async with self.session.client('s3', endpoint_url=self.endpoint, verify=self.secure) as s3_client:
				response = await s3_client.list_buckets()
				log(INFO_LOG, f"Response: {response}")
				if not response or not 'Buckets' in response:
					log(ERROR_LOG, f"Failed to check if bucket {bucket_name} exists!")
					return False
    
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
			async with self.session.client('s3', endpoint_url=self.endpoint, verify=self.secure) as s3_client:
				response = await s3_client.create_bucket(Bucket=bucket_name)
				log(INFO_LOG, f"Response: {response}")
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
			return False
		except Exception as e:
			log(ERROR_LOG, f"Failed to create bucket: {e}")
			return False

	async def put_object(self, bucket_name, object_name, file_name, version, container, file_hash, on_complete=None, on_complete_args=None):
		log(INFO_LOG, f"Uploading file: {file_name} v({version}) as {object_name} to bucket: {bucket_name} from: {container} with hash: {file_hash}")

		if ".dll.bak" in file_name and "rtti" not in file_name:
			log(INFO_LOG, f"Skipping backup file: {file_name}")
			return None

		if not version or not container:
			log(ERROR_LOG, f"Skipping file: {file_name} because version or container is not set!")
			return None

		file_size = os.path.getsize(file_name)

		tags = f"version={version}&container={container}"
		if len(file_hash):
			tags += f"&hash={file_hash}"
		if file_size:
			tags += f"&size={file_size}"
  
		try:
			async with aiofiles.open(file_name, 'rb') as f:
				async with self.session.client('s3', endpoint_url=self.endpoint, verify=self.secure) as s3_client:
					response = await s3_client.put_object(Bucket=bucket_name, Key=object_name, Body=await f.read(), Tagging=tags)
					log(INFO_LOG, f"Response: {response}")
					metadata = await self.find_object_latest_version_id(bucket_name, object_name)
					log(INFO_LOG, f"File {file_name} metadata: {metadata}")
					if on_complete:
						await on_complete(object_name, metadata, on_complete_args)
					else:
						log(INFO_LOG, f"File {file_name} uploaded successfully!")
					return metadata
		except botocore.exceptions.ClientError as e:
			error_code = e.response['Error']['Code']
			error_message = e.response['Error']['Message']
			log(ERROR_LOG, f"Failed to put object {object_name} ({file_name}) to bucket {bucket_name}! Error: {error_code} - {error_message} Tag list: {tags}")
			return None
		except Exception as e:
			log(ERROR_LOG, f"[Exception] Failed to put object {object_name} ({file_name}) to bucket {bucket_name}! Error: {e} Tag list: {tags}")
			return None

	async def find_object_latest_version_id(self, bucket_name, key):
		async with self.session.client('s3', endpoint_url=self.endpoint, verify=self.secure) as s3_client:
			response = await s3_client.list_object_versions(Bucket=bucket_name, Prefix=key)
			log(INFO_LOG, f"Response: {response}")
			versions = response.get('Versions', [])
			if versions:
				latest_version = max(versions, key=lambda v: v['LastModified'])
				output = latest_version['VersionId']
				log(INFO_LOG, f"Found latest version id for {key} in bucket {bucket_name}: {output}")
				return output
			log(ERROR_LOG, f"Failed to find latest version id for {key} in bucket {bucket_name}!")
			return None

async def main(args):
	log(INFO_LOG, f"{args}")
	log(INFO_LOG, f"Path: {os.getcwd()}")
 
	if not args:
		log(ERROR_LOG, "Artifact filelist param not found!")
		return 1

	versionId = args[0]
	if not versionId:
		log(ERROR_LOG, "Version id param not found!")
		return 1

	artifactListFile = FILELIST_FILE_NAME
	if not os.path.exists(artifactListFile):
		log(ERROR_LOG, f"Artifact list file: {artifactListFile} does not exist!")
		return 1	

	configFile = os.path.join(os.getcwd(), "document", "internal", "patch_uploader_config.json")
	if not os.path.exists(configFile):
		log(ERROR_LOG, f"Config file: {configFile} does not exist!")
		return 1		

	hosts = []
	with open(configFile, 'r') as fp:
		buffer = fp.read()
		if not buffer:
			log(ERROR_LOG, "Config file could not read!")
			return 1
		
		doc = jstyleson.loads(buffer)
	
		if "hosts" not in doc:
			log(ERROR_LOG, "Config 'hosts' key does not exist!")
			return 1
		elif not isinstance(doc["hosts"], dict):
			log(ERROR_LOG, "Config 'hosts' key is not object!")
			return 1
		elif not doc["hosts"]:
			log(ERROR_LOG, "Config 'hosts' value is not valid!")
			return 1
		elif not doc["hosts"]["s3"]:
			log(ERROR_LOG, "Config 'hosts':'s3' value is not valid!")
			return 1

		hosts = doc["hosts"]

	host = hosts["s3"]

	client = S3Client(host["endpoint"], host["access_key"], host["secret_key"], host["region"])
	log(INFO_LOG, f"Initialized s3 host client: {client}")
 
	if not await client.has_bucket(BUCKET_NAME) and await client.create_bucket(BUCKET_NAME):
		log(ERROR_LOG, f"Bucket: {BUCKET_NAME} create failed!")
		return 1		

	artifactList = []
	with open(artifactListFile, 'r') as fp:
		artifactList = fp.readlines()
		if not artifactList:
			log(ERROR_LOG, "Artifact list file could not read!")
			return 1
 
	for artifactFile in artifactList:
		artifactFile = artifactFile.strip()
  
		if not os.path.exists(artifactFile):
			log(ERROR_LOG, f"Artifact file: {artifactFile} does not exist!")
			# return 1
			continue

		artifactObject = os.path.basename(artifactFile)
		artifactContainer = get_container_name(artifactObject)
		artifactHash = get_file_sha1(artifactFile)
  
		log(INFO_LOG, f"Put object: {artifactObject} :: {artifactFile} :: {versionId} :: {artifactContainer} :: {artifactHash}")

		if not await client.put_object(BUCKET_NAME, artifactObject, artifactFile, versionId, artifactContainer, artifactHash):
			log(ERROR_LOG, f"Put object: {artifactFile} failed!")
			return 1

		log(INFO_LOG, f"Put object: {artifactFile} completed!")

	return 0

if __name__ == '__main__':
	asyncio.run(main(sys.argv[1:]))
