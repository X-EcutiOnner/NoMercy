import pickle
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum

DEFAULT_CRYPT_KEY_LENGTH = 64
DefaultCryptionKey = bytearray([
    # Key: 0 - 32
    0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x2,

    # IV: 32 - 64
    0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9, 0x0, 0x0, 0x4
])

class EFileAttributes(Enum):
	FILE_ATTR_NONE = 1 << 0
	FILE_ATTR_PATH_SYSTEM = 1 << 1
	FILE_ATTR_PATH_GAME = 1 << 2
	FILE_ATTR_PATH_LOCAL = 1 << 3
	FILE_ATTR_HIDDEN = 1 << 4
	FILE_ATTR_CRYPTED_1 = 1 << 5  # AES256
	FILE_ATTR_COMPRESSED_1 = 1 << 6  # LZ4
	
@dataclass
class SObjectDetails:
	hostname: str
	metadata: str

@dataclass
class SFileCtx:
	name: str
	new_name: str = ""
	local_source_file: str = ""
	local_debug_symbol_file: str = ""
	local_path: str = ""
	attr: int = 0
	preprocess: str = ""
	size: int = 0
	hash: str = ""
	egg_hash: str = ""
	optional: bool = False
	skip_pdb: bool = False
	processed: bool = False
	binary_metadata: List[SObjectDetails] = None
	symbol_metadata: List[SObjectDetails] = None

@dataclass
class SFileContainerCtx:
	id: str
	method: str
	files: List[SFileCtx]
	archive_file: str = ""
	archive_metadata: str = ""

@dataclass
class SHostCtx:
	hostname: str
	endpoint: str
	access_key: str
	secret_key: str

@dataclass
class SSFTPHostCtx:
	hostname: str
	endpoint: str
	port: int
	username: str
	password: str

# Serialization functions
def serialize(obj):
	return pickle.dumps(obj)
def deserialize(data):
	return pickle.loads(data)
