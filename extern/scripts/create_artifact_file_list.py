import os, sys, glob, time

FILELIST_FILE_NAME = "artifact_list.txt"

folders_patterns = {
    "Bin": ["*.pdb", "*.bak", "*.dll", "*.exe", "*.sys", "*.cdb", "*.dat"],
    "extern\\bin\\CrashHandler": ["*.exe"],
    "document\\i18n_files": ["*.json"],
    "document\\license_files": ["*.txt"],
    "extern\\scripts\\Output": ["*.exe"],
    "Bin\\SDK": ["NoMercy_Loader_x*.lib"],
    "source\\Client\\SDK\\CppWrapper\\include": ["*.hpp"],
}

def find_files_in_folders(root_path, folder_patterns):
    file_list = []

    for folder, patterns in folder_patterns.items():
        folder_path = f"{root_path}{os.path.sep}{folder}"
        if not os.path.exists(folder_path):
            print(f"Folder not found: {folder_path}")
            continue

        for pattern in patterns:
            pattern_files = glob.glob(os.path.join(folder_path, pattern))
            file_list.extend(pattern_files)

    return file_list

def write_filelist_to_txt(file_list):
    # filename = f"{time.time()}_{FILELIST_FILE_NAME}"
    filename = FILELIST_FILE_NAME
    if (os.path.exists(filename)):
        os.remove(filename)
        
    with open(filename, "w") as file:
        file.write("\n".join(file_list))
        
    print(f"List file created: '{filename}'")
    print(f"Files: {str(file_list)}")

def main(args):
    files_found = find_files_in_folders(args[0], folders_patterns)
    if files_found:
        write_filelist_to_txt(files_found)
        print(f"{FILELIST_FILE_NAME} created successfully.")
    else:
        print("No files found.")    

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
