import os
import json
import hashlib
import math
import datetime
import zipfile
try:
    import pyzipper
except ImportError:
    pyzipper = None
import pefile

ZIP_PASSWORD = b"infected"

def calculate_hashes(file_path, data=None):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    if data is not None:
        md5.update(data)
        sha1.update(data)
        sha256.update(data)
    else:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
            
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }

def calculate_entropy(data):
    if not data:
        return 0.0
    
    entropy = 0

    length = len(data)
    frequencies = [0] * 256

    for byte in data:
        frequencies[byte] += 1

    for count in frequencies:
        if count > 0:
            p = float(count) / length
            entropy -= p * math.log(p, 2)

    return round(entropy, 4)

def extract_pe_info(file_path, data=None):
    if data is None and file_path.lower().endswith('.zip'):
        try:
            if pyzipper is not None:
                with pyzipper.AESZipFile(file_path) as z:
                    for name in z.namelist():
                        inner_data = z.read(name, pwd=ZIP_PASSWORD)
                        features = extract_pe_info(file_path, data=inner_data)
                        if "file_info" in features and features["file_info"]:
                            features["file_info"]["file_name"] = name
                        return features
            else:
                with zipfile.ZipFile(file_path) as z:
                    for name in z.namelist():
                        inner_data = z.read(name, pwd=ZIP_PASSWORD)
                        features = extract_pe_info(file_path, data=inner_data)
                        if "file_info" in features and features["file_info"]:
                            features["file_info"]["file_name"] = name
                        return features
        except Exception as e:
            return {"error": f"Failed to extract PE info from ZIP {file_path}: {e}"}

    if data is None and not os.path.exists(file_path):
        return {"error": f"File {file_path} khong ton tai."}

    features = {}
    
    try:
        # Ten + Kthc + Hash
        features["file_info"] = {
            "file_name": os.path.basename(file_path),
            "file_size_bytes": len(data) if data is not None else os.path.getsize(file_path),
            **calculate_hashes(file_path, data=data)
        }
    except Exception as e:
        return {"error": f"Failed to compute file hashes/info: {e}"}

    try:
        if data is not None:
            pe = pefile.PE(data=data)
        else:
            pe = pefile.PE(file_path)
            
        with pe:
            # Header
            try:
                compile_time = datetime.datetime.fromtimestamp(
                    pe.FILE_HEADER.TimeDateStamp, tz=datetime.timezone.utc
                ).isoformat()
            except (ValueError, OSError, OverflowError):
                compile_time = f"Invalid timestamp ({pe.FILE_HEADER.TimeDateStamp})"

            has_optional = hasattr(pe, 'OPTIONAL_HEADER')
            entry_point = (
                hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                if (has_optional and pe.OPTIONAL_HEADER.AddressOfEntryPoint is not None)
                else "0x0"
            )
            image_base = (
                hex(pe.OPTIONAL_HEADER.ImageBase)
                if (has_optional and pe.OPTIONAL_HEADER.ImageBase is not None)
                else "0x0"
            )
            subsystem = (
                pe.OPTIONAL_HEADER.Subsystem
                if (has_optional and pe.OPTIONAL_HEADER.Subsystem is not None)
                else 0
            )
            subsystem_str = pefile.SUBSYSTEM_TYPE.get(subsystem, f"Unknown ({subsystem})")

            try:
                imphash = pe.get_imphash()
            except Exception:
                imphash = ""

            features["headers"] = {
                "machine": pefile.MACHINE_TYPE.get(
                    pe.FILE_HEADER.Machine, f"Unknown ({hex(pe.FILE_HEADER.Machine)})"
                ),
                "compile_time": compile_time,
                "entry_point": entry_point,
                "image_base": image_base,
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                "subsystem": subsystem_str,
                "imphash": imphash
            }

            # Sections
            features["sections"] = []

            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                try:
                    section_data = section.get_data()
                except Exception:
                    section_data = b""
                
                # Quyen R W X
                characteristics = []
                char_val = section.Characteristics

                if char_val & 0x40000000: characteristics.append("READ")
                if char_val & 0x80000000: characteristics.append("WRITE")
                if char_val & 0x20000000: characteristics.append("EXECUTE")

                features["sections"].append({
                    "name": section_name,
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": calculate_entropy(section_data),
                    "characteristics": characteristics
                })

            # IAT
            features["imports"] = {}

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                try:
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        if not entry.dll:
                            continue
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                        features["imports"][dll_name] = []

                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode('utf-8', errors='ignore')
                            else:
                                func_name = f"ordinal_{imp.ordinal}"

                            features["imports"][dll_name].append(func_name)
                except Exception:
                    pass

            # export
            features["exports"] = []

            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                try:
                    img_base = (
                        pe.OPTIONAL_HEADER.ImageBase
                        if (has_optional and pe.OPTIONAL_HEADER.ImageBase is not None)
                        else 0
                    )
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            func_name = exp.name.decode('utf-8', errors='ignore')
                        else:
                            func_name = f"ordinal_{exp.ordinal}"
                            
                        if exp.address is not None:
                            address_str = hex(img_base + exp.address)
                        else:
                            address_str = "None"
                            
                        features["exports"].append({
                            "name": func_name,
                            "address": address_str
                        })
                except Exception:
                    pass

    except Exception as e:
        features["error"] = f"Failed to parse PE file structure: {e}"

    return features

def process_multiple_files(file_paths, output_json_path):
    combined_results = {}

    for path in file_paths:
        features = extract_pe_info(path)
        
        
        if "error" in features and not features.get("file_info"):
            key = path #Khong cos sha256 thi dung path
        else:
            key = features["file_info"]["sha256"]

        combined_results[key] = features

    output_dir = os.path.dirname(output_json_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_json_path, 'w', encoding='utf-8') as f:
        json.dump(combined_results, f, indent=4, ensure_ascii=False)
        


if __name__ == "__main__":

    #Chinh duong dan o day

    dataset_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dataset"))
    categories = ["benign", "malware"]

    for category in categories:
        folder_path = os.path.join(dataset_dir, category)
        files_to_analyze = []
        
        if os.path.exists(folder_path):
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file.lower().endswith(('.exe', '.dll', '.sys', '.zip')):
                        files_to_analyze.append(os.path.join(root, file))

        output_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output", f"{category}_pe_features.json"))
        
        print(f"Processing {category} files...")
        if files_to_analyze:
            process_multiple_files(files_to_analyze, output_file)
            print(f"Saved {category} features to {output_file}")
        else:
            print(f"Cannot find any files in {folder_path}")