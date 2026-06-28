import os
import re
import json
import hashlib
import tempfile
import zipfile
from collections import Counter

try:
    import pyzipper
except ImportError:
    pyzipper = None

import pefile
from capstone import *


# ============================================================
# CONFIG
# ============================================================

ZIP_PASSWORD = b"infected"

SUSPICIOUS_STRINGS = {
    "powershell",
    "cmd.exe",
    "http://",
    "https://",
    "runonce",
    "regedit",
    "taskkill",
    "vssadmin",
    "bitcoin",
    "wallet"
}

COMMON_PORTS = {
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    443,
    445,
    8080
}


# ============================================================
# PE SECTION HELPERS
# ============================================================

def get_text_section(pe):
    """
    Locate .text section.
    """

    for section in pe.sections:

        name = section.Name.decode(
            errors="ignore"
        ).strip("\x00")

        if name == ".text":
            return section

    return None


# ============================================================
# DISASSEMBLY
# ============================================================

def extract_opcodes(filepath, data=None):
    """
    Extract opcode mnemonics from .text section.
    """

    try:
        if data is not None:
            pe = pefile.PE(data=data)
        else:
            pe = pefile.PE(filepath)
            
        with pe:
            text_section = get_text_section(pe)

            if text_section is None:
                return []

            code = text_section.get_data()

            has_optional = hasattr(pe, 'OPTIONAL_HEADER')
            image_base = pe.OPTIONAL_HEADER.ImageBase if (has_optional and pe.OPTIONAL_HEADER.ImageBase is not None) else 0

            address = (
                image_base
                + text_section.VirtualAddress
            )

            md = Cs(CS_ARCH_X86, CS_MODE_32)

            opcodes = []

            for ins in md.disasm(code, address):
                opcodes.append(ins.mnemonic)

            return opcodes

    except Exception:
        return []


def opcode_frequency(opcodes):
    return dict(Counter(opcodes))


def top_n_opcodes(opcodes, n=30):
    return dict(
        Counter(opcodes).most_common(n)
    )


# ============================================================
# OPCODE NGRAMS
# ============================================================

def opcode_ngrams(opcodes, n=3):

    grams = []

    for i in range(len(opcodes) - n + 1):

        grams.append(
            tuple(opcodes[i:i+n])
        )

    return grams


# ============================================================
# STRING EXTRACTION
# ============================================================

def extract_strings(filepath, min_length=4, data=None):

    try:
        if data is None:
            with open(filepath, "rb") as f:
                data = f.read()

        pattern = rb"[\x20-\x7E]{%d,}" % min_length

        matches = re.findall(
            pattern,
            data
        )

        return [
            s.decode(errors="ignore")
            for s in matches
        ]

    except Exception:
        return []


def suspicious_strings(strings):

    results = []

    for s in strings:

        lower = s.lower()

        for keyword in SUSPICIOUS_STRINGS:

            if keyword in lower:
                results.append(s)
                break

    return results


# ============================================================
# CONSTANT EXTRACTION
# ============================================================

def extract_constants(filepath, data=None):

    try:
        if data is None:
            with open(filepath, "rb") as f:
                data = f.read()

        matches = re.findall(
            rb"\d{2,10}",
            data
        )

        constants = []

        for m in matches:

            try:
                constants.append(
                    int(m)
                )

            except ValueError:
                pass

        return constants

    except Exception:
        return []


def detect_ports(constants):

    return list(
        set(constants)
        &
        COMMON_PORTS
    )


# ============================================================
# SAVE ASM FILE
# ============================================================

def save_disassembly(
        filepath,
        output_path):

    if filepath.lower().endswith('.zip'):
        try:
            if pyzipper is not None:
                with pyzipper.AESZipFile(filepath) as z:
                    for name in z.namelist():
                        data = z.read(name, pwd=ZIP_PASSWORD)
                        # Process first file
                        pe = pefile.PE(data=data)
                        with pe:
                            text_section = get_text_section(pe)
                            if text_section is None:
                                return
                            code = text_section.get_data()
                            has_optional = hasattr(pe, 'OPTIONAL_HEADER')
                            image_base = pe.OPTIONAL_HEADER.ImageBase if (has_optional and pe.OPTIONAL_HEADER.ImageBase is not None) else 0
                            address = (image_base + text_section.VirtualAddress)
                            md = Cs(CS_ARCH_X86, CS_MODE_32)
                            with open(output_path, "w", encoding="utf-8") as f:
                                for ins in md.disasm(code, address):
                                    f.write(f"{hex(ins.address)}: {ins.mnemonic} {ins.op_str}\n")
                        return
            else:
                with zipfile.ZipFile(filepath) as z:
                    for name in z.namelist():
                        data = z.read(name, pwd=ZIP_PASSWORD)
                        pe = pefile.PE(data=data)
                        with pe:
                            text_section = get_text_section(pe)
                            if text_section is None:
                                return
                            code = text_section.get_data()
                            has_optional = hasattr(pe, 'OPTIONAL_HEADER')
                            image_base = pe.OPTIONAL_HEADER.ImageBase if (has_optional and pe.OPTIONAL_HEADER.ImageBase is not None) else 0
                            address = (image_base + text_section.VirtualAddress)
                            md = Cs(CS_ARCH_X86, CS_MODE_32)
                            with open(output_path, "w", encoding="utf-8") as f:
                                for ins in md.disasm(code, address):
                                    f.write(f"{hex(ins.address)}: {ins.mnemonic} {ins.op_str}\n")
                        return
        except Exception:
            pass
        return

    try:
        with pefile.PE(filepath) as pe:
            text_section = get_text_section(pe)

            if text_section is None:
                return

            code = text_section.get_data()

            has_optional = hasattr(pe, 'OPTIONAL_HEADER')
            image_base = pe.OPTIONAL_HEADER.ImageBase if (has_optional and pe.OPTIONAL_HEADER.ImageBase is not None) else 0

            address = (
                image_base
                + text_section.VirtualAddress
            )

            md = Cs(
                CS_ARCH_X86,
                CS_MODE_32
            )

            with open(
                output_path,
                "w",
                encoding="utf-8"
            ) as f:

                for ins in md.disasm(
                        code,
                        address):

                    f.write(
                        f"{hex(ins.address)}: "
                        f"{ins.mnemonic} "
                        f"{ins.op_str}\n"
                    )
    except Exception:
        pass


# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

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
def extract_bytes_from_db(line):
    # Match db/dw/dd declarations
    # e.g., db 0x90, 0xeb, 0x19
    # or db "cmd.exe", 0
    # or db 'http://...'
    m = re.match(r'^\s*(?:db|dw|dd)\s+(.+)$', line, re.IGNORECASE)
    if not m:
        return b""
    
    parts = m.group(1).split(',')
    line_bytes = bytearray()
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # Check if it's a quoted string
        str_match = re.match(r'^["\']([^"\']*)["\']$', part)
        if str_match:
            line_bytes.extend(str_match.group(1).encode('utf-8', errors='ignore'))
        else:
            # Check if numeric constant (hex, dec, or bin)
            try:
                if part.lower().startswith('0x'):
                    val = int(part, 16)
                elif part.lower().endswith('h'):
                    val = int(part[:-1], 16)
                else:
                    val = int(part)
                # Append as bytes
                if 0 <= val < 256:
                    line_bytes.append(val)
            except ValueError:
                pass
    return bytes(line_bytes)


def extract_asm_from_text(filepath, data=None):
    """
    Extract opcodes, strings, and constants from an assembly (.asm) text file.
    Uses the Capstone engine to disassemble any binary bytes declared via db/dw/dd statements.
    """
    opcodes = []
    strings = []
    constants = []
    binary_payload = bytearray()
    
    try:
        if data is not None:
            text = data.decode(errors='ignore')
        else:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
                
        # Simple line-by-line parsing
        lines = text.splitlines()
        for line in lines:
            # Clean comments starting with ;
            line = line.split(';')[0].strip()
            if not line:
                continue
                
            # 1. Extract raw bytes from db/dw/dd directives
            line_bytes = extract_bytes_from_db(line)
            if line_bytes:
                binary_payload.extend(line_bytes)
                
            # 2. Extract strings from double/single quotes
            for s in re.findall(r'"([^"]*)"|\'([^\']*)\'', line):
                val = s[0] if s[0] else s[1]
                if len(val) >= 4:
                    strings.append(val)
                    
            # 3. Extract numeric constants
            for num_str in re.findall(r'\b\d+\b', line):
                constants.append(int(num_str))
                
            # 4. Clean labels and extract instruction mnemonics
            line_no_label = re.sub(r'^[a-zA-Z0-9_@\.\$]+:', '', line).strip()
            m = re.match(r'^([a-zA-Z]{2,6})\b', line_no_label)
            if m:
                op = m.group(1).lower()
                # Ignore common assembly pseudo-ops / directives
                if op not in {"db", "dw", "dd", "dq", "dt", "section", "segment", "global", "extern", "equ", "org", "align", "include", "end", "use32", "use64"}:
                    opcodes.append(op)

        # Disassemble binary payload using Capstone
        if binary_payload:
            try:
                md = Cs(CS_ARCH_X86, CS_MODE_32)
                for ins in md.disasm(bytes(binary_payload), 0x1000):
                    opcodes.append(ins.mnemonic)
            except Exception as e:
                print(f"[-] Capstone error disassembling payload in {filepath}: {e}")

            # Run Regex string extraction on assembled binary payload
            try:
                for s in re.findall(rb"[\x20-\x7E]{4,}", bytes(binary_payload)):
                    decoded = s.decode(errors='ignore')
                    if decoded not in strings:
                        strings.append(decoded)
            except Exception:
                pass
    except Exception as e:
        print(f"[-] Error parsing text ASM file {filepath}: {e}")
        
    return opcodes, strings, constants


def extract_asm_features(filepath, data=None):

    if data is None and filepath.lower().endswith('.zip'):
        try:
            if pyzipper is not None:
                with pyzipper.AESZipFile(filepath) as z:
                    for name in z.namelist():
                        inner_data = z.read(name, pwd=ZIP_PASSWORD)
                        features = extract_asm_features(name, data=inner_data)
                        if "file_info" in features and features["file_info"]:
                            features["file_info"]["file_name"] = name
                        return features
            else:
                with zipfile.ZipFile(filepath) as z:
                    for name in z.namelist():
                        inner_data = z.read(name, pwd=ZIP_PASSWORD)
                        features = extract_asm_features(name, data=inner_data)
                        if "file_info" in features and features["file_info"]:
                            features["file_info"]["file_name"] = name
                        return features
        except Exception as e:
            print(f"[-] Error extracting zip {filepath}: {e}")
            return {}

    if filepath.lower().endswith('.asm'):
        opcodes, strings, constants = extract_asm_from_text(filepath, data=data)
    else:
        opcodes = extract_opcodes(filepath, data=data)
        strings = extract_strings(filepath, data=data)
        constants = extract_constants(filepath, data=data)

    try:
        file_info = {
            "file_name": os.path.basename(filepath),
            "file_size_bytes": len(data) if data is not None else os.path.getsize(filepath),
            **calculate_hashes(filepath, data=data)
        }
    except Exception as e:
        print(f"[-] Hash/info extraction error for {filepath}: {e}")
        file_info = {}

    return {

        "file_info":
            file_info,

        "opcode_count":
            len(opcodes),

        "top_opcodes":
            top_n_opcodes(
                opcodes,
                n=30
            ),

        "opcode_ngrams":
            [
                list(x)
                for x in opcode_ngrams(
                    opcodes,
                    n=3
                )[:500]
            ],

        "string_count":
            len(strings),

        "suspicious_strings":
            suspicious_strings(strings),

        "detected_ports":
            detect_ports(constants)
    }


# ============================================================
# SAVE FEATURES
# ============================================================

def save_feature_json(
        filepath,
        output_json):

    features = extract_asm_features(
        filepath
    )

    output_dir = os.path.dirname(output_json)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(
        output_json,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            features,
            f,
            indent=4
        )

# ============================================================
# PROCESS ENTIRE DATASET
# ============================================================

def process_dataset(dataset_root,
                    feature_root,
                    asm_root=None):

    for root, dirs, files in os.walk(dataset_root):

        for filename in files:

            filepath = os.path.join(
                root,
                filename
            )

            try:

                relative_path = os.path.relpath(
                    root,
                    dataset_root
                )

                feature_dir = os.path.join(
                    feature_root,
                    relative_path
                )

                os.makedirs(
                    feature_dir,
                    exist_ok=True
                )

                features = extract_asm_features(
                    filepath
                )

                # Determine output filename (use inner file name if it was a zip)
                out_name = filename
                if filename.lower().endswith('.zip'):
                    if features.get("file_info") and "file_name" in features["file_info"]:
                        out_name = features["file_info"]["file_name"]
                    else:
                        out_name = filename[:-4]

                json_path = os.path.join(
                    feature_dir,
                    f"{out_name}.json"
                )

                with open(
                    json_path,
                    "w",
                    encoding="utf-8"
                ) as f:

                    json.dump(
                        features,
                        f,
                        indent=4
                    )

                if asm_root:

                    asm_dir = os.path.join(
                        asm_root,
                        relative_path
                    )

                    os.makedirs(
                        asm_dir,
                        exist_ok=True
                    )

                    asm_path = os.path.join(
                        asm_dir,
                        f"{out_name}.asm"
                    )

                    save_disassembly(
                        filepath,
                        asm_path
                    )

                print(
                    f"[+] {out_name}"
                )

            except Exception as e:

                print(
                    f"[-] {filename}: {e}"
                )

# ============================================================
# PROCESS MULTIPLE FILES
# ============================================================

def process_multiple_files(file_paths, output_json_path):
    combined_results = {}

    for path in file_paths:
        features = extract_asm_features(path)
        
        if not features.get("file_info") or "sha256" not in features["file_info"]:
            key = path
        else:
            key = features["file_info"]["sha256"]

        combined_results[key] = features

    output_dir = os.path.dirname(output_json_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_json_path, 'w', encoding='utf-8') as f:
        json.dump(combined_results, f, indent=4, ensure_ascii=False)


# ============================================================
# ENTRY POINT
# ============================================================

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
                    if file.lower().endswith(('.exe', '.dll', '.sys', '.zip', '.asm')):
                        files_to_analyze.append(os.path.join(root, file))

        output_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output", f"{category}_asm_features.json"))

        print(f"Processing {category} files...")
        if files_to_analyze:
            process_multiple_files(files_to_analyze, output_file)
            print(f"Saved {category} features to {output_file}")
        else:
            print(f"Cannot find any files in {folder_path}")