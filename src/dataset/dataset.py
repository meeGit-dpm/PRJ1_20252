import os
import time
import json
import zipfile
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import pyzipper
except ImportError:
    pyzipper = None

# ==========================================================
# CONFIG
# ==========================================================

API_URL = "https://mb-api.abuse.ch/api/v1/"
HEADER = {"Auth-Key": "YOUR_AUTH_KEY_HERE"}

MALWARE_TYPE = {
    "trojan": ["AgentTesla"],
    "botnet": ["Mirai"],
    "ransomware": ["WannaCry", "LockBit", "Phobos"],
    "spyware": ["RedLineStealer"],
    "worm": ["QakBot", "Emotet"],
    "rat": ["AsyncRAT"]}      # Malware families
TARGET_COUNT = 500        # Number of samples wanted each types
MAX_WORKERS = 20

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dataset", "malware"))
HASH_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "downloaded_hashes.txt"))

ZIP_PASSWORD = b"infected"

# ==========================================================
# SETUP
# ==========================================================

os.makedirs(OUTPUT_DIR, exist_ok=True)

if os.path.exists(HASH_FILE):
    with open(HASH_FILE, "r") as f:
        downloaded_hashes = set(
            line.strip() for line in f if line.strip()
        )
else:
    downloaded_hashes = set()

# ==========================================================
# HELPER FUNCTIONS
# ==========================================================

def save_hash(sha256):
    """
    Persist downloaded hashes.
    """

    with open(HASH_FILE, "a") as f:
        f.write(sha256 + "\n")

    downloaded_hashes.add(sha256)


def is_supported_format(entry):
    """
    Filter PE executables and assembly source code files.
    """

    file_type = str(entry.get("file_type", "")).lower()
    file_name = str(entry.get("file_name", "")).lower()

    target_keywords = [
        "exe",
        "dll",
        "pe",
        "asm",
        "assembly"
    ]

    if any(x in file_type for x in target_keywords):
        return True

    if file_name.endswith((".exe", ".dll", ".sys", ".asm")):
        return True

    return False


def query_family(signature, limit=100):
    data = {
        "query": "get_siginfo",
        "signature": signature,
        "limit": str(limit)
    }

    try:
        r = requests.post(API_URL, headers=HEADER, data=data, timeout=60)
        r.raise_for_status()
        result = r.json()
    except Exception as e:
        print(f"[-] API error: {e}")
        print("[-] Please ensure you have replaced 'YOUR-AUTH-KEY-HERE' with a valid API key in dataset.py")
        return []

    if result.get("query_status") != "ok":
        return []

    return result.get("data", [])


def download_sample(sha256, type):
    """
    Download a malware sample.
    """

    output_path = os.path.join(
        OUTPUT_DIR,
        type
    )
    os.makedirs(output_path, exist_ok=True)

    try:

        save_path = os.path.join(
            output_path,
            f"{sha256}.zip"
        )

        # If the zip file already exists on disk, try to extract it (in case a previous run failed to extract it)
        if os.path.exists(save_path):
            try:
                if pyzipper is not None:
                    with pyzipper.AESZipFile(save_path) as z:
                        z.extractall(path=output_path, pwd=ZIP_PASSWORD)
                else:
                    with zipfile.ZipFile(save_path) as z:
                        z.extractall(path=output_path, pwd=ZIP_PASSWORD)
                os.remove(save_path)
                save_hash(sha256)
                return "downloaded", sha256
            except Exception:
                # If extraction fails (e.g. missing pyzipper or corrupted file), delete it so it can be re-downloaded
                try:
                    os.remove(save_path)
                except Exception:
                    pass
                return "failed", sha256

        payload = {
            "query": "get_file",
            "sha256_hash": sha256
        }

        r = requests.post(
            API_URL,
            headers=HEADER,
            data=payload,
            timeout=120
        )

        if r.status_code != 200:
            return "failed", sha256

        with open(save_path, "wb") as f:
            f.write(r.content)

        if pyzipper is not None:
            with pyzipper.AESZipFile(save_path) as z:
                z.extractall(path=output_path, pwd=ZIP_PASSWORD)
        else:
            with zipfile.ZipFile(save_path) as z:
                z.extractall(path=output_path, pwd=ZIP_PASSWORD)
        os.remove(save_path)

        save_hash(sha256)

        return "downloaded", sha256

    except Exception:
        return "failed", sha256


# ==========================================================
# MAIN
# ==========================================================

def main():

    for type, signatures in MALWARE_TYPE.items():        

        print("\n==========================================================")
        print(f"Querying type: {type}")
        print("==========================================================")

        target = TARGET_COUNT // len(signatures)

        for signature in signatures:

            print(f"\nQuerying family: {signature}")

            samples = query_family(signature, target * 2)

            if not samples:
                print("No samples returned.")
                continue

            print(f"Found {len(samples)} candidate samples")

            candidates = []

            for sample in samples:

                sha256 = sample.get("sha256_hash")

                if not sha256:
                    continue

                if sha256 in downloaded_hashes:
                    continue

                if not is_supported_format(sample):
                    continue

                candidates.append(sha256)

            print(f"Candidates: {len(candidates)}")

            output_path = os.path.join(OUTPUT_DIR, type)
            existing = len(os.listdir(output_path)) if os.path.exists(output_path) else 0
            remaining = target - existing

            if remaining <= 0:
                print("Target already reached.")
                continue

            candidates = candidates[:remaining]

            print(f"Downloading {len(candidates)} samples...\n")

            downloaded = 0

            with ThreadPoolExecutor(
                max_workers=MAX_WORKERS
            ) as executor:

                futures = [
                    executor.submit(
                        download_sample,
                        sha256,
                        type
                    )
                    for sha256 in candidates
                ]

                for future in as_completed(futures):

                    status, sha256 = future.result()

                    if status == "downloaded":
                        downloaded += 1

                        print(
                            f"[{downloaded}] "
                            f"Downloaded {sha256}"
                        )

                    elif status == "exists":
                        print(f"Already exists: {sha256}")

                    else:
                        print(f"Failed: {sha256}")

                    if downloaded >= remaining:
                        break

            print("\nDone.")
            print(
                f"Total downloaded: "
                f"{len(downloaded_hashes)}"
            )


if __name__ == "__main__":
    main()