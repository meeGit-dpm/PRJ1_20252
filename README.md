# Heuristic Malware Detection & Feature Extraction System

A static-analysis based heuristic malware detection system written in Python. This project provides utilities to download malware samples, extract PE headers and disassembly (assembly instructions) features, and statically classify files as benign or malware using heuristic rule matching and Finite State Machines (FSMs).

## Table of Contents
- [Project Architecture](#project-architecture)
- [Requirements & Installation](#requirements--installation)
- [Usage Instructions](#usage-instructions)
  - [1. Downloading Malware Dataset](#1-downloading-malware-dataset)
  - [2. Extracting PE Features](#2-extracting-pe-features)
  - [3. Extracting Assembly Features](#3-extracting-assembly-features)
  - [4. Evaluating & Scanning Files](#4-evaluating--scanning-files)
- [Detection Engine Heuristics](#detection-engine-heuristics)
  - [State Machines (FSM)](#state-machines-fsm)
  - [Static Analysis & Heuristics](#static-analysis--heuristics)

---

## Project Architecture

```text
PRJ1/
├── dataset/                  # Dataset directory containing raw PE files
│   ├── benign/               # User-supplied benign files (.exe, .dll, etc.)
│   └── malware/              # Downloaded malware files grouped by type
├── output/                   # Directory containing extracted JSON features and reports
├── report/                   # Project documentation and reports
├── src/
│   ├── dataset/
│   │   └── dataset.py        # Malware dataset downloader (Abuse.ch MalwareBazaar API)
│   ├── pe_extractor/
│   │   └── pe_extractor.py   # Extracts PE headers, sections, imports, and exports
│   ├── asm_extractor/
│   │   └── asm_extractor.py  # Disassembles PE code sections and extracts opcodes/strings
│   └── detector/
│       ├── engine.py         # Heuristic rules & FSM detection logic
│       ├── rules.py          # Configuration arrays for APIs & strings
│       └── evaluate.py       # Main evaluation entry point and scanner CLI
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

---

## Requirements & Installation

The project requires Python 3.8+ and the following third-party dependencies:
* `pefile` - Portable Executable (PE) parsing library.
* `capstone` - Disassembly framework for machine instructions.
* `requests` - HTTP library for dataset downloads.
* `pyzipper` - Required to extract password-protected AES zip files (malware samples from MalwareBazaar).

Install the requirements by running:
```bash
pip install -r requirements.txt
```

---

## Usage Instructions

### 1. Downloading Malware Dataset
The dataset downloader uses the [MalwareBazaar API](https://bazaar.abuse.ch/api/) to fetch real Windows PE malware samples.

1. Open `src/dataset/dataset.py`.
2. Replace `"YOUR_AUTH_KEY_HERE"` with your actual MalwareBazaar API key on line 18:
   ```python
   HEADER = {"Auth-Key": "YOUR_AUTH_KEY_HERE"}
   ```
3. Run the script to download malware families (e.g. AgentTesla, Mirai, WannaCry, RedLineStealer) into the `dataset/malware/` folder:
   ```bash
   python src/dataset/dataset.py
   ```
   *Note: Samples are downloaded as zipped files encrypted with password `infected` and automatically extracted to `.exe` / `.dll` format by the script.*

### 2. Extracting PE Features
Extract structural features (Machine type, Section info, Entropy, Imports, Exports, and Hashes) from both benign and malware datasets:
```bash
python src/pe_extractor/pe_extractor.py
```
This scans all PE files in `dataset/benign/` and `dataset/malware/` and saves the combined results to:
* `output/benign_pe_features.json`
* `output/malware_pe_features.json`

### 3. Extracting Assembly Features
Disassemble the `.text` section of files to extract instruction sequences, opcode counts, n-grams, suspicious strings, and constants:
```bash
python src/asm_extractor/asm_extractor.py
```
This runs the Capstone disassembler on the files in `dataset/benign/` and `dataset/malware/` and saves the output to:
* `output/benign_asm_features.json`
* `output/malware_asm_features.json`

### 4. Evaluating & Scanning Files
`src/detector/evaluate.py` serves as the CLI tool for the detection system. It supports several execution modes:

#### Mode A: Evaluate Pre-Extracted Datasets (Performance Report)
Run the script without arguments to calculate detection statistics (Accuracy, Precision, Recall, F1 Score) across the pre-extracted JSON feature files:
```bash
python src/detector/evaluate.py
```
The console prints performance metrics and writes a detailed log (including False Positives and False Negatives) to `output/evaluation_report.txt`.

#### Mode B: Static Scan of a Single File
Scan a specific file on your disk (extracts features dynamically and evaluates it):
```bash
python src/detector/evaluate.py <path_to_file>
```
*Example Output:*
```text
==================================================
              EVALUATION RESULT                   
==================================================
File: infected.exe
Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Result: MALWARE (Score: 75/50, Malware Probability: 91.79%)
--------------------------------------------------
Details:
  - High section entropy: 7.621
  - Behavior FSM threat state reached: INJECTING (+15 points)
  - Process Injection APIs: ['VirtualAllocEx', 'WriteProcessMemory']
--------------------------------------------------
Behaviors:
  - Evasion / Packing
    Indicators: ['Entropy: 7.6210']
  - Process Injection / Hollowing
    Indicators: ["APIs: ['VirtualAllocEx', 'WriteProcessMemory']"]
==================================================
```

#### Mode C: Scan an Entire Directory
Scan all PE executables inside a target directory:
```bash
python src/detector/evaluate.py <path_to_directory>
```
The summary report containing classification results for all found files will be output to `output/dataset_evaluation_report.txt`.

#### Mode D: Evaluate Random Sample from Pre-Extracted Features
Pick a random sample from the pre-extracted feature files to test the engine:
* **Random Malware:**
  ```bash
  python src/detector/evaluate.py --random-malware
  # or
  python src/detector/evaluate.py -rm
  ```
* **Random Benign:**
  ```bash
  python src/detector/evaluate.py --random-benign
  # or
  python src/detector/evaluate.py -rb
  ```

---

## Detection Engine Heuristics

### State Machines (FSM)
1. **Behavior FSM (`BehaviorFSM`)**: Analyzes the import address table (IAT) to trace suspicious sequences of Windows APIs. It transitions through the following threat states:
   * `CLEAN` &rarr; `EVASIVE` (upon debug evasion detection)
   * `EVASIVE`/`CLEAN` &rarr; `SURVEY` (process enumeration)
   * `SURVEY`/`EVASIVE`/`CLEAN` &rarr; `INJECTING` (process injection/memory writing)
   * `INJECTING` &rarr; `MALICIOUS` (network socket/download APIs triggered)
2. **Decryption Loop FSM (`DecryptionLoopFSM`)**: Feeds opcode 3-grams to detect typical decryption loop patterns (e.g., `xor/rol/ror` &rarr; arithmetic update instruction `inc/dec/add/sub` &rarr; conditional branch `jnz/jne/loop`).

### Static Analysis & Heuristics
The engine computes a threat score based on several indicators:
* **Section Entropy**: High entropy (&gt; 7.5) triggers points for packing or encryption.
* **W^X Violations**: Sections marked as both Writable and Executable.
* **Size Anomalies**: Large mismatches between section raw size and virtual size.
* **Massive Overlays**: Large quantities of data appended to the end of the executable.
* **Import Anomalies**: Zero imports, very few imports (indicative of packed/shellcode wrapper), or dynamic API resolution loops (using `GetProcAddress` + `LoadLibrary` + `VirtualAlloc`).
* **High-Risk Strings**: Presence of sensitive keywords (e.g. `vssadmin`, `shadowcopy`, `exclusionprocess`).
* **Whitelists & Discounts**: Score deductions applied to complex files (like drivers or files with high numbers of exports and imports) to reduce False Positives.
