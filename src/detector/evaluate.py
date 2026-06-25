import json
import os
import sys
import random
import argparse

# Add parent directory to sys.path to allow importing pe_extractor and asm_extractor
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(current_dir)
if src_dir not in sys.path:
    sys.path.append(src_dir)

from engine import MalwareDetector

try:
    from pe_extractor.pe_extractor import extract_pe_info
    from asm_extractor.asm_extractor import extract_asm_features
except ImportError:
    extract_pe_info = None
    extract_asm_features = None

# Paths to feature files
base_dir = os.path.dirname(os.path.abspath(__file__))
output_dir = os.path.abspath(os.path.join(base_dir, "..", "..", "output"))

pe_benign_path = os.path.join(output_dir, "benign_pe_features.json")
pe_malware_path = os.path.join(output_dir, "malware_pe_features.json")
asm_benign_path = os.path.join(output_dir, "benign_asm_features.json")
asm_malware_path = os.path.join(output_dir, "malware_asm_features.json")


def load_json(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Feature file not found at {path}")
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def combine_features(pe_data, asm_data):
    combined = {}
    for h in pe_data:
        if h in asm_data:
            combined[h] = {
                "pe": pe_data[h],
                "asm": asm_data[h]
            }
    return combined


def evaluate_file(file_path, detector):
    if not os.path.exists(file_path):
        print(f"Error: File not found at {file_path}")
        return

    if extract_pe_info is None or extract_asm_features is None:
        print("Error: Extraction modules not available.")
        return

    # Extract PE features
    pe_features = extract_pe_info(file_path)
    if "error" in pe_features and not pe_features.get("file_info"):
        print(f"Error extracting PE features from {file_path}: {pe_features['error']}")
        return

    # Extract ASM features
    asm_features = extract_asm_features(file_path)

    # Run detection
    res = detector.detect(pe_features, asm_features)

    # Output result
    print("==================================================")
    print("              EVALUATION RESULT                   ")
    print("==================================================")
    print(f"File: {os.path.basename(file_path)}")
    print(f"Hash: {pe_features['file_info']['sha256']}")
    status = "MALWARE" if res["is_malware"] else "BENIGN"
    print(
        f"Result: {status} (Score: {res['score']}/{detector.threshold}, Malware Probability: {res['malware_probability']:.2f}%)")
    print("--------------------------------------------------")
    print("Details:")
    if res["details"]:
        for detail in res["details"]:
            print(f"  - {detail}")
    else:
        print("  - None")
    print("--------------------------------------------------")
    print("Behaviors:")
    if res["detected_behaviors"]:
        for behavior in res["detected_behaviors"]:
            print(f"  - {behavior['behavior']}")
            print(f"    Indicators: {behavior['indicators']}")
    else:
        print("  - None")
    print("==================================================")


def evaluate_directory(dir_path, detector):
    if not os.path.exists(dir_path):
        print(f"Error: Directory not found at {dir_path}")
        return

    if extract_pe_info is None or extract_asm_features is None:
        print("Error: Extraction modules not available.")
        return

    # Find all executable files recursively
    executables = []
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if file.lower().endswith(('.exe', '.dll', '.sys', '.zip')):
                executables.append(os.path.join(root, file))

    if not executables:
        print("No executable files (.exe, .dll, .sys, .zip) found in directory.")
        return

    print(f"Found {len(executables)} executable files. Evaluating...")

    malware_count = 0
    benign_count = 0
    report = []

    for file_path in executables:
        pe_features = extract_pe_info(file_path)
        if "error" in pe_features and not pe_features.get("file_info"):
            continue
        asm_features = extract_asm_features(file_path)
        res = detector.detect(pe_features, asm_features)

        status = "MALWARE" if res["is_malware"] else "BENIGN"
        if res["is_malware"]:
            malware_count += 1
        else:
            benign_count += 1

        report.append(
            f"[{status}] (Score: {res['score']}, Probability: {res['malware_probability']:.2f}%) {os.path.basename(file_path)}")

    report.append("==================================================")
    report.append("          DATASET EVALUATION REPORT               ")
    report.append("==================================================")
    report.append(f"Total Evaluated Samples: {len(executables)}")
    report.append(f"  Benign Detected      : {benign_count}")
    report.append(f"  Malware Detected     : {malware_count}")
    report.append("==================================================")

    report_content = "\n".join(report)
    report_path = os.path.join(output_dir, "dataset_evaluation_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"Evaluation complete. Report written to: {report_path}")


def evaluate_random_sample(pe_path, asm_path, detector, label="MALWARE"):
    try:
        pe_data = load_json(pe_path)
        asm_data = load_json(asm_path)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return

    dataset = combine_features(pe_data, asm_data)
    if not dataset:
        print(f"No combined features found for {label} dataset.")
        return

    h = random.choice(list(dataset.keys()))
    data = dataset[h]

    res = detector.detect(data["pe"], data["asm"])

    # Output result
    print("==================================================")
    print(f"        RANDOM {label} SAMPLE EVALUATION          ")
    print("==================================================")
    print(f"File: {data['pe']['file_info']['file_name']}")
    print(f"Hash: {h}")
    status = "MALWARE" if res["is_malware"] else "BENIGN"
    print(
        f"Result: {status} (Score: {res['score']}/{detector.threshold}, Malware Probability: {res['malware_probability']:.2f}%)")
    print("--------------------------------------------------")
    print("Details:")
    if res["details"]:
        for detail in res["details"]:
            print(f"  - {detail}")
    else:
        print("  - None")
    print("--------------------------------------------------")
    print("Behaviors:")
    if res["detected_behaviors"]:
        for behavior in res["detected_behaviors"]:
            print(f"  - {behavior['behavior']}")
            print(f"    Indicators: {behavior['indicators']}")
    else:
        print("  - None")
    print("==================================================")


def main():
    parser = argparse.ArgumentParser(description="Evaluate malware files or datasets.")
    parser.add_argument("path", nargs="?", default=None,
                        help="Path to an executable file or a directory to evaluate statically.")
    parser.add_argument("--random-malware", "-rm", action="store_true",
                        help="Pick a random malware sample from the pre-extracted features and evaluate it.")
    parser.add_argument("--random-benign", "-rb", action="store_true",
                        help="Pick a random benign sample from the pre-extracted features and evaluate it.")
    args = parser.parse_args()

    detector = MalwareDetector()

    if args.random_malware:
        evaluate_random_sample(pe_malware_path, asm_malware_path, detector, label="MALWARE")
        return
    elif args.random_benign:
        evaluate_random_sample(pe_benign_path, asm_benign_path, detector, label="BENIGN")
        return
    elif args.path:
        if os.path.isdir(args.path):
            evaluate_directory(args.path, detector)
        else:
            evaluate_file(args.path, detector)
        return

    # Load features for full dataset evaluation
    pe_benign = load_json(pe_benign_path)
    pe_malware = load_json(pe_malware_path)
    asm_benign = load_json(asm_benign_path)
    asm_malware = load_json(asm_malware_path)

    benign_dataset = combine_features(pe_benign, asm_benign)
    malware_dataset = combine_features(pe_malware, asm_malware)

    tp, fp, tn, fn = 0, 0, 0, 0
    false_positives = []
    false_negatives = []

    # Evaluate Malware
    for h, data in malware_dataset.items():
        res = detector.detect(data["pe"], data["asm"])
        if res["is_malware"]:
            tp += 1
        else:
            fn += 1
            false_negatives.append(
                (h, data["pe"]["file_info"]["file_name"], res["score"], res["details"], res["detected_behaviors"]))

    # Evaluate Benign
    for h, data in benign_dataset.items():
        res = detector.detect(data["pe"], data["asm"])
        if res["is_malware"]:
            fp += 1
            false_positives.append(
                (h, data["pe"]["file_info"]["file_name"], res["score"], res["details"], res["detected_behaviors"]))
        else:
            tn += 1

    # Metrics
    total = len(benign_dataset) + len(malware_dataset)
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # Build report string
    report = []
    report.append("==================================================")
    report.append("          MALWARE DETECTOR EVALUATION REPORT      ")
    report.append("==================================================")
    report.append(f"Total Evaluated Samples: {total}")
    report.append(f"  Benign Samples       : {len(benign_dataset)}")
    report.append(f"  Malware Samples      : {len(malware_dataset)}")
    report.append("--------------------------------------------------")
    report.append(f"True Positives (TP)    : {tp}")
    report.append(f"False Negatives (FN)   : {fn}")
    report.append(f"True Negatives (TN)    : {tn}")
    report.append(f"False Positives (FP)   : {fp}")
    report.append("--------------------------------------------------")
    report.append(f"Accuracy               : {accuracy:.4f}")
    report.append(f"Precision              : {precision:.4f}")
    report.append(f"Recall                 : {recall:.4f}")
    report.append(f"F1 Score               : {f1:.4f}")
    report.append("==================================================")

    if false_positives:
        report.append("\nFalse Positives Details:")
        for h, name, score, details, behaviors in false_positives:
            report.append(f"  Hash: {h} | Name: {name} | Score: {score}")
            report.append(f"    Details: {details}")
            report.append(f"    Behaviors: {behaviors}")

    if false_negatives:
        report.append("\nFalse Negatives Details:")
        for h, name, score, details, behaviors in false_negatives:
            report.append(f"  Hash: {h} | Name: {name} | Score: {score}")
            report.append(f"    Details: {details}")
            report.append(f"    Behaviors: {behaviors}")

    report_content = "\n".join(report)
    
    report_path = os.path.join(output_dir, "evaluation_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    print(f"Evaluation complete. Report written to: {report_path}")


if __name__ == "__main__":
    main()
