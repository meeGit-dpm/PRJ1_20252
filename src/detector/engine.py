import os
import math
try:
    from . import rules
except ImportError:
    import rules


class BehaviorFSM:
    def __init__(self):
        self.state = "CLEAN"

    def transition(self, event):
        if self.state == "CLEAN":
            if event == "EVASION":
                self.state = "EVASIVE"
            elif event == "INJECTION":
                self.state = "INJECTING"
            elif event == "ENUMERATION":
                self.state = "SURVEY"

        elif self.state == "EVASIVE":
            if event == "ENUMERATION":
                self.state = "SURVEY"
            elif event == "INJECTION":
                self.state = "INJECTING"

        elif self.state == "SURVEY":
            if event == "INJECTION":
                self.state = "INJECTING"
                
        elif self.state == "INJECTING":
            if event == "NETWORK":
                self.state = "MALICIOUS"

    def get_score(self):
        scores = {
            "CLEAN": 0,
            "EVASIVE": 0,
            "SURVEY": 5,
            "INJECTING": 15,
            "MALICIOUS": 35
        }
        return scores.get(self.state, 0)


class DecryptionLoopFSM:
    def __init__(self):
        self.state = "START"

    def feed(self, ngram):
        # ngram: tuple/list of 3 opcodes, e.g. ("xor", "inc", "jnz")
        if len(ngram) < 3:
            return
        op1, op2, op3 = ngram[0], ngram[1], ngram[2]
        
        if self.state == "START":
            if op1 in ["xor", "rol", "ror"]:
                self.state = "XOR_FOUND"
        elif self.state == "XOR_FOUND":
            if op2 in ["cmp", "test", "dec", "inc", "add", "sub"]:
                self.state = "LOOP_FOUND"
            else:
                self.state = "START"
        elif self.state == "LOOP_FOUND":
            if op3 in ["jnz", "jne", "loop", "jmp", "jg", "jl"]:
                self.state = "DECRYPTOR"
            else:
                self.state = "START"

    def is_decryptor(self):
        return self.state == "DECRYPTOR"


class MalwareDetector:
    def __init__(self, threshold=50):
        self.threshold = threshold

    def clean_suspicious_strings(self, raw_strings):
        cleaned = []
        for s in raw_strings:
            sl = s.lower()
            if sl.startswith((".", "/")) and "$" in sl:
                continue
            if sl in ["http://", "https://"]:
                continue
            if "http" in sl:
                should_ignore = False
                for kw in rules.CLEAN_STRING_EXCLUSIONS:
                    if kw in sl:
                        should_ignore = True
                        break
                if should_ignore:
                    continue
            cleaned.append(s)
        return cleaned

    def calculate_score(self, pe_features, asm_features):
        score = 0
        details = []

        is_source = pe_features.get("is_source_code", False)

        sections = pe_features.get("sections", [])
        has_execute_section = any("EXECUTE" in sec.get("characteristics", []) for sec in sections)

        if not is_source and not has_execute_section:
            return 0, ["No executable sections found (data or resource file)"], []

        # Extract imports early
        imports = pe_features.get("imports", {})
        dll_count = len(imports)
        func_count = sum(len(funcs) for funcs in imports.values())

        # .NET Check (improved to recognize DLLs via _CorDllMain)
        has_dotnet = False
        for dll, funcs in imports.items():
            func_names = [f.lower() for f in funcs]
            if "_corexemain" in func_names or "_cordllmain" in func_names:
                has_dotnet = True
                break

        # Instantiate FSMs
        behavior_fsm = BehaviorFSM()
        decryptor_fsm = DecryptionLoopFSM()

        # Feed Opcode ngrams to Decryptor FSM (skip for .NET binaries)
        if not has_dotnet:
            ngrams = asm_features.get("opcode_ngrams", [])
            for ngram in ngrams:
                decryptor_fsm.feed(ngram)
                if decryptor_fsm.is_decryptor():
                    break

        if decryptor_fsm.is_decryptor():
            score += 25
            details.append("Decryption loop FSM triggered (potential self-decryption loop)")

        opcode_count = asm_features.get("opcode_count", 0)
        if not is_source and opcode_count == 0:
            score += 35
            details.append("No standard '.text' code section found (renamed/packed)")

        is_dll = pe_features.get("file_info", {}).get("file_name", "").lower().endswith((".dll", ".sys"))

        # Section Heuristics
        max_entropy = 0
        has_wx = False
        has_mismatch = False
        has_susp_sec = False
        has_slash_sec = False
        rsrc_size = 0

        for sec in sections:
            ent = sec.get("entropy", 0)
            if ent > max_entropy:
                max_entropy = ent

            chars = sec.get("characteristics", [])
            if "WRITE" in chars and "EXECUTE" in chars:
                has_wx = True
            
            vsize = sec.get("virtual_size", 0)
            rsize = sec.get("raw_size", 0)
            if vsize > 100000 and rsize == 0:
                has_mismatch = True
            
            sec_name = sec.get("name", "").strip()
            sec_name_lower = sec_name.lower()
            if sec_name_lower in [".upx0", ".upx1", ".upx2", ".pack", ".aspack", ".ptext"]:
                has_susp_sec = True
            if sec_name.startswith('/'):
                has_slash_sec = True
            if ".rsrc" in sec_name_lower:
                rsrc_size = vsize

        if not is_source:
            if max_entropy > 7.9:
                score += 45
                details.append(f"Extremely high section entropy: {max_entropy} (encrypted/packed)")
            elif max_entropy > 7.5:
                score += 30
                details.append(f"High section entropy: {max_entropy}")
            elif max_entropy > 7.1:
                score += 15
                details.append(f"Elevated section entropy: {max_entropy}")

            if has_wx:
                score += 35
                details.append("W^X violation")
            if has_mismatch:
                score += 25
                details.append("Virtual size vs Raw size mismatch (likely packed)")
            if has_susp_sec:
                score += 35
                details.append("Suspicious section name")
            if has_slash_sec:
                score += 35
                details.append("Section name starts with '/' (obfuscated/compiler anomaly)")

        # Overlay Check
        file_size = pe_features.get("file_info", {}).get("file_size_bytes", 0)
        sum_raw_size = sum(sec.get("raw_size", 0) for sec in sections)
        
        if not is_source:
            if file_size > sum_raw_size + 3000000 and file_size > 4000000:
                score += 55
                details.append(f"Massive overlay detected (Size: {file_size}, Sections Raw Size Sum: {sum_raw_size})")
            elif file_size > sum_raw_size + 150000 and file_size > 500000:
                score += 30
                details.append(f"Significant overlay detected (Size: {file_size}, Sections Raw Size Sum: {sum_raw_size})")

            # Low opcode density check (packed binary indication) - skip for DLLs
            if not is_dll and 0 < opcode_count < 300 and file_size > 50000:
                score += 25
                details.append(f"Low opcode density: {opcode_count} opcodes for {file_size} bytes (wrapper/dropper)")

        # Imports complexity rules
        if not is_source:
            if dll_count == 0:
                # Resource/metadata only files with zero imports and low entropy should not be penalized
                if max_entropy > 6.0:
                    score += 60
                    details.append("Zero imports table (extreme anomaly, packed/shellcode)")
            elif func_count < 5:
                score += 30
                details.append(f"Extremely few imports: {func_count} functions (likely packed)")

        # API categorization
        injection_found = []
        network_found = []
        evasion_found = []
        process_enum_found = []
        
        has_setthreadcontext = False
        is_driver = False
        driver_proc_ctrl = False
        has_advanced_debug = False
        has_getprocaddress = False
        has_loadlibrary = False
        has_virtualalloc = False
        has_resource_api = False
        has_proc_create_api = False

        apims_dll_count = 0

        for dll, funcs in imports.items():
            dll_lower = dll.lower()

            if dll_lower.startswith("api-ms-win"):
                apims_dll_count += 1

            if "ntoskrnl" in dll_lower or "hal.dll" in dll_lower:
                is_driver = True
                
            for f in funcs:
                fl = f.lower()
                if fl == "setthreadcontext":
                    has_setthreadcontext = True
                if fl == "getprocaddress":
                    has_getprocaddress = True
                if fl in ["loadlibrarya", "loadlibraryw", "loadlibraryexw"]:
                    has_loadlibrary = True
                if fl in ["virtualalloc", "virtualallocw", "virtualalloca"]:
                    has_virtualalloc = True
                if fl in rules.ADVANCED_DEBUG_APIS:
                    has_advanced_debug = True
                if is_driver and fl in ["zwterminateprocess", "zwopenprocess", "zwreadvirtualmemory", "zwwritevirtualmemory", "zwprotectvirtualmemory", "ntterminateprocess"]:
                    driver_proc_ctrl = True

                if fl in ["findresourcea", "findresourcew", "findresourceex", "loadresource", "lockresource", "sizeofresource"]:
                    has_resource_api = True
                if fl in ["createprocessa", "createprocessw", "winexec", "shellexecutea", "shellexecutew", "shellexecuteexa", "shellexecuteexw"]:
                    has_proc_create_api = True

                if fl in rules.INJECTION_APIS or fl.rstrip('aw') in rules.INJECTION_APIS:
                    injection_found.append(f)
                if fl in rules.NETWORK_APIS or fl.rstrip('aw') in rules.NETWORK_APIS:
                    network_found.append(f)
                if fl in rules.EVASION_APIS or fl.rstrip('aw') in rules.EVASION_APIS:
                    evasion_found.append(f)
                if fl in rules.PROCESS_ENUM_APIS or fl.rstrip('aw') in rules.PROCESS_ENUM_APIS:
                    process_enum_found.append(f)

        # Transition Behavior FSM
        if len(evasion_found) > 0:
            behavior_fsm.transition("EVASION")
        if len(process_enum_found) > 0:
            behavior_fsm.transition("ENUMERATION")
        if len(injection_found) > 0:
            behavior_fsm.transition("INJECTION")
        if len(network_found) > 0:
            behavior_fsm.transition("NETWORK")

        fsm_score = behavior_fsm.get_score()
        if fsm_score > 0:
            score += fsm_score
            details.append(f"Behavior FSM threat state reached: {behavior_fsm.state} (+{fsm_score} points)")

        if is_driver and driver_proc_ctrl:
            score += 20
            details.append("Kernel driver with process control capabilities")

        if has_advanced_debug:
            score += 30
            details.append("Advanced anti-debugging or debugging APIs found")

        # Injection API counts
        if len(injection_found) >= 3:
            score += 45
            details.append(f"Multiple Process Injection APIs: {list(set(injection_found))}")
        elif len(injection_found) == 2:
            score += 35
            details.append(f"Process Injection APIs: {list(set(injection_found))}")
        elif len(injection_found) == 1:
            if has_virtualalloc and func_count > 50:
                if not is_dll and (len(evasion_found) >= 2 or len(process_enum_found) >= 2):
                    score += 15
                    details.append("VirtualAlloc with multiple evasion/enumeration APIs")
            else:
                score += 15
                details.append(f"Single Process Injection API: {list(set(injection_found))}")

        if has_setthreadcontext:
            score += 20
            details.append("Imports SetThreadContext (process injection signature)")

        # Network API counts
        if len(network_found) >= 2:
            score += 25
            details.append(f"Network communication APIs: {list(set(network_found))}")
        elif len(network_found) == 1:
            score += 10
            details.append(f"Single Network API: {list(set(network_found))}")

        # Process Enumeration check
        has_proc_snap = any("createtoolhelp32snapshot" in f.lower() for f in process_enum_found)
        has_proc_first = any(f.lower().startswith("process32first") for f in process_enum_found)
        has_proc_next = any(f.lower().startswith("process32next") for f in process_enum_found)
        
        if has_proc_snap and has_proc_first and has_proc_next:
            score += 45
            details.append("Full process enumeration loop (Toolhelp32 loop, highly suspicious)")
        elif len(process_enum_found) >= 2:
            score += 25
            details.append(f"Process enumeration APIs: {list(set(process_enum_found))}")
        elif len(process_enum_found) == 1:
            score += 10
            details.append(f"Single process enumeration API: {list(set(process_enum_found))}")

        # Evasion APIs
        if len(evasion_found) >= 2:
            score += 30
            details.append(f"Multiple evasion/debugging APIs: {list(set(evasion_found))}")
        elif len(evasion_found) == 1:
            score += 10
            details.append(f"Single evasion/debugging API: {list(set(evasion_found))}")

        # Dynamic Resolution pattern
        if has_getprocaddress and has_loadlibrary and has_virtualalloc:
            score += 15
            details.append("Dynamic API resolution pattern (GetProcAddress + LoadLibrary + VirtualAlloc)")

        # Opcode Metrics (skip for .NET binaries)
        add_ratio = 0
        if opcode_count > 0:
            adds = asm_features.get("top_opcodes", {}).get("add", 0)
            add_ratio = adds / opcode_count

            if not has_dotnet:
                if add_ratio > 0.40:
                    score += 20 if is_dll else 40
                    details.append(f"Extremely high ADD instruction ratio: {add_ratio:.2%}")
                elif add_ratio > 0.30:
                    score += 10 if is_dll else 25
                    details.append(f"High ADD instruction ratio: {add_ratio:.2%}")

        # Strings
        raw_susp_strs = asm_features.get("suspicious_strings", [])
        susp_strs = self.clean_suspicious_strings(raw_susp_strs)
        
        has_high_risk_string = False
        for s in susp_strs:
            sl = s.lower()
            if any(k in sl for k in rules.HIGH_RISK_STRINGS):
                has_high_risk_string = True
                break

        if has_high_risk_string:
            score += 30
            details.append("High-risk strings found (e.g. shadow copies removal or AV exclusion)")

        if len(susp_strs) > 0:
            score += min(len(susp_strs) * 10, 45)
            details.append(f"Suspicious strings count: {len(susp_strs)}")

        # Library Discounts (skip for high-entropy packed files)
        skip_discounts = max_entropy > 7.5
        if not skip_discounts:
            exports = pe_features.get("exports", [])
            if len(exports) > 50:
                score -= 35
                details.append(f"Major library discount: {len(exports)} functions exported")
            elif len(exports) > 15:
                score -= 25
                details.append(f"Library discount: {len(exports)} functions exported")
            elif len(exports) > 5:
                score -= 15
                details.append(f"Minor library discount: {len(exports)} functions exported")

        # System Complexity Discounts (skip for high-entropy packed files)
        has_severe_behavior = (
            has_high_risk_string or
            has_slash_sec or
            has_susp_sec or
            has_wx or
            has_mismatch or
            opcode_count == 0 or
            (len(evasion_found) >= 2 and has_virtualalloc)
        )

        if not has_severe_behavior and not skip_discounts:
            if dll_count > 12:
                score -= 20
                details.append(f"Complexity discount: {dll_count} DLLs imported")
            if apims_dll_count > 4:
                score -= 20
                details.append(f"Modern Windows SDK discount: {apims_dll_count} API-set DLLs imported")

        # .NET Check
        if has_dotnet:
            is_obfuscated = max_entropy > 7.0 or len(susp_strs) > 0
            if is_obfuscated:
                score += 45
                details.append("Obfuscated/Suspicious .NET executable")
            else:
                score += 35
                details.append(".NET executable")

        # Dropper behavior detection logic (Resource APIs + Process Creation APIs + Large resource section ratio)
        if has_resource_api and has_proc_create_api:
            rsrc_ratio = rsrc_size / file_size if file_size > 0 else 0
            if rsrc_ratio > 0.70:
                score += 45
                details.append(f"Dropper behavior detected (Large resource section: {rsrc_ratio:.1%})")

        # Whitelist Windows / Driver system files
        is_sys = pe_features.get("file_info", {}).get("file_name", "").lower().endswith(".sys")
        if is_sys:
            score -= 40
            details.append("Driver whitelist discount")

        # Behavior Mapping
        detected_behaviors = []

        # 1. Evasion / Packing (Integrate entropy data to flag evasion/packing)
        is_packed = False
        packing_reasons = []

        if max_entropy > 7.1:
            is_packed = True
            packing_reasons.append(f"Entropy: {max_entropy:.4f}")

        if has_mismatch:
            is_packed = True
            packing_reasons.append("Virtual/Raw size mismatch")

        if has_susp_sec:
            is_packed = True
            packing_reasons.append("Suspicious section name")

        if opcode_count == 0:
            is_packed = True
            packing_reasons.append("Missing standard code section")

        if decryptor_fsm.is_decryptor():
            is_packed = True
            packing_reasons.append("Decryption loop FSM triggered")

        if dll_count == 0 or (func_count > 0 and func_count < 5):
            is_packed = True
            packing_reasons.append(f"Low imports count: {func_count}")

        if is_packed:
            detected_behaviors.append({
                "behavior": "Evasion / Packing",
                "indicators": packing_reasons
            })

        # 2. Process Injection
        if len(injection_found) > 0 or has_setthreadcontext:
            inj_reasons = []

            if injection_found:
                inj_reasons.append(f"APIs: {list(set(injection_found))}")

            if has_setthreadcontext:
                inj_reasons.append("Imports SetThreadContext")

            detected_behaviors.append({
                "behavior": "Process Injection / Hollowing",
                "indicators": inj_reasons
            })

        # 3. Evasion / Anti-Debugging
        if len(evasion_found) > 0 or has_advanced_debug:
            dbg_reasons = []

            if evasion_found:
                dbg_reasons.append(f"APIs: {list(set(evasion_found))}")

            if has_advanced_debug:
                dbg_reasons.append("Advanced anti-debugging APIs")

            detected_behaviors.append({
                "behavior": "Evasion / Anti-Debugging",
                "indicators": dbg_reasons
            })

        # 4. Process Enumeration & Survey
        if len(process_enum_found) > 0:
            enum_reasons = [f"APIs: {list(set(process_enum_found))}"]

            if has_proc_snap and has_proc_first and has_proc_next:
                enum_reasons.append("Full process loop (Toolhelp32)")
                
            detected_behaviors.append({
                "behavior": "Process Enumeration & Survey",
                "indicators": enum_reasons
            })

        # 5. Network Backdoor / Command & Control
        ports = asm_features.get("detected_ports", [])

        if len(network_found) > 0 or len(ports) > 0:
            net_reasons = []

            if network_found:
                net_reasons.append(f"APIs: {list(set(network_found))}")

            if ports:
                net_reasons.append(f"Constants referencing common ports: {ports}")
            
            detected_behaviors.append({
                "behavior": "Network Backdoor / Command & Control",
                "indicators": net_reasons
            })

        # 6. Ransomware / System Tampering
        if has_high_risk_string or driver_proc_ctrl:
            tamper_reasons = []

            if has_high_risk_string:
                tamper_reasons.append("High-risk string referencing shadow copies removal or AV exclusion")
            
            if driver_proc_ctrl:
                tamper_reasons.append("Kernel driver process control capabilities")
            
            detected_behaviors.append({
                "behavior": "Ransomware / System Tampering",
                "indicators": tamper_reasons
            })

        return score, details, detected_behaviors

    def detect(self, pe_features, asm_features):
        score, details, behaviors = self.calculate_score(pe_features, asm_features)
        
        # Calculate malware probability
        if score <= 0:
            prob = 0.0
        elif score < self.threshold:
            prob = (score / self.threshold) * 50.0
        else:
            # score >= threshold
            # Using a smooth exponential curve approaching 100%
            prob = 50.0 + 50.0 * (1.0 - math.exp(-0.05 * (score - self.threshold)))
            
        return {
            "is_malware": score >= self.threshold,
            "score": score,
            "malware_probability": prob,
            "details": details,
            "detected_behaviors": behaviors
        }

