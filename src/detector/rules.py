# API Categorization for Heuristic Scanning
INJECTION_APIS = {
    "virtualalloc",
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "setthreadcontext",
    "resumethread"
}

NETWORK_APIS = {
    "socket",
    "connect",
    "send",
    "recv",
    "urldownloadtofile"
}

EVASION_APIS = {
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess"
}

PROCESS_ENUM_APIS = {
    "createtoolhelp32snapshot",
    "process32first",
    "process32next"
}

ADVANCED_DEBUG_APIS = {
    "ntremoveprocessdebug",
    "dbguisetthreaddebugobject",
    "waitfordebugevent",
    "continuedebugevent"
}

# Suspicious strings matching
HIGH_RISK_STRINGS = {
    "vssadmin",
    "shadows",
    "mppreference",
    "exclusionprocess",
    "shadowcopy"
}

CLEAN_STRING_EXCLUSIONS = [
    "microsoft",
    "windows",
    "w3.org",
    "adobe.com",
    "xml",
    "schema",
    "crl",
    "telemetry",
    "curl.se",
    "github.com",
    "wikipedia.org",
    "oracle.com"
]
