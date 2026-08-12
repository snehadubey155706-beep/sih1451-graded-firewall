import re
import json
import time
import os

REGISTRY_PATH = "data/honeytoken_registry.json"
INCIDENT_LOG_PATH = "data/incidents.json"

# --- Pattern-based sensitive data detection ---
CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
API_KEY_PATTERN = re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")


def luhn_valid(card_number):
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13:
        return False
    odd = digits[-1::-2]
    even = digits[-2::-2]
    checksum = sum(odd)
    for d in even:
        checksum += sum(divmod(d * 2, 10))
    return checksum % 10 == 0


def load_registry():
    if not os.path.exists(REGISTRY_PATH):
        raise FileNotFoundError("Run honeytoken_generator.py first to create the registry.")
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def scan_payload(payload_text, registry):
    """
    Scans a piece of outbound data (e.g. a file being uploaded/sent)
    and returns a list of matches found: honeytoken hits and
    generic sensitive-pattern hits.
    """
    matches = []

    # 1. Exact honeytoken matches (highest confidence — zero false positive by design)
    for card in registry["card_numbers"]:
        if card in payload_text:
            matches.append({"type": "HONEYTOKEN_CARD", "value_redacted": card[:4] + "****" + card[-4:]})

    for email in registry["emails"]:
        if email in payload_text:
            matches.append({"type": "HONEYTOKEN_EMAIL", "value_redacted": email.split("@")[0][:3] + "***@" + email.split("@")[1]})

    for key in registry["api_keys"]:
        if key in payload_text:
            matches.append({"type": "HONEYTOKEN_API_KEY", "value_redacted": key[:10] + "..." })

    # 2. Generic sensitive-pattern matches (real card-shaped numbers, real emails, real API keys)
    for card_candidate in CARD_PATTERN.findall(payload_text):
        cleaned = re.sub(r"[ -]", "", card_candidate)
        if luhn_valid(cleaned) and cleaned not in registry["card_numbers"]:
            matches.append({"type": "SENSITIVE_CARD_PATTERN", "value_redacted": cleaned[:4] + "****" + cleaned[-4:]})

    for email_candidate in EMAIL_PATTERN.findall(payload_text):
        if email_candidate not in registry["emails"]:
            matches.append({"type": "SENSITIVE_EMAIL_PATTERN", "value_redacted": email_candidate.split("@")[0][:3] + "***"})

    return matches


def block_transfer_and_log(session_id, source_ip, matches, sus_score=None):
    """
    'Vanish the jewels, keep him inside' — this simulates dropping
    ONLY the matched sensitive content from the outbound payload,
    while leaving the session alive, and writes a full incident case.
    """
    incident = {
        "session_id": session_id,
        "source_ip": source_ip,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "sus_score": sus_score,
        "matches": matches,
        "action": "TRANSFER_BLOCKED_SESSION_KEPT_ALIVE",
    }

    incidents = []
    if os.path.exists(INCIDENT_LOG_PATH):
        with open(INCIDENT_LOG_PATH) as f:
            incidents = json.load(f)
    incidents.append(incident)
    with open(INCIDENT_LOG_PATH, "w") as f:
        json.dump(incidents, f, indent=2)

    print(f"[BLOCKED] session={session_id} source={source_ip} — {len(matches)} sensitive item(s) caught")
    for m in matches:
        print(f"    - {m['type']}: {m['value_redacted']}")
    print(f"    Session kept alive. Incident logged to {INCIDENT_LOG_PATH}")
    return incident


if __name__ == "__main__":
    registry = load_registry()

    # --- Simulated test: an "attacker" trying to exfiltrate data ---
    fake_outbound_payload = f"""
    Uploading extracted data...
    contact: someone@randommail.com
    card: {registry['card_numbers'][0]}
    notes: nothing else here
    """

    print("--- Scanning simulated outbound payload ---")
    matches = scan_payload(fake_outbound_payload, registry)

    if matches:
        block_transfer_and_log(
            session_id="TEST-SESSION-001",
            source_ip="203.0.113.9",
            matches=matches,
            sus_score=87.0,
        )
    else:
        print("No sensitive data detected — transfer allowed.")