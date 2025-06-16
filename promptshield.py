import re
from typing import List
from dataclasses import dataclass

@dataclass
class ThreatDetectionResult:
    is_malicious: bool
    threat_type: str
    description: str
    confidence: float

class PromptShield:
    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self):
        self.keyword_patterns = [
            # Prompt Injection / Roleplay Override
            (re.compile(r'\bignore (all|any)? (prior|previous)? instructions\b', re.IGNORECASE), "Prompt Injection"),
            (re.compile(r'\byou are no longer chatgpt\b', re.IGNORECASE), "Role Override"),
            (re.compile(r'\b(DAN mode|act as DAN|simulate DAN)\b', re.IGNORECASE), "Role Simulation"),

            # Credential Theft & Keyloggers
            (re.compile(r'\b(keylogger|admin\s+password|steal\s+password|capture\s+keystrokes)\b', re.IGNORECASE), "Credential Theft"),
            (re.compile(r'\b(send\s+keystrokes\s+to\s+(email|server))\b', re.IGNORECASE), "Keylogger Exfiltration"),

            # Phishing & Social Engineering
            (re.compile(r'\bpretend to be (IT support|admin|bank|google|microsoft)\b', re.IGNORECASE), "Impersonation Attempt"),
            (re.compile(r'\b(fake login|fake link|reset password here|click here to verify)\b', re.IGNORECASE), "Phishing Link"),
            (re.compile(r'\blogin credentials|verify account|confirm password\b', re.IGNORECASE), "Phishing Content"),

            # Malware / Exploit Generation
            (re.compile(r'\b(generate|write)\s+(malware|virus|ransomware|trojan)\b', re.IGNORECASE), "Malware Instruction"),
            (re.compile(r'\b(code|script)\s+to\s+(disable antivirus|bypass firewall|exploit vulnerability)\b', re.IGNORECASE), "Exploit Instruction"),

            # Scripting Injection
            (re.compile(r'<script>.*?</script>', re.IGNORECASE), "Script Injection"),
        ]

        self.obfuscation_patterns = [
            (re.compile(r'([!@#$%^&*()_+=👦👦{};:\'",.<>/?\\|`~]){6,}'), "Character Flooding"),
            # Removed too-aggressive obfuscation rule
            # Safer alternative: looking for mix of digits + special chars
            (re.compile(r'(?=.[a-zA-Z])(?=.\d)(?=.*[^a-zA-Z\d]).{10,}'), "Complex Obfuscated String")
        ]

    def scan(self, prompt: str) -> ThreatDetectionResult:
        checks = [
            self._check_keywords,
            self._check_obfuscation,
            self._check_length,
            self._check_encoding
        ]
        for check in checks:
            result = check(prompt)
            if result.is_malicious:
                return result
        return ThreatDetectionResult(False, "Clean", "No threats detected", 0.0)

    def _check_keywords(self, prompt: str) -> ThreatDetectionResult:
        for pattern, threat_type in self.keyword_patterns:
            if pattern.search(prompt):
                return ThreatDetectionResult(True, threat_type, f"Detected '{threat_type}' in prompt.", 0.9)
        return ThreatDetectionResult(False, "", "", 0.0)

    def _check_obfuscation(self, prompt: str) -> ThreatDetectionResult:
        for pattern, threat_type in self.obfuscation_patterns:
            if pattern.search(prompt):
                return ThreatDetectionResult(True, threat_type, f"Detected obfuscation: {threat_type}.", 0.7)
        return ThreatDetectionResult(False, "", "", 0.0)

    def _check_length(self, prompt: str) -> ThreatDetectionResult:
        if len(prompt) > 1500:
            return ThreatDetectionResult(True, "Length Abuse", "Prompt too long; potential flooding", 0.6)
        return ThreatDetectionResult(False, "", "", 0.0)

    def _check_encoding(self, prompt: str) -> ThreatDetectionResult:
        try:
            prompt.encode('ascii')
        except UnicodeEncodeError:
            return ThreatDetectionResult(True, "Encoding Anomaly", "Non-ASCII characters detected", 0.8)
        return ThreatDetectionResult(False, "", "", 0.0)

def check_prompt(prompt: str):
    scanner = PromptShield()
    result = scanner.scan(prompt)
    if result.is_malicious:
        return True, f"🚨 PromptShield: {result.description} (Type: {result.threat_type}, Confidence: {result.confidence})"
    else:
        return False, "✅ PromptShield: No malicious content detected."
