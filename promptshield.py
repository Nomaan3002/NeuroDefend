import re
from typing import Tuple, List
from dataclasses import dataclass

@dataclass
class ThreatDetectionResult:
    is_malicious: bool
    threat_type: str
    description: str
    confidence: float  # 0.0 to 1.0

class PromptShield:
    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for efficiency"""
        # Keyword-based injection patterns
        self.keyword_patterns = [
            (re.compile(r'\bignore previous instructions\b', re.IGNORECASE), "Direct Injection"),
            (re.compile(r'\b(jailbreak|override|system prompt)\b', re.IGNORECASE), "Jailbreak Attempt"),
            (re.compile(r'\b(forget|disregard) (all )?(prior|previous) (instructions|rules)\b', re.IGNORECASE), "Context Wiping")
        ]

        # Obfuscation patterns
        self.obfuscation_patterns = [
            (re.compile(r'([!@#$%^&*()_+=\[\]{};\':"\\|,.<>\/?]){5,}'), "Character Flooding"),
            (re.compile(r'\b(?:[a-z]{2,}\d{3,}|\d{3,}[a-z]{2,})\b'), "Alphanumeric Obfuscation")
        ]

    def scan(self, prompt: str) -> ThreatDetectionResult:
        """Main scanning method with layered checks"""
        checks = [
            self._check_keywords,
            self._check_obfuscation,
            self._check_length,
            self._check_encoding_anomalies
        ]

        for check in checks:
            result = check(prompt)
            if result.is_malicious:
                return result

        return ThreatDetectionResult(False, "Clean", "No threats detected", 0.0)

    def _check_keywords(self, prompt: str) -> ThreatDetectionResult:
        """Check for known malicious phrases"""
        for pattern, threat_type in self.keyword_patterns:
            if pattern.search(prompt):
                return ThreatDetectionResult(
                    True,
                    threat_type,
                    f"Detected '{threat_type}' pattern: '{pattern.pattern}'",
                    confidence=0.9
                )
        return ThreatDetectionResult(False, "", "", 0.0)

    def _check_obfuscation(self, prompt: str) -> ThreatDetectionResult:
        """Detect obfuscation techniques"""
        for pattern, threat_type in self.obfuscation_patterns:
            if pattern.search(prompt):
                return ThreatDetectionResult(
                    True,
                    "Obfuscation",
                    f"Detected {threat_type}: '{pattern.pattern}'",
                    confidence=0.7
                )
        return ThreatDetectionResult(False, "", "", 0.0)

    def _check_length(self, prompt: str) -> ThreatDetectionResult:
        """Heuristic for prompt length"""
        if len(prompt) > 1500:  # Adjust based on your use case
            return ThreatDetectionResult(
                True,
                "Length Abuse",
                f"Prompt too long ({len(prompt)} chars). Possible flooding attempt.",
                confidence=0.6
            )
        return ThreatDetectionResult(False, "", "", 0.0)

    def _check_encoding_anomalies(self, prompt: str) -> ThreatDetectionResult:
        """Detect unusual encoding/Unicode tricks"""
        if prompt.encode('ascii', 'ignore').decode() != prompt:
            return ThreatDetectionResult(
                True,
                "Encoding Anomaly",
                "Non-ASCII characters detected (possible homoglyph attack)",
                confidence=0.8
            )
        return ThreatDetectionResult(False, "", "", 0.0)
    # Wrapper function for external use
def check_prompt(prompt):
    scanner = PromptShield()
    result = scanner.scan(prompt)
    
    if result.is_malicious:
        return True, f"🚨 PromptShield: {result.description} (Confidence: {result.confidence})"
    else:
        return False, "✅ PromptShield: No malicious content detected."
