"""
Threat Actor Entity Redaction and Sanitization Module for NexusCTI Benchmark.

Removes explicit threat actor names, public aliases, sponsoring military units,
and state intelligence agencies from source threat intelligence passages.
Ensures that retrieval systems evaluate behavioral TTPs and telemetry rather
than trivial entity string matching.
"""

import re
from typing import List, Tuple

# Comprehensive case-insensitive regex patterns for known threat actors and public aliases
REDACTION_RULES: List[Tuple[str, str]] = [
    # APT28 / Fancy Bear / Strontium / Forest Blizzard
    (
        r"\b(apt-?28|fancy\s*bear|strontium|sednit|pawn\s*storm|forest\s*blizzard|sofacy|iron\s*twilight|snakemackerel)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(gru\s*unit\s*26165|unit\s*26165|85th\s*main\s*special\s*service\s*center|gtsss)\b",
        "[REDACTED_AFFILIATION]",
    ),
    # APT29 / Cozy Bear / Nobelium / Midnight Blizzard
    (
        r"\b(apt-?29|cozy\s*bear|nobelium|midnight\s*blizzard|the\s*dukes|cozyduke|dark\s*halo|stellarparticle|iron\s*hemlock|unc2452)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(foreign\s*intelligence\s*service|svr(?:\s*rf)?)\b",
        "[REDACTED_AFFILIATION]",
    ),
    # Lazarus / Hidden Cobra / Diamond Sleet
    (
        r"\b(lazarus(?:\s*group)?|hidden\s*cobra|guardians\s*of\s*peace|gop|zinc|diamond\s*sleet|applejeus|bluenoroff|blue\s*noroff|andariel|labyrinth\s*chollima)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(reconnaissance\s*general\s*bureau|rgb\s*(?:110|unit\s*110)|lab\s*110)\b",
        "[REDACTED_AFFILIATION]",
    ),
    # Sandworm / Voodoo Bear / Seashell Blizzard
    (
        r"\b(sandworm(?:\s*team)?|voodoo\s*bear|telebots|blackenergy|electrum|seashell\s*blizzard|iron\s*viking|quringinia)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(gru\s*unit\s*74455|unit\s*74455|main\s*centre\s*for\s*special\s*technologies|gtsst)\b",
        "[REDACTED_AFFILIATION]",
    ),
    # Volt Typhoon / Vanguard Panda
    (
        r"\b(volt\s*typhoon|vanguard\s*panda|bronze\s*silhouette|dev-0391|insidious\s*taurus)\b",
        "[REDACTED_ACTOR]",
    ),
    # FIN7 / Carbanak / Sangria Tempest
    (
        r"\b(fin-?7|carbanak(?:\s*group)?|sangria\s*tempest|elbrus|navigator\s*group)\b",
        "[REDACTED_ACTOR]",
    ),
    # Novel / Open-Set Actors (Task B)
    (
        r"\b(charming\s*kitten|apt-?35|mint\s*sandstorm|ta453)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(muddywater|earth\s*vetala|mercury|static\s*kitten)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(oilrig|apt-?34|helix\s*kitten|chrysene)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(kimsuky|thallium|velvet\s*chollima|black\s*banshee)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(storm-?0558)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(scattered\s*spider|unc3944|octo\s*tempest|starfraud)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(lockbit(?:\s*black|\s*3\.0|\s*2\.0)?)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(blackcat|alphv)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(cl0p|clop|ta505|lace\s*tempest)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(darkside|blackmatter)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(turla|waterbug|venomous\s*bear|iron\s*hunter|krypton)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(apt-?41|wicked\s*panda|barium|brass\s*typhoon)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(apt-?10|stone\s*panda|red\s*apollo|menu\s*pass)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(gamaredon|primitive\s*bear|shuckworm|armageddon)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(winnti(?:\s*group)?|blackfly)\b",
        "[REDACTED_ACTOR]",
    ),
    (
        r"\b(lapsus\$|lapsus)\b",
        "[REDACTED_ACTOR]",
    ),
]

_COMPILED_RULES = [(re.compile(pat, re.IGNORECASE), rep) for pat, rep in REDACTION_RULES]


def redact_actor_entities(text: str) -> str:
    """
    Substitutes all explicit threat actor entities, aliases, and affiliations
    with sanitized tokens [REDACTED_ACTOR] or [REDACTED_AFFILIATION].
    """
    if not text:
        return ""
    sanitized = text
    for rx, rep in _COMPILED_RULES:
        sanitized = rx.sub(rep, sanitized)
    # Collapse redundant redaction tokens
    sanitized = re.sub(r"(\[REDACTED_ACTOR\]\s*[\(\/,]?\s*)+\[REDACTED_ACTOR\]", "[REDACTED_ACTOR]", sanitized)
    return sanitized
