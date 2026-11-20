"""Engineering specification linter and requirements traceability table verifier.

Checks mathematical and architecture specification markdown files (`*_SPEC.md`,
`*_DRAFT.md`, or configured globs) for:
1. Implementation-specific magic hex literals (`0x...`), raw memory offsets, or
   platform-specific register/pointer expressions that do not belong in an
   implementation-independent mathematical specification.
2. Hardcoded local filesystem drive paths (`C:\\...`, `D:/...`) or build artifact extensions.
3. Configurable project-specific banned substrings and whole-word tokens loaded from JSON.
4. Exact 1-to-1 bidirectional traceability between numbered specification clauses (`**Sx-nn**`)
   and rows in a companion traceability matrix (`*_TRACEABILITY.md` or `*_PROVENANCE.md`),
   plus verification status validation (`VERIFIED`, `DESIGNED`, `INFERRED`, `OPEN`).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

DEFAULT_LEVELS = ("VERIFIED", "INFERRED", "OPEN", "DESIGNED", "已验证", "推定", "未解决", "自主设计")

PATTERNS = [
    ("hex 0x", re.compile(r"0[xX][0-9A-Fa-f]")),
    ("hex run >= 6", re.compile(r"(?<![0-9A-Za-z_])[0-9A-Fa-f]{6,}(?![0-9A-Za-z_])")),
    ("address +hex", re.compile(r"\+\s*[0-9A-Fa-f]{3,}h?(?![0-9A-Za-z])")),
    ("register-relative", re.compile(r"\[\s*[re]?[a-d]x\s*[+\-]|\[\s*r(?:sp|bp|si|di|[89]|1[0-5])\s*[+\-]", re.I)),
    ("low-level layout word", re.compile(r"(?<![A-Za-z])(?:rva|offset|imagebase)(?![A-Za-z])", re.I)),
    ("drive path", re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/]")),
    ("artifact extension", re.compile(r"\.(?:py|json|jsonl|bin|dll|exe|ps1|pdb|asm|inc|dmp)(?![A-Za-z])", re.I)),
]

STMT_RE = re.compile(r"\*\*(S\d+-\d+)\*\*")
TRACE_ROW_RE = re.compile(r"^\|\s*(S\d+-\d+)\s*\|(.*)$")


def scan_text(
    text: str,
    banned_substrings: tuple[str, ...] | list[str] = (),
    banned_tokens: tuple[str, ...] | list[str] = (),
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    low = text.lower()
    for word in banned_substrings:
        idx = low.find(word.lower())
        if idx >= 0:
            snippet = text[max(0, idx - 20) : idx + len(word) + 20].replace("\n", " ")
            hits.append({"rule": "banned_substring", "what": word, "at": snippet})
    for token in banned_tokens:
        rx = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])")
        m = rx.search(text)
        if m:
            snippet = text[max(0, m.start() - 20) : m.end() + 20].replace("\n", " ")
            hits.append({"rule": "banned_token", "what": token, "at": snippet})
    for name, rx in PATTERNS:
        for m in rx.finditer(text):
            snippet = text[max(0, m.start() - 20) : m.end() + 20].replace("\n", " ")
            hits.append({"rule": name, "what": m.group(0), "at": snippet})
    return hits


def check_spec_pair(
    spec_path: Path,
    traceability_path: Path | None = None,
    banned_substrings: tuple[str, ...] | list[str] = (),
    banned_tokens: tuple[str, ...] | list[str] = (),
    allowed_levels: tuple[str, ...] = DEFAULT_LEVELS,
) -> dict[str, Any]:
    text = spec_path.read_text(encoding="utf-8")
    if traceability_path is None:
        if spec_path.name.endswith("_SPEC.md"):
            trace_candidate = spec_path.with_name(spec_path.name.replace("_SPEC.md", "_TRACEABILITY.md"))
        else:
            trace_candidate = spec_path.with_name(spec_path.name.replace("_DRAFT.md", "_TRACEABILITY.md"))
            if not trace_candidate.is_file():
                trace_candidate = spec_path.with_name(spec_path.name.replace("_DRAFT.md", "_PROVENANCE.md"))
    else:
        trace_candidate = traceability_path

    ids = STMT_RE.findall(text)
    row: dict[str, Any] = {
        "spec": spec_path.name,
        "statements": len(ids),
        "hits": scan_text(text, banned_substrings, banned_tokens),
        "problems": [],
    }
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        row["problems"].append(f"duplicate statement ids in spec: {dup}")
    if not trace_candidate.is_file():
        row["problems"].append("traceability file missing")
    else:
        rows = [
            (m.group(1), m.group(2))
            for line in trace_candidate.read_text(encoding="utf-8").splitlines()
            if (m := TRACE_ROW_RE.match(line))
        ]
        pids = [r[0] for r in rows]
        if sorted(set(ids)) != sorted(pids) or len(pids) != len(set(pids)):
            only_spec = sorted(set(ids) - set(pids))
            only_trace = sorted(set(pids) - set(ids))
            dup_trace = sorted({p for p in pids if pids.count(p) > 1})
            row["problems"].append(
                f"statement/traceability mismatch: only in spec {only_spec}, only in traceability {only_trace}, duplicated rows {dup_trace}"
            )
        levels: dict[str, int] = {}
        for sid, rest in rows:
            cells = [c.strip() for c in rest.split("|")]
            lv = next((l for l in allowed_levels if cells and cells[0].startswith(l)), None)
            if lv is None:
                row["problems"].append(f"{sid}: verification level not one of {allowed_levels}")
            else:
                levels[lv] = levels.get(lv, 0) + 1
        row["levels"] = levels
    row["status"] = "FAIL" if (row["hits"] or row["problems"]) else "PASS"
    return row


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", type=Path, help="Directory containing *_SPEC.md / *_DRAFT.md and traceability tables")
    p.add_argument("--policy", type=Path, help="Optional JSON policy with banned_substrings and banned_tokens")
    p.add_argument("--report", type=Path, help="Optional output JSON report")
    args = p.parse_args(argv)

    substrings: list[str] = []
    tokens: list[str] = []
    if args.policy:
        pol = json.loads(args.policy.read_text(encoding="utf-8"))
        substrings = pol.get("banned_substrings", [])
        tokens = pol.get("banned_tokens", [])

    specs = sorted(list(args.directory.glob("*_SPEC.md")) + list(args.directory.glob("*_DRAFT.md")))
    out: dict[str, Any] = {"schema": "sim_verify-spec-lint-v1", "specs": [], "status": "PASS"}
    if not specs:
        out["status"] = "FAIL"
        out["reason"] = "no specs found"
    for d in specs:
        res = check_spec_pair(d, banned_substrings=substrings, banned_tokens=tokens)
        if res["status"] != "PASS":
            out["status"] = "FAIL"
        out["specs"].append(res)

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": out["status"], "spec_count": len(specs)}))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
