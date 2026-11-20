"""Streaming SHA-256 file identities, frozen contracts, and independent review gate."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ALLOWED_VERDICTS = ("ACCEPTED", "ACCEPTED_WITH_CAVEATS")


def identity(path: Path) -> dict[str, Any]:
    target = Path(path).resolve()
    digest = hashlib.sha256()
    with target.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "path": target.name,
        "size_bytes": target.stat().st_size,
        "sha256": digest.hexdigest().upper(),
    }


def write_json(path: Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def freeze_contract(
    files: list[Path],
    base_dir: Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = Path(base_dir).resolve() if base_dir else None
    entries = []
    overall = hashlib.sha256()
    for item in sorted(Path(f).resolve() for f in files):
        info = identity(item)
        rel = item.relative_to(root).as_posix() if root and item.is_relative_to(root) else item.name
        row = {"relative_path": rel, "size_bytes": info["size_bytes"], "sha256": info["sha256"]}
        entries.append(row)
        overall.update(f"{rel}:{info['size_bytes']}:{info['sha256']}\n".encode("utf-8"))
    return {
        "schema": "sim_verify-frozen-contract-v1",
        "contract_sha256": overall.hexdigest().upper(),
        "file_count": len(entries),
        "files": entries,
        "metadata": metadata or {},
    }


def verify_contract(
    contract: dict[str, Any],
    base_dir: Path,
    require_review: Path | None = None,
) -> dict[str, Any]:
    root = Path(base_dir).resolve()
    if not isinstance(contract, dict) or contract.get("schema") != "sim_verify-frozen-contract-v1":
        return {"status": "REFUSED", "reason": "invalid contract schema", "mismatches": []}
    mismatches = []
    overall = hashlib.sha256()
    for entry in contract.get("files", []):
        rel = entry["relative_path"]
        target = root / rel
        overall.update(f"{rel}:{entry['size_bytes']}:{entry['sha256']}\n".encode("utf-8"))
        if not target.is_file():
            mismatches.append({"relative_path": rel, "error": "missing"})
            continue
        actual = identity(target)
        if actual["size_bytes"] != entry["size_bytes"] or actual["sha256"] != entry["sha256"]:
            mismatches.append({
                "relative_path": rel,
                "error": "hash_or_size_mismatch",
                "expected_sha256": entry["sha256"],
                "actual_sha256": actual["sha256"],
            })
    expected_digest = contract.get("contract_sha256")
    computed_digest = overall.hexdigest().upper()
    if expected_digest != computed_digest:
        mismatches.append({
            "relative_path": "<contract>",
            "error": "contract_digest_mismatch",
            "expected_sha256": expected_digest,
            "actual_sha256": computed_digest,
        })
    if mismatches:
        return {"status": "REFUSED", "reason": "contract verification failed", "mismatches": mismatches}

    if require_review is not None:
        review_path = Path(require_review)
        if not review_path.is_file():
            return {"status": "REFUSED", "reason": "review record missing", "mismatches": []}
        try:
            review = json.loads(review_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"status": "REFUSED", "reason": f"malformed review json: {exc}", "mismatches": []}
        if not isinstance(review, dict):
            return {"status": "REFUSED", "reason": "review json is not an object", "mismatches": []}
        if review.get("contract_sha256") != expected_digest:
            return {"status": "REFUSED", "reason": "review contract_sha256 mismatch", "mismatches": []}
        if review.get("verdict") not in ALLOWED_VERDICTS:
            return {"status": "REFUSED", "reason": f"review verdict refused: {review.get('verdict')}", "mismatches": []}
        if review.get("must_fix"):
            return {"status": "REFUSED", "reason": "review has unresolved must_fix items", "mismatches": []}
        if review.get("author") and review.get("reviewer") and review.get("author") == review.get("reviewer"):
            return {"status": "REFUSED", "reason": "self-review is forbidden", "mismatches": []}

    return {
        "status": "PASS",
        "contract_sha256": expected_digest,
        "verified_files": len(contract.get("files", [])),
        "mismatches": [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_freeze = sub.add_parser("freeze", help="Freeze file SHA-256 contract")
    p_freeze.add_argument("--base-dir", type=Path, required=True)
    p_freeze.add_argument("--out", type=Path, required=True)
    p_freeze.add_argument("files", nargs="+", type=Path)

    p_verify = sub.add_parser("verify", help="Verify frozen contract and optional review gate")
    p_verify.add_argument("--base-dir", type=Path, required=True)
    p_verify.add_argument("--contract", type=Path, required=True)
    p_verify.add_argument("--require-review", type=Path)

    args = parser.parse_args(argv)
    if args.cmd == "freeze":
        contract = freeze_contract(args.files, args.base_dir)
        write_json(args.out, contract)
        print(json.dumps({"status": "FROZEN", "contract_sha256": contract["contract_sha256"], "files": contract["file_count"]}))
        return 0

    contract_data = json.loads(args.contract.read_text(encoding="utf-8"))
    res = verify_contract(contract_data, args.base_dir, args.require_review)
    print(json.dumps(res, ensure_ascii=False))
    return 0 if res["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
