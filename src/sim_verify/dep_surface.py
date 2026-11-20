"""Multi-mask bit-flip and Delta-Debugging (ddmin) dependency surface certifier.

Pure-stdlib implementation (no NumPy dependency):
1. `xor_patch_bytes`: XOR-perturbs fixed-width words at arbitrary byte offsets.
2. `classify_perturbation`: runs a target function on perturbed state and classifies
   the outcome across all output frames as ``'unread'``, ``'overwritten'``,
   ``'mixed'``, ``'dependency'``, or ``'rejected'`` (checking both out-of-mask
   mutations and stayed-flipped vs returned-to-baseline invariants inside the mask).
3. `collective_split`: binary-splitting group flip isolation for single dependencies.
4. `ddmin_shrink`: complement-based Delta-Debugging isolating minimal joint
   dependency sets (templates that pass individually but fail together).
5. `settle_dependency_surface`: fixed-point loop across all masks until a full pass
   removes nothing, followed by independent final-verification flips per mask.
6. `certify_dependency_surface`: end-to-end single-process or multi-process certifier.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
import concurrent.futures
import hashlib
import json
from typing import Any

DEFAULT_MASKS: tuple[int, ...] = (0x41414141, 0x01010101, 0xFFFFFFFF)
BAD_CLASSIFICATIONS: frozenset[str] = frozenset({"dependency", "rejected"})

_WORKER_CTX: dict[str, Any] = {}


def _is_bad(classification: str) -> bool:
    return classification in BAD_CLASSIFICATIONS or classification.startswith("rejected")


def _json_key(key: Any) -> Any:
    if isinstance(key, tuple):
        return [_json_key(x) for x in key]
    return key


def xor_patch_bytes(
    base: bytes,
    offsets: Sequence[int],
    mask: int,
    word_size: int = 4,
) -> bytes:
    """Return a copy of ``base`` with ``mask`` XORed at each unique offset."""
    if word_size <= 0:
        raise ValueError(f"word_size must be positive, got {word_size}")
    mask_bytes = (int(mask) & ((1 << (8 * word_size)) - 1)).to_bytes(word_size, "little")
    buf = bytearray(base)
    length = len(buf)
    for off in sorted(set(offsets)):
        if off < 0 or off + word_size > length:
            raise IndexError(f"offset {off}+{word_size} out of bounds for length {length}")
        for j in range(word_size):
            buf[off + j] ^= mask_bytes[j]
    return bytes(buf)


def classify_perturbation(
    base_state: bytes,
    baseline_outputs: Sequence[bytes],
    run_fn: Callable[[bytes], Sequence[bytes]],
    offsets: Sequence[int],
    mask: int,
    word_size: int = 4,
) -> str:
    """Classify the effect of XOR-flipping ``offsets`` with ``mask`` across all outputs.

    Returns one of ``'unread'``, ``'overwritten'``, ``'mixed'``, ``'dependency'``,
    or ``'rejected'``.
    """
    patched = xor_patch_bytes(base_state, offsets, mask, word_size=word_size)
    try:
        outputs = [bytes(x) for x in run_fn(patched)]
    except Exception:
        return "rejected"

    if len(outputs) != len(baseline_outputs):
        return "dependency"

    mask_bytes = (int(mask) & ((1 << (8 * word_size)) - 1)).to_bytes(word_size, "little")
    perturbed: dict[int, int] = {}
    for off in sorted(set(offsets)):
        for j in range(word_size):
            perturbed[off + j] = mask_bytes[j]

    unread = True
    overwritten = True
    for got, want in zip(outputs, baseline_outputs):
        if len(got) != len(want):
            return "dependency"
        if got == want:
            if any(m_byte != 0 for m_byte in perturbed.values()):
                unread = False
            continue

        # Replace perturbed indices in a scratch copy with baseline bytes so
        # any difference outside the perturbed set is caught in a single C compare.
        outside_buf = bytearray(got)
        for idx, m_byte in perturbed.items():
            b_got = got[idx]
            b_want = want[idx]
            stayed = b_got == (b_want ^ m_byte)
            same = b_got == b_want
            if not (stayed or same):
                return "dependency"
            unread &= stayed
            overwritten &= same
            outside_buf[idx] = b_want

        if bytes(outside_buf) != want:
            return "dependency"

    if unread:
        return "unread"
    if overwritten:
        return "overwritten"
    return "mixed"


def _init_worker(
    base_state: bytes,
    baseline_outputs: Sequence[bytes],
    run_fn: Callable[[bytes], Sequence[bytes]],
    word_size: int,
) -> None:
    _WORKER_CTX.clear()
    _WORKER_CTX.update(
        base_state=base_state,
        baseline_outputs=tuple(baseline_outputs),
        run_fn=run_fn,
        word_size=word_size,
    )


def _worker_classify(task: tuple[Sequence[int], int]) -> str:
    offsets, mask = task
    return classify_perturbation(
        _WORKER_CTX["base_state"],
        _WORKER_CTX["baseline_outputs"],
        _WORKER_CTX["run_fn"],
        offsets,
        mask,
        word_size=_WORKER_CTX["word_size"],
    )


def collective_split(
    items: Sequence[tuple[Any, Sequence[int]]],
    mask: int,
    test_fn: Callable[[Sequence[int], int], str],
    bad_out: dict[Any, dict[str, Any]],
    *,
    _batch_fn: Callable[[Sequence[tuple[Sequence[int], int]]], Sequence[str]] | None = None,
) -> list[dict[str, Any]]:
    """Binary-splitting group flip isolation; returns newly isolated single dependencies."""
    groups: list[list[tuple[Any, Sequence[int]]]] = [list(items)] if items else []
    isolated: list[dict[str, Any]] = []
    while groups:
        if _batch_fn is not None:
            tasks = [([off for _, offs in g for off in offs], mask) for g in groups]
            results = list(_batch_fn(tasks))
        else:
            results = [test_fn([off for _, offs in g for off in offs], mask) for g in groups]

        next_groups: list[list[tuple[Any, Sequence[int]]]] = []
        for g, res in zip(groups, results):
            if not _is_bad(res):
                continue
            if len(g) == 1:
                key = g[0][0]
                info = {"result": res, "mask": hex(mask)}
                bad_out[key] = info
                isolated.append({"template": _json_key(key), "result": res, "mask": hex(mask)})
            else:
                mid = len(g) // 2
                next_groups.append(g[:mid])
                next_groups.append(g[mid:])
        groups = next_groups
    return isolated


def ddmin_shrink(
    group: Sequence[tuple[Any, Sequence[int]]],
    mask: int,
    test_fn: Callable[[Sequence[int], int], str],
    *,
    _batch_fn: Callable[[Sequence[tuple[Sequence[int], int]]], Sequence[str]] | None = None,
) -> list[tuple[Any, Sequence[int]]]:
    """Complement-based Delta-Debugging isolating a minimal joint failing set."""
    cur = list(group)
    n = 2
    while len(cur) >= 2:
        size = len(cur) / n
        chunks = [cur[round(i * size):round((i + 1) * size)] for i in range(n)]
        rests = [[x for j, ch in enumerate(chunks) if j != i for x in ch] for i in range(n)]
        non_empty = [r for r in rests if r]
        if _batch_fn is not None:
            tasks = [([off for _, offs in r for off in offs], mask) for r in non_empty]
            results = list(_batch_fn(tasks))
        else:
            results = [test_fn([off for _, offs in r for off in offs], mask) for r in non_empty]

        hit = next((r for r, res in zip(non_empty, results) if _is_bad(res)), None)
        if hit is not None:
            cur = hit
            n = max(n - 1, 2)
        elif n >= len(cur):
            return cur
        else:
            n = min(2 * n, len(cur))
    return cur


def settle_dependency_surface(
    items: Sequence[tuple[Any, Sequence[int]]],
    masks: Sequence[int],
    test_fn: Callable[[Sequence[int], int], str],
    *,
    _batch_fn: Callable[[Sequence[tuple[Sequence[int], int]]], Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Fixed-point loop across all masks until a full pass finds no new single or joint dependencies."""
    item_list = list(items)
    mask_list = list(masks)
    bad: dict[Any, dict[str, Any]] = {}
    single_deps: list[dict[str, Any]] = []
    joint_deps: list[dict[str, Any]] = []

    while True:
        before = len(bad)
        for mask in mask_list:
            rest = [item for item in item_list if item[0] not in bad]
            if not rest:
                continue
            single_deps.extend(collective_split(rest, mask, test_fn, bad, _batch_fn=_batch_fn))
            rest = [item for item in item_list if item[0] not in bad]
            if not rest:
                continue
            all_offs = [off for _, offs in rest for off in offs]
            res = test_fn(all_offs, mask)
            if _is_bad(res):
                group = ddmin_shrink(rest, mask, test_fn, _batch_fn=_batch_fn)
                joint_res = test_fn([off for _, offs in group for off in offs], mask)
                joint_deps.append(
                    {
                        "mask": hex(mask),
                        "result": joint_res,
                        "members": [_json_key(k) for k, _ in group],
                    }
                )
                for k, _ in group:
                    bad[k] = {"result": f"joint_{joint_res}", "mask": hex(mask)}
        if len(bad) == before:
            break

    final_quiet = [k for k, _ in item_list if k not in bad]
    quiet_offs = [off for k, offs in item_list if k not in bad for off in offs]
    if final_quiet:
        if _batch_fn is not None:
            flip_res = list(_batch_fn([(quiet_offs, m) for m in mask_list]))
            final_flips = {hex(m): r for m, r in zip(mask_list, flip_res)}
        else:
            final_flips = {hex(m): test_fn(quiet_offs, m) for m in mask_list}
        remainder_clean = len(final_flips) == len(mask_list) and not any(_is_bad(v) for v in final_flips.values())
    else:
        final_flips = {}
        remainder_clean = True

    return {
        "bad": bad,
        "single_dependencies": single_deps,
        "joint_dependencies": joint_deps,
        "final_quiet_templates": [_json_key(k) for k in final_quiet],
        "final_flip_results": final_flips,
        "remainder_clean_under_all_masks": remainder_clean,
    }


def certify_dependency_surface(
    base_state: bytes,
    templates: Mapping[Any, Sequence[int]] | Sequence[tuple[Any, Sequence[int]]],
    run_fn: Callable[[bytes], Sequence[bytes]],
    masks: Sequence[int] = DEFAULT_MASKS,
    word_size: int = 4,
    workers: int = 1,
) -> dict[str, Any]:
    """Certify the full dependency surface of ``run_fn`` over ``templates`` and ``masks``."""
    if not masks:
        raise ValueError("masks must be non-empty")
    items: list[tuple[Any, list[int]]] = (
        [(k, list(v)) for k, v in templates.items()]
        if isinstance(templates, Mapping)
        else [(k, list(v)) for k, v in templates]
    )
    baseline_outputs = [bytes(x) for x in run_fn(base_state)]

    def local_test(offs: Sequence[int], mask: int) -> str:
        return classify_perturbation(base_state, baseline_outputs, run_fn, offs, mask, word_size=word_size)

    if workers > 1 and len(items) > 1:
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=workers,
            initializer=_init_worker,
            initargs=(base_state, baseline_outputs, run_fn, word_size),
        ) as pool:
            def batch_test(tasks: Sequence[tuple[Sequence[int], int]]) -> list[str]:
                return list(pool.map(_worker_classify, tasks, chunksize=1))

            triage_res = list(pool.map(_worker_classify, [(offs, masks[0]) for _, offs in items], chunksize=8))
            triage = {k: r for (k, _), r in zip(items, triage_res)}
            triage_singles = [
                {"template": _json_key(k), "result": r, "mask": hex(masks[0])}
                for k, r in triage.items()
                if _is_bad(r)
            ]
            quiet_items = [(k, offs) for k, offs in items if not _is_bad(triage[k])]
            settled = settle_dependency_surface(quiet_items, masks, local_test, _batch_fn=batch_test)
    else:
        triage = {k: local_test(offs, masks[0]) for k, offs in items}
        triage_singles = [
            {"template": _json_key(k), "result": r, "mask": hex(masks[0])}
            for k, r in triage.items()
            if _is_bad(r)
        ]
        quiet_items = [(k, offs) for k, offs in items if not _is_bad(triage[k])]
        settled = settle_dependency_surface(quiet_items, masks, local_test)

    all_singles = triage_singles + settled["single_dependencies"]
    final_class: dict[Any, str] = {}
    for k, _ in items:
        if k in settled["bad"]:
            final_class[_json_key(k) if not isinstance(k, str) else k] = settled["bad"][k]["result"]
        else:
            final_class[_json_key(k) if not isinstance(k, str) else k] = triage[k]

    quiet_list = settled["final_quiet_templates"]
    quiet_sha = hashlib.sha256(
        json.dumps(quiet_list, separators=(",", ":")).encode("utf-8")
    ).hexdigest().upper()

    return {
        "schema": "sim_verify-dep-surface-v1",
        "status": "PASS" if settled["remainder_clean_under_all_masks"] else "FAIL",
        "templates_total": len(items),
        "masks": [hex(m) for m in masks],
        "word_size": word_size,
        "triage_counts": dict(Counter(triage.values())),
        "single_dependencies": all_singles,
        "joint_dependencies": settled["joint_dependencies"],
        "final_quiet_templates": quiet_list,
        "final_quiet_count": len(quiet_list),
        "final_quiet_sha256": quiet_sha,
        "final_flip_results": settled["final_flip_results"],
        "remainder_clean_under_all_masks": settled["remainder_clean_under_all_masks"],
        "final_counts": dict(Counter(final_class.values())),
    }
