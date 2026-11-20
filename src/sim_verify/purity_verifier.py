"""Formal restricted-subset Python purity and statelessness static certifier (S1-S9).

Certifies that a set of entry points in a Python package cannot hold or mutate
hidden cross-call state, combining:
1. Static import-closure loading over relative intra-package imports.
2. Reachability and interprocedural persistence-level dataflow analysis (catching
   persistent receivers, mutable defaults, module-level iterators, and mutating calls).
3. Fresh-subprocess S1/S2 module-binding classification (``frozen`` / ``data`` / ``opaque``).
4. Mention-closed walked graph ``W`` and syntactic S3-S9 restrictions:
   - S3: allow-listed stdlib modules/attributes and pure builtins only.
   - S4: closure-wide read-only positions for ``data`` lookup tables and class tables.
   - S5: attribute stores restricted to ``self`` or fresh local constructors; no ``global``/``nonlocal``.
   - S6: banned introspective, dunder, frame, traceback, generator, and ``__wrapped__`` attributes.
   - S7: unbound instance method calls restricted to ``self``; class values cannot escape.
   - S8: live class base, metaclass, keyword, decorator, body, and dunder constraints.
   - S9: function decorator and frozen default-argument constraints.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence, Set as AbstractSet
from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

INF = 9
TOP = "TOP"

DEFAULT_STDLIB: dict[str, set[str] | None] = {
    "math": {
        "sqrt", "isfinite", "isnan", "isinf", "fabs", "floor", "ceil", "copysign",
        "inf", "nan", "pi", "trunc", "ldexp", "frexp", "fsum", "sin", "cos",
        "atan2", "asin", "acos", "hypot", "exp", "log", "nextafter", "ulp",
    },
    "struct": {"pack", "unpack", "unpack_from", "pack_into", "calcsize", "Struct", "iter_unpack", "error"},
    "bisect": {"bisect_left", "bisect_right", "bisect", "insort"},
    "hashlib": {"sha256", "sha1", "md5", "blake2b", "blake2s"},
    "json": {"loads", "dumps"},
    "base64": {"b64encode", "b64decode"},
    "dataclasses": {"dataclass", "field", "fields", "replace", "asdict", "astuple", "is_dataclass", "FrozenInstanceError"},
    "collections": {"Counter", "defaultdict", "OrderedDict", "namedtuple", "deque"},
    "typing": {"Sequence", "Literal", "Any", "Optional", "Union", "Iterable", "Mapping", "Tuple", "Callable"},
    "types": {"MappingProxyType", "SimpleNamespace"},
    "ctypes": {
        "c_uint8", "c_uint16", "c_uint32", "c_uint64", "c_int8", "c_int16", "c_int32", "c_int64",
        "c_int", "c_uint", "c_float", "c_double", "c_void_p", "c_char", "c_bool",
        "POINTER", "Structure", "sizeof", "byref", "create_string_buffer", "CDLL",
    },
}

PURE_BUILTINS: set[str] = {
    "len", "range", "enumerate", "zip", "map", "filter", "min", "max", "sum", "abs", "round",
    "divmod", "pow", "all", "any", "int", "float", "bool", "str", "bytes", "bytearray",
    "tuple", "list", "dict", "set", "frozenset", "sorted", "reversed", "isinstance", "issubclass",
    "type", "object", "super", "iter", "next", "repr", "format", "chr", "ord", "hex", "bin", "oct",
    "memoryview", "slice", "property", "staticmethod", "classmethod", "callable",
    "getattr", "setattr", "hasattr", "delattr",
    "ValueError", "TypeError", "KeyError", "IndexError", "OverflowError", "ZeroDivisionError",
    "AssertionError", "Exception", "ArithmeticError", "StopIteration", "RuntimeError",
    "LookupError", "AttributeError", "NotImplementedError",
}
FORBIDDEN_BUILTINS: set[str] = {
    "open", "eval", "exec", "compile", "__import__", "globals", "locals", "vars",
    "input", "print", "breakpoint", "id", "hash", "help", "exit", "quit",
}
BUILTINS_OK: set[str] = (
    PURE_BUILTINS
    - {"object", "type", "super", "getattr", "setattr", "hasattr", "delattr", "property", "staticmethod", "classmethod", "memoryview"}
    | {"NotImplemented", "Ellipsis", "True", "False", "None"}
)
SPECIAL_BUILTINS: set[str] = {
    "object", "type", "super", "getattr", "setattr", "hasattr", "delattr", "property", "staticmethod", "classmethod",
}
PURE_METHODS: set[str] = {
    "append", "extend", "insert", "pop", "remove", "index", "count", "copy", "clear", "reverse",
    "sort", "get", "items", "keys", "values", "update", "setdefault", "add", "discard", "union",
    "intersection", "difference", "issubset", "issuperset", "isdisjoint", "symmetric_difference",
    "join", "split", "strip", "startswith", "endswith", "replace", "format", "encode", "decode",
    "hex", "fromhex", "to_bytes", "from_bytes", "bit_length", "is_integer", "upper", "lower",
    "zfill", "ljust", "rjust", "hexdigest", "digest", "most_common", "elements", "total",
    "popleft", "appendleft", "tobytes", "cast", "find", "rstrip", "lstrip", "rsplit", "partition",
    "isdigit", "isalnum", "as_integer_ratio", "subtract", "fromkeys", "unpack", "pack",
    "unpack_from", "iter_unpack", "popitem", "removeprefix", "removesuffix", "splitlines",
    "__getattribute__",
}
MUTATING: set[str] = {
    "append", "extend", "insert", "pop", "remove", "clear", "update", "setdefault", "add",
    "discard", "sort", "reverse", "popitem", "popleft", "appendleft", "subtract",
    "__setitem__", "__delitem__",
}
ORDERED_CONSUMERS: set[str] = {
    "list", "tuple", "enumerate", "zip", "next", "iter", "map", "filter", "dict", "bytes", "bytearray",
}
HOOKS: set[str] = {
    "__getattr__", "__getattribute__", "__setattr__", "__delattr__",
    "__get__", "__set__", "__delete__", "__set_name__", "__init_subclass__", "__class_getitem__",
}

INSERTING: set[str] = {"append", "extend", "insert", "update", "setdefault", "add", "appendleft", "__setitem__"}
SCALAR_BUILTINS: set[str] = {
    "len", "int", "float", "bool", "str", "bytes", "bytearray", "repr", "format",
    "chr", "ord", "hex", "bin", "oct", "abs", "round", "divmod", "pow", "all", "any",
    "isinstance", "issubclass", "callable", "range", "object",
}
FRESH_BUILTINS: set[str] = {"list", "tuple", "dict", "set", "frozenset", "sorted", "reversed"}
PAIR_BUILTINS: set[str] = {"enumerate", "zip", "map", "filter"}
SCALAR_METHODS: set[str] = {
    "count", "index", "startswith", "endswith", "hexdigest", "digest", "join", "encode", "decode",
    "hex", "fromhex", "to_bytes", "from_bytes", "bit_length", "is_integer", "upper", "lower",
    "zfill", "ljust", "rjust", "find", "strip", "rstrip", "lstrip", "replace", "format", "split",
    "rsplit", "partition", "isdigit", "isalnum", "as_integer_ratio", "removeprefix", "removesuffix",
    "splitlines", "tobytes", "issubset", "issuperset", "isdisjoint", "unpack", "unpack_from",
    "iter_unpack", "pack", "__len__",
}
FRESH_METHODS: set[str] = {"copy", "keys", "values", "union", "intersection", "difference", "symmetric_difference"}
SCALAR_STDLIB: set[str] = {"math", "struct", "bisect", "base64", "json", "hashlib"}
ITERATOR_CALLS: set[str] = {"iter", "map", "filter", "zip", "enumerate", "reversed"}
IMMUTABLE_CALLS: set[str] = {"frozenset", "tuple", "bytes", "int", "float", "str"}
INPLACE_OPS = (ast.Add, ast.Mult, ast.BitOr, ast.BitAnd, ast.Sub, ast.BitXor)

INTROSPECTIVE: set[str] = {
    "__class__", "__dict__", "__globals__", "__closure__", "__func__", "__self__", "__code__",
    "__defaults__", "__kwdefaults__", "__mro__", "__bases__", "__base__", "__module__",
    "__builtins__", "__wrapped__", "__objclass__", "__subclasses__", "__init_subclass__",
}
BUILTIN_TYPES: set[str] = {
    "list", "dict", "set", "bytearray", "object", "type", "frozenset", "tuple", "str", "bytes", "int", "float", "memoryview",
}
MUTATORS: set[str] = set(MUTATING) | {
    "__setitem__", "__delitem__", "__setattr__", "__delattr__", "__iadd__", "__isub__", "__imul__",
    "__ior__", "__iand__", "__ixor__", "__ilshift__", "__irshift__", "pack_into", "readinto",
    "write", "fill", "put", "resize", "setfield", "insert", "remove", "discard",
    "intersection_update", "difference_update", "symmetric_difference_update",
}
READONLY_METHODS: set[str] = (
    SCALAR_METHODS
    | FRESH_METHODS
    | {
        "get", "items", "keys", "values", "index", "count", "__getitem__", "__len__", "__contains__",
        "__eq__", "__ne__", "__hash__", "__getattribute__", "most_common", "elements", "total",
        "tolist", "tobytes", "issubset", "issuperset", "isdisjoint",
    }
) - MUTATORS
ARG_WRITERS: dict[tuple[str, str], int] = {
    ("struct", "pack_into"): 1,
    ("bisect", "insort"): 0,
    ("bisect", "insort_left"): 0,
    ("bisect", "insort_right"): 0,
    ("heapq", "heappush"): 0,
    ("heapq", "heappop"): 0,
    ("heapq", "heapify"): 0,
    ("heapq", "heapreplace"): 0,
    ("heapq", "heappushpop"): 0,
    ("ctypes", "memmove"): 0,
    ("ctypes", "memset"): 0,
}
ARG_WRITER_METHODS: dict[str, int] = {"pack_into": 0, "readinto": 0}
STDLIB_READ: dict[str, set[str] | None] = {
    "math": None,
    "base64": None,
    "hashlib": None,
    "typing": None,
    "json": {"dumps", "loads"},
    "struct": {"pack", "unpack", "unpack_from", "iter_unpack", "calcsize", "Struct", "error"},
    "bisect": {"bisect", "bisect_left", "bisect_right"},
    "dataclasses": {"replace", "fields", "asdict", "astuple", "is_dataclass", "field", "dataclass"},
    "types": {"MappingProxyType", "SimpleNamespace"},
    "collections": {"Counter", "defaultdict", "OrderedDict", "namedtuple", "deque"},
    "ctypes": DEFAULT_STDLIB["ctypes"],
}
EMPTY_FACTORIES: set[str] = {"list", "dict", "set", "tuple", "frozenset", "bytearray"}
BINARY: set[str] = {
    "__add__", "__radd__", "__sub__", "__rsub__", "__mul__", "__rmul__", "__matmul__", "__rmatmul__",
    "__truediv__", "__rtruediv__", "__floordiv__", "__rfloordiv__", "__mod__", "__rmod__",
    "__pow__", "__rpow__", "__lshift__", "__rlshift__", "__rshift__", "__rrshift__",
    "__and__", "__rand__", "__or__", "__ror__", "__xor__", "__rxor__", "__divmod__", "__rdivmod__",
}
UNARY: set[str] = {"__neg__", "__pos__", "__invert__", "__abs__", "__round__"}
COMPARE: set[str] = {"__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__", "__contains__"}
CALL_DUNDERS: dict[str, set[str]] = {
    "abs": {"__abs__"},
    "round": {"__round__"},
    "divmod": {"__divmod__", "__rdivmod__"},
    "pow": {"__pow__", "__rpow__"},
}
COMPS = (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)

READ_CALLS: set[str] = {
    "len", "sorted", "tuple", "list", "set", "frozenset", "dict",
    "min", "max", "sum", "any", "all", "enumerate", "reversed", "iter", "bool", "zip",
}
READ_METHODS: set[str] = {"get", "keys", "values", "items", "copy", "count", "index"}
STD_READ_CALLS: set[tuple[str, str]] = {
    ("bisect", "bisect"), ("bisect", "bisect_left"), ("bisect", "bisect_right"), ("math", "fsum"),
}
TABLE_ATTRS: set[str] = {"_fields_", "__dataclass_fields__"}
BANNED_ATTRS: set[str] = {
    "fget", "fset", "fdel", "__wrapped__",
    "gi_frame", "gi_code", "gi_yieldfrom",
    "cr_frame", "cr_code", "ag_frame",
    "tb_frame", "tb_next",
    "f_globals", "f_locals", "f_builtins", "f_back", "f_code",
    "co_consts", "mro",
}
DUNDER_ATTRS_OK: set[str] = {"__name__", "__dataclass_fields__", "__setattr__", "__delattr__", "__init__"}
DUNDER_DEFS_OK: set[str] = {
    "__init__", "__post_init__", "__setattr__", "__delattr__", "__len__", "__contains__", "__enter__", "__exit__", "__call__",
}
BASES_OK: set[str] = {
    "object", "ValueError", "TypeError", "KeyError", "IndexError", "RuntimeError", "Exception", "ArithmeticError", "LookupError",
}
METHOD_DECORATORS: set[str] = {"classmethod", "staticmethod", "property"}


@dataclass(frozen=True)
class VerifierConfig:
    package_dir: Path
    package_name: str
    entries: tuple[tuple[str, str], ...]
    input_entries: tuple[tuple[str, str], ...]
    input_classes: tuple[tuple[str, str], ...]
    wrapper_modules: frozenset[str]
    entry_params: frozenset[str] | None
    stdlib: dict[str, set[str] | None]
    builtins_ok: frozenset[str]
    foreign_marker: str | None = None
    timeout: float = 120.0


def _inc(d: int) -> int:
    return INF if d >= INF else min(d + 1, 3)


def _dec(d: int) -> int:
    return d if d in (0, INF) else d - 1


def _join(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    for k, v in b.items():
        if v < a.get(k, INF):
            a[k] = v
    return a


def _dotted(n: ast.AST | None) -> str | None:
    if n is None:
        return None
    parts: list[str] = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
        return ".".join(reversed(parts))
    return None


def _import_entries(nodes: Sequence[ast.AST]) -> dict[str, tuple[str, str | None, str | None]]:
    out: dict[str, tuple[str, str | None, str | None]] = {}
    for n in nodes:
        if isinstance(n, ast.Import):
            for a in n.names:
                out[a.asname or a.name.split(".")[0]] = ("stdlib", a.name, None)
        elif isinstance(n, ast.ImportFrom):
            kind, mod = ("project", n.module) if n.level == 1 else ("stdlib", n.module)
            for a in n.names:
                out[a.asname or a.name] = (kind, mod, a.name)
    return out


class ParsedModule:
    def __init__(self, name: str, path: Path):
        self.name = name
        self.path = path
        self.tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        self.imports: dict[str, tuple[str, str | None, str | None]] = {}
        self.globals: dict[str, ast.AST | None] = {}
        self.defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.classes: dict[str, ast.ClassDef] = {}
        for n in self.tree.body:
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                self.imports.update(_import_entries([n]))
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.defs[n.name] = n
            elif isinstance(n, ast.ClassDef):
                self.classes[n.name] = n
            elif isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in targets:
                    for x in ast.walk(t):
                        if isinstance(x, ast.Name):
                            self.globals[x.id] = n.value
            elif isinstance(n, (ast.If, ast.Try)):
                self.imports.update(_import_entries([x for x in ast.walk(n) if isinstance(x, (ast.Import, ast.ImportFrom))]))
                for x in ast.walk(n):
                    if isinstance(x, ast.FunctionDef):
                        self.defs.setdefault(x.name, x)

    def const_str_tuple(self, name: str) -> bool:
        v = self.globals.get(name)
        return isinstance(v, (ast.Tuple, ast.List)) and all(
            isinstance(e, ast.Constant) and type(e.value) is str for e in v.elts
        )


def load_closure(
    package_dir: Path,
    seeds: Sequence[str],
    overrides: Mapping[str, Path] | None = None,
) -> dict[str, ParsedModule]:
    """Transitively load all relative-imported modules within ``package_dir``."""
    overrides = overrides or {}
    mods: dict[str, ParsedModule] = {}
    todo = list(seeds)
    while todo:
        m = todo.pop()
        path = Path(overrides[m]) if m in overrides else package_dir / f"{m}.py"
        if m in mods or not path.is_file():
            continue
        mods[m] = ParsedModule(m, path)
        for n in ast.walk(mods[m].tree):
            if isinstance(n, ast.ImportFrom) and n.level == 1 and n.module:
                todo.append(n.module)
    return mods


def _harden_modules(mods: dict[str, ParsedModule]) -> dict[str, ParsedModule]:
    for m in mods.values():
        occ: Counter[str] = Counter()
        simple = {
            x.id
            for n in m.tree.body
            if isinstance(n, (ast.Assign, ast.AnnAssign))
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
            if isinstance(t, ast.Name)
            for x in [t]
        }

        def visit(node: ast.AST) -> None:
            for ch in ast.iter_child_nodes(node):
                if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    occ[ch.name] += 1
                    continue
                if isinstance(ch, ast.Lambda):
                    continue
                if isinstance(ch, COMPS):
                    for x in ast.walk(ch):
                        if isinstance(x, ast.NamedExpr) and isinstance(x.target, ast.Name):
                            occ[x.target.id] += 1
                    continue
                if isinstance(ch, ast.Name) and isinstance(ch.ctx, (ast.Store, ast.Del)):
                    occ[ch.id] += 1
                if isinstance(ch, ast.ExceptHandler) and ch.name:
                    occ[ch.name] += 1
                if isinstance(ch, (ast.Import, ast.ImportFrom)):
                    for a in ch.names:
                        occ[a.asname or a.name.split(".")[0]] += 1
                visit(ch)

        visit(m.tree)
        for name, n in occ.items():
            if n == 1 and (name in simple or name in m.defs or name in m.classes or name in m.imports):
                continue
            m.globals[name] = None
    return mods


def _bound_names(stmts: Sequence[ast.stmt], args: Sequence[str] | None = None) -> set[str]:
    out = set(args or ())
    glob: set[str] = set()

    def visit(node: ast.AST) -> None:
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out.add(ch.name)
                continue
            if isinstance(ch, ast.Lambda):
                continue
            if isinstance(ch, COMPS):
                out.update(
                    x.target.id
                    for x in ast.walk(ch)
                    if isinstance(x, ast.NamedExpr) and isinstance(x.target, ast.Name)
                )
                continue
            if isinstance(ch, ast.Name) and isinstance(ch.ctx, (ast.Store, ast.Del)):
                out.add(ch.id)
            if isinstance(ch, ast.ExceptHandler) and ch.name:
                out.add(ch.name)
            if isinstance(ch, ast.Global):
                glob.update(ch.names)
            visit(ch)

    visit(ast.Module(body=list(stmts), type_ignores=[]))
    return out - glob


def _is_docstring(s: ast.AST) -> bool:
    return isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str)


def _target_names(t: ast.AST) -> list[str]:
    if isinstance(t, ast.Name):
        return [t.id]
    if isinstance(t, (ast.Tuple, ast.List)):
        return [n for e in t.elts for n in _target_names(e)]
    if isinstance(t, ast.Starred):
        return _target_names(t.value)
    return []


def _local_bindings(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> dict[str, list[tuple[Any, ...]]]:
    out: dict[str, list[tuple[Any, ...]]] = {}

    def add(n: str, src: tuple[Any, ...]) -> None:
        out.setdefault(n, []).append(src)

    a = node.args
    for x in (
        a.posonlyargs
        + a.args
        + a.kwonlyargs
        + ([a.vararg] if a.vararg else [])
        + ([a.kwarg] if a.kwarg else [])
    ):
        add(x.arg, ("param", x))
    body = node.body if isinstance(node.body, list) else [node.body]

    def visit(n: ast.AST, in_comp: bool = False) -> None:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not in_comp:
                add(n.name, ("def", n))
            return
        if isinstance(n, ast.Lambda):
            return
        if isinstance(n, COMPS):
            for g in n.generators:
                for x in ast.walk(g):
                    if isinstance(x, ast.NamedExpr) and isinstance(x.target, ast.Name):
                        add(x.target.id, ("walrus", x))
            for x in ast.walk(n):
                if isinstance(x, ast.NamedExpr) and isinstance(x.target, ast.Name):
                    add(x.target.id, ("walrus", x))
            return
        if isinstance(n, ast.Assign):
            for t in n.targets:
                for x in _target_names(t):
                    add(x, ("assign", n) if isinstance(t, ast.Name) else ("unpack", n))
        elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and isinstance(n.target, ast.Name):
            add(n.target.id, (type(n).__name__.lower(), n))
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            for x in _target_names(n.target):
                add(x, ("for", n))
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for it in n.items:
                if it.optional_vars is not None:
                    for x in _target_names(it.optional_vars):
                        add(x, ("with", n))
        elif isinstance(n, ast.ExceptHandler) and n.name:
            add(n.name, ("except", n))
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for al in n.names:
                add(al.asname or al.name.split(".")[0], ("import", n, al))
        elif isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name):
            add(n.target.id, ("walrus", n))
        elif isinstance(n, ast.Delete):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    add(t.id, ("del", n))
        elif hasattr(ast, "MatchAs") and isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            add(n.name, ("match", n))
        for c in ast.iter_child_nodes(n):
            visit(c, in_comp)

    for s in body:
        visit(s)
    return out


class _ReachClosure:
    def __init__(self, mods: dict[str, ParsedModule], cfg: VerifierConfig):
        self.mods = mods
        self.cfg = cfg
        self.funcs: dict[tuple[str, str], tuple[ParsedModule, ast.FunctionDef | ast.AsyncFunctionDef, str | None]] = {}
        self.methods: dict[str, set[tuple[str, str]]] = defaultdict(set)
        self.parent: dict[ast.AST, ast.AST] = {}
        self.dataclasses: set[tuple[str, str]] = set()
        self._scope_cache: dict[int, tuple[ast.AST, dict[str, tuple[str, str | None, str | None]]]] = {}
        for m in mods.values():
            for n in ast.walk(m.tree):
                for c in ast.iter_child_nodes(n):
                    self.parent[c] = n
            for name, f in m.defs.items():
                self.funcs[(m.name, name)] = (m, f, None)
            for cname, c in m.classes.items():
                if any("dataclass" in ast.unparse(d) for d in c.decorator_list):
                    self.dataclasses.add((m.name, cname))
                for f in c.body:
                    if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        k = (m.name, f"{cname}.{f.name}")
                        self.funcs[k] = (m, f, cname)
                        self.methods[f.name].add(k)
        self.foreign: set[str] = set()
        if cfg.foreign_marker:
            for w in cfg.wrapper_modules & set(mods):
                for n in ast.walk(mods[w].tree):
                    if isinstance(n, ast.Assign) and len(n.targets) == 1:
                        d = _dotted(n.targets[0])
                        v = _dotted(n.value)
                        if d and d.startswith("self.") and v and cfg.foreign_marker in v:
                            self.foreign.add(d[5:])

    def scope_imports(self, fn: ast.AST) -> dict[str, tuple[str, str | None, str | None]]:
        key = id(fn)
        if key not in self._scope_cache:
            self._scope_cache[key] = (
                fn,
                _import_entries([x for x in ast.walk(fn) if isinstance(x, (ast.Import, ast.ImportFrom))]),
            )
        return self._scope_cache[key][1]

    def walk(
        self,
        entries: Sequence[tuple[str, str]],
        live: set[tuple[str, str]],
        rules: bool,
    ) -> _ReachClosure:
        self.live = set(live)
        self.rules = rules
        self.reach: set[tuple[str, str]] = set()
        self.problems: list[str] = []
        self.escaped: set[tuple[str, str]] = set()
        self.constructed: set[tuple[str, str]] = set()
        self.stdlib_used: dict[str, set[str]] = defaultdict(set)
        self.unresolved = 0
        self.replace_used = False
        self.checked_globals: dict[str, set[str]] = {}
        self.checked_classes: set[tuple[str, str]] = set()
        self.import_calls: set[tuple[str, str]] = set()
        self.unresolved_sites: list[str] = []

        todo = list(entries)
        if rules:
            for k, (m, f, cls) in self.funcs.items():
                if cls and (m.name, cls) in self.live and self.implicit(f):
                    todo.append(k)
                    if f.name in HOOKS and not self.benign_hook(f):
                        self.bad(m, f, f"attribute hook defined: {cls}.{f.name}")

        while True:
            while todo:
                k = todo.pop()
                if k in self.reach or k not in self.funcs:
                    continue
                self.reach.add(k)
                m, fn, _ = self.funcs[k]
                todo.extend(self.body(m, fn))
            extra = [k for k in self.escaped if k not in self.reach]
            for mod, name in list(self.import_calls):
                k: tuple[str, str] | None = (mod, name) if (mod, name) in self.funcs else None
                if k is None and name in self.mods[mod].imports and self.mods[mod].imports[name][0] == "project":
                    _, tmod, attr = self.mods[mod].imports[name]
                    k = (tmod, attr) if tmod and attr and (tmod, attr) in self.funcs else None
                if k is not None and k not in self.reach:
                    extra.append(k)
            inits: list[tuple[str, str]] = []
            for mod, cname in set(self.constructed) | (self.dataclasses & self.live if self.replace_used else set()):
                for s in ("__init__", "__post_init__", "__new__"):
                    key = (mod, f"{cname}.{s}")
                    if key in self.funcs and key not in self.reach:
                        inits.append(key)
            if not extra and not inits:
                break
            todo.extend(extra + inits)
        return self

    def implicit(self, f: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        if f.name in ("__init__", "__post_init__", "__new__"):
            return False
        if f.name.startswith("__") and f.name.endswith("__"):
            return True
        return any(
            _dotted(d) == "property" or (isinstance(d, ast.Attribute) and d.attr in ("setter", "getter", "deleter"))
            for d in f.decorator_list
        )

    def benign_hook(self, f: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        if f.name not in ("__setattr__", "__delattr__"):
            return False
        for s in f.body:
            if isinstance(s, ast.If) and all(isinstance(x, ast.Raise) for x in s.body) and not s.orelse:
                continue
            if (
                isinstance(s, ast.Expr)
                and isinstance(s.value, ast.Call)
                and _dotted(s.value.func) in ("object.__setattr__", "object.__delattr__")
            ):
                continue
            return False
        return True

    def bad(self, m: ParsedModule, node: ast.AST | None, msg: str) -> None:
        if self.rules:
            self.problems.append(f"{m.name}.py:{getattr(node, 'lineno', 0)}: {msg}")

    def enclosing_class(self, fn: ast.AST) -> ast.ClassDef | None:
        node = fn
        while node in self.parent:
            node = self.parent[node]
            if isinstance(node, ast.ClassDef):
                return node
        return None

    def resolve_name(
        self,
        m: ParsedModule,
        fn: ast.FunctionDef | ast.AsyncFunctionDef | None,
        name: str,
        node: ast.AST,
        depth: int = 0,
    ) -> set[tuple[str, str]]:
        if name == "cls" and fn is not None and any(_dotted(d) == "classmethod" for d in getattr(fn, "decorator_list", [])):
            c = self.enclosing_class(fn)
            if c is not None:
                self.constructed.add((m.name, c.name))
                self.live.add((m.name, c.name))
            return set()
        local_imports = self.scope_imports(fn) if fn is not None else {}
        if fn is not None:
            nested = {x.name for x in ast.walk(fn) if isinstance(x, ast.FunctionDef) and x is not fn}
            if name in nested:
                return set()
            args = {a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)} if hasattr(fn, "args") else set()
            stored = {x.id for x in ast.walk(fn) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store)}
            if name in args or (name in stored and name not in local_imports):
                self.unresolved += 1
                self.unresolved_sites.append(f"{m.name}.py:{getattr(node, 'lineno', 0)} {name}")
                return set()
        imports = dict(m.imports)
        imports.update(local_imports)
        if name in imports:
            kind, mod, attr = imports[name]
            if kind == "stdlib":
                self.stdlib(m, node, mod, attr)
                return set()
            if mod not in self.mods:
                self.bad(m, node, f"project import outside closure: {mod}")
                return set()
            tm = self.mods[mod]
            if attr in tm.defs:
                return {(mod, attr)}
            if attr in tm.classes:
                self.constructed.add((mod, attr))
                self.live.add((mod, attr))
                return set()
            if attr in tm.imports and depth < 4:
                return self.resolve_name(tm, None, attr, node, depth + 1)
            self.unresolved += 1
            return set()
        if name in m.defs:
            return {(m.name, name)}
        if name in m.classes:
            self.constructed.add((m.name, name))
            self.live.add((m.name, name))
            return set()
        if name in FORBIDDEN_BUILTINS:
            self.bad(m, node, "forbidden builtin " + name)
            return set()
        if name in PURE_BUILTINS:
            return set()
        if name in m.globals:
            self.unresolved += 1
            return set()
        self.bad(m, node, "unresolvable call " + name)
        return set()

    def stdlib(self, m: ParsedModule, node: ast.AST, mod: str | None, attr: str | None) -> None:
        root = (mod or "").split(".")[0]
        if root == "__future__":
            return
        if root not in self.cfg.stdlib:
            self.bad(m, node, f"stdlib module not allowed in reachable code: {mod}.{attr}")
            return
        if root == "ctypes" and m.name not in self.cfg.wrapper_modules:
            self.bad(m, node, "ctypes outside the wrapper modules")
            return
        allowed = self.cfg.stdlib[root]
        if allowed is not None and attr is not None and attr not in allowed:
            self.bad(m, node, f"stdlib attribute not allowed: {mod}.{attr}")
            return
        if root == "dataclasses" and attr == "replace":
            self.replace_used = True
        self.stdlib_used[root].add(attr or "*")

    def body(self, m: ParsedModule, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        imports = dict(m.imports)
        imports.update(self.scope_imports(fn))
        local_sets: dict[str, bool] = {}
        stored = {x.id for x in ast.walk(fn) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store)} | {
            a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)
        }

        def is_global(name: str) -> bool:
            return (name in m.globals or name in m.imports) and name not in stored

        for n in ast.walk(fn):
            if isinstance(n, (ast.Global, ast.Nonlocal)):
                self.bad(m, n, "global/nonlocal")
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                if n.id in FORBIDDEN_BUILTINS and n.id not in m.globals and n.id not in imports:
                    self.bad(m, n, "forbidden builtin " + n.id)
                if n.id in imports and imports[n.id][0] == "stdlib":
                    par = self.parent.get(n)
                    if not (isinstance(par, ast.Attribute) and par.value is n):
                        self.stdlib(m, n, imports[n.id][1], imports[n.id][2])
                par = self.parent.get(n)
                if not (isinstance(par, ast.Call) and par.func is n):
                    if (
                        n.id in m.classes
                        and n.id not in stored
                        and not isinstance(par, ast.Compare)
                        and not (isinstance(par, ast.Call) and _dotted(par.func) in ("isinstance", "issubclass", "type"))
                    ):
                        self.constructed.add((m.name, n.id))
                        self.live.add((m.name, n.id))
                    elif (
                        n.id in imports
                        and imports[n.id][0] == "project"
                        and imports[n.id][1] in self.mods
                        and imports[n.id][2] in self.mods[imports[n.id][1]].classes
                        and not isinstance(par, ast.Compare)
                        and not (isinstance(par, ast.Call) and _dotted(par.func) in ("isinstance", "issubclass", "type"))
                    ):
                        mod_t, cls_t = imports[n.id][1], imports[n.id][2]
                        if mod_t and cls_t:
                            self.constructed.add((mod_t, cls_t))
                            self.live.add((mod_t, cls_t))
                    if n.id in m.defs and n.id not in stored:
                        self.escaped.add((m.name, n.id))
                    elif n.id in imports and imports[n.id][0] == "project":
                        _, mod, attr = imports[n.id]
                        if mod in self.mods and attr and attr in self.mods[mod].defs:
                            self.escaped.add((mod, attr))
            if (
                isinstance(n, ast.Attribute)
                and isinstance(n.ctx, ast.Load)
                and isinstance(n.value, ast.Name)
                and n.value.id in imports
                and imports[n.value.id][2] is None
                and imports[n.value.id][0] == "stdlib"
            ):
                self.stdlib(m, n, imports[n.value.id][1], n.attr)
            if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
                for t in (n.targets if isinstance(n, (ast.Assign, ast.Delete)) else [n.target]):
                    for x in ast.walk(t):
                        if isinstance(x, (ast.Subscript, ast.Attribute)):
                            base = x.value
                            while isinstance(base, (ast.Subscript, ast.Attribute)):
                                base = base.value
                            if isinstance(base, ast.Name) and is_global(base.id):
                                self.bad(m, x, "store into module-level object " + base.id)
                            if isinstance(x, ast.Attribute) and isinstance(x.value, ast.Call) and _dotted(x.value.func) == "type":
                                self.bad(m, x, "store into type(...) attribute")
                            if isinstance(x, ast.Attribute) and isinstance(x.value, ast.Name) and x.value.id == "cls":
                                self.bad(m, x, "store into class attribute")
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in MUTATING
                and isinstance(n.func.value, ast.Name)
                and is_global(n.func.value.id)
            ):
                self.bad(m, n, f"mutating call on module-level object {n.func.value.id}.{n.func.attr}")
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("getattr", "setattr", "delattr", "hasattr") and len(n.args) >= 2:
                if not self.constant_name(m, fn, n.args[1]):
                    self.bad(m, n, f"{n.func.id} with a non-constant attribute name")
                if n.func.id in ("setattr", "delattr") and not self.setattr_ok(fn, n):
                    self.bad(m, n, f"{n.func.id} on an object that is not fresh/self")
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and self.is_set(n.value, local_sets):
                local_sets[n.targets[0].id] = True
            if isinstance(n, ast.comprehension) and self.is_set(n.iter, local_sets) and not self.order_free(m, fn, self.parent.get(n)):
                self.bad(m, self.parent.get(n), "order-dependent iteration over a set (hash order)")
            if isinstance(n, ast.For) and self.is_set(n.iter, local_sets):
                self.bad(m, n, "for loop over a set (hash order)")
            if isinstance(n, ast.Call) and (
                (isinstance(n.func, ast.Name) and n.func.id in ORDERED_CONSUMERS)
                or (isinstance(n.func, ast.Attribute) and n.func.attr == "join")
            ):
                if any(self.is_set(a, local_sets) for a in n.args):
                    self.bad(m, n, f"order-dependent use of a set (hash order) via {_dotted(n.func) or 'call'}")
            if isinstance(n, ast.Starred) and self.is_set(n.value, local_sets):
                self.bad(m, n, "star-unpacking a set (hash order)")
            if isinstance(n, ast.Call):
                out.extend(self.call(m, fn, n, imports))
            if isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load) and not (
                isinstance(self.parent.get(n), ast.Call) and getattr(self.parent.get(n), "func", None) is n
            ):
                out.extend(k for k in self.methods.get(n.attr, ()) if (k[0], k[1].split(".")[0]) in self.live)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("getattr", "hasattr") and len(n.args) >= 2:
                for name in self.name_values(m, fn, n.args[1]):
                    out.extend(k for k in self.methods.get(name, ()) if (k[0], k[1].split(".")[0]) in self.live)
            if (
                isinstance(n, ast.Name)
                and isinstance(n.ctx, ast.Load)
                and n.id in m.globals
                and n.id not in stored
                and n.id not in self.checked_globals.setdefault(m.name, set())
            ):
                self.checked_globals[m.name].add(n.id)
                self.import_time(m, m.globals[n.id], "module value " + n.id)

        if fn.args.defaults or fn.args.kw_defaults:
            for d in list(fn.args.defaults) + [x for x in fn.args.kw_defaults if x is not None]:
                self.import_time(m, d, "default of " + fn.name)
        cls = self.enclosing_class(fn)
        if cls is not None and (m.name, cls.name) not in self.checked_classes:
            self.checked_classes.add((m.name, cls.name))
            for s in cls.body:
                if isinstance(s, (ast.Assign, ast.AnnAssign)) and s.value is not None:
                    self.import_time(m, s.value, "class attribute of " + cls.name)
            for d in cls.decorator_list:
                self.import_time(m, d, "decorator of " + cls.name)
        return out

    def name_values(self, m: ParsedModule, fn: ast.AST, node: ast.AST) -> list[str]:
        if isinstance(node, ast.Constant) and type(node.value) is str:
            return [node.value]
        out: list[str] = []
        if isinstance(node, ast.Name):
            for f in ast.walk(fn):
                if isinstance(f, (ast.For, ast.comprehension)) and node.id in [x.id for x in ast.walk(f.target) if isinstance(x, ast.Name)]:
                    it = f.iter
                    if isinstance(it, ast.Name) and it.id in m.globals and m.globals[it.id] is not None:
                        it = m.globals[it.id]  # type: ignore[assignment]
                    for x in ast.walk(it):
                        if isinstance(x, ast.Constant) and type(x.value) is str:
                            out.append(x.value)
                        if isinstance(x, ast.keyword) and x.arg:
                            out.append(x.arg)
        return out

    def import_time(self, m: ParsedModule, expr: ast.AST | None, what: str) -> None:
        if expr is None:
            return
        for x in ast.walk(expr):
            if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load):
                if x.id in FORBIDDEN_BUILTINS:
                    self.bad(m, x, f"{what} uses forbidden builtin {x.id}")
                if x.id in m.imports and m.imports[x.id][0] == "stdlib":
                    par = self.parent.get(x)
                    attr = par.attr if isinstance(par, ast.Attribute) and par.value is x else m.imports[x.id][2]
                    self.stdlib(m, x, m.imports[x.id][1], attr)
            if isinstance(x, ast.Call):
                fn_name = _dotted(x.func)
                head = (fn_name or "").split(".")[0]
                if head in PURE_BUILTINS or head in m.classes or (head in m.imports and m.imports[head][0] == "stdlib") or fn_name in ("field", "dataclass"):
                    continue
                if head in m.imports and m.imports[head][0] == "project" and m.imports[head][1] in self.mods and m.imports[head][2] in self.mods[m.imports[head][1]].classes:
                    continue
                if head in m.defs or (head in m.imports and m.imports[head][0] == "project"):
                    if fn_name:
                        self.import_calls.add((m.name, fn_name))
                    continue
                self.bad(m, x, f"{what} calls {fn_name} at import time")

    def constant_name(self, m: ParsedModule, fn: ast.AST, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and type(node.value) is str:
            return True
        if not isinstance(node, ast.Name):
            return False
        for f in ast.walk(fn):
            if not isinstance(f, (ast.For, ast.comprehension)):
                continue
            names = [x.id for x in ast.walk(f.target) if isinstance(x, ast.Name)]
            if node.id not in names:
                continue
            it = f.iter
            first = isinstance(f.target, ast.Tuple) and len(f.target.elts) > 0 and isinstance(f.target.elts[0], ast.Name) and f.target.elts[0].id == node.id
            if isinstance(it, (ast.Tuple, ast.List)) and all(isinstance(e, ast.Constant) and type(e.value) is str for e in it.elts):
                return True
            if isinstance(it, ast.Name) and m.const_str_tuple(it.id) and it.id not in {x.id for x in ast.walk(fn) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store)}:
                return True
            if _dotted(it) and (_dotted(it) or "").endswith("_fields_") and first:
                return True
            if (
                isinstance(it, ast.Call)
                and isinstance(it.func, ast.Attribute)
                and it.func.attr == "items"
                and isinstance(it.func.value, ast.Call)
                and _dotted(it.func.value.func) == "dict"
                and not it.func.value.args
                and first
            ):
                return True
            if (
                isinstance(it, (ast.Tuple, ast.List))
                and first
                and all(isinstance(e, ast.Tuple) and len(e.elts) > 0 and isinstance(e.elts[0], ast.Constant) and type(e.elts[0].value) is str for e in it.elts)
            ):
                return True
        return False

    def setattr_ok(self, fn: ast.FunctionDef | ast.AsyncFunctionDef, n: ast.Call) -> bool:
        t = n.args[0]
        if fn.name in ("__post_init__", "__init__") and isinstance(t, ast.Name) and t.id == "self":
            return True
        if isinstance(t, ast.Name):
            assigns = [x for x in ast.walk(fn) if isinstance(x, ast.Assign) and any(isinstance(y, ast.Name) and y.id == t.id for y in x.targets)]
            return bool(assigns) and all(isinstance(x.value, ast.Call) for x in assigns)
        return False

    def is_set(self, node: ast.AST, local_sets: dict[str, bool]) -> bool:
        if isinstance(node, (ast.Set, ast.SetComp)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("set", "frozenset"):
            return True
        if isinstance(node, ast.Name) and node.id in local_sets:
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.BitOr, ast.BitAnd, ast.Sub, ast.BitXor)):
            return self.is_set(node.left, local_sets) or self.is_set(node.right, local_sets)
        return False

    def order_free(self, m: ParsedModule, fn: ast.AST, comp: ast.AST | None) -> bool:
        if comp is None:
            return False
        if isinstance(comp, ast.SetComp):
            return True
        par = self.parent.get(comp)
        if (
            isinstance(par, ast.Call)
            and isinstance(par.func, ast.Name)
            and par.func.id in ("all", "any", "set", "frozenset", "sorted", "len")
            and not isinstance(comp, ast.ListComp)
        ) or (isinstance(par, ast.Call) and isinstance(par.func, ast.Name) and par.func.id == "sorted"):
            return True
        if isinstance(comp, ast.DictComp):
            if isinstance(par, ast.Assign) and len(par.targets) == 1 and isinstance(par.targets[0], ast.Name):
                name = par.targets[0].id
                for x in ast.walk(fn):
                    if isinstance(x, ast.Name) and x.id == name and isinstance(x.ctx, ast.Load):
                        p = self.parent.get(x)
                        if isinstance(p, ast.Subscript) and p.value is x:
                            continue
                        if isinstance(p, ast.keyword) and p.arg is None:
                            continue
                        if isinstance(p, ast.Compare) and all(isinstance(o, (ast.In, ast.NotIn, ast.Eq, ast.NotEq)) for o in p.ops):
                            continue
                        return False
                return True
            if isinstance(par, ast.keyword) and par.arg is None:
                return True
            if isinstance(par, ast.Compare) and all(isinstance(o, (ast.Eq, ast.NotEq)) for o in par.ops):
                return True
        return False

    def call(
        self,
        m: ParsedModule,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        n: ast.Call,
        imports: dict[str, tuple[str, str | None, str | None]],
    ) -> list[tuple[str, str]]:
        f = n.func
        if isinstance(f, ast.Name):
            return list(self.resolve_name(m, fn, f.id, n))
        if not isinstance(f, ast.Attribute):
            self.unresolved += 1
            self.unresolved_sites.append(f"{m.name}.py:{n.lineno} {ast.unparse(f)[:60]}")
            return []
        base = f.value
        if isinstance(base, ast.Call) and isinstance(base.func, ast.Name) and base.func.id == "super":
            cls = self.enclosing_class(fn)
            out: list[tuple[str, str]] = []
            for b in (cls.bases if cls is not None else []):
                bn = _dotted(b)
                if bn in m.classes:
                    tm, tn = m, bn
                elif bn in imports and imports[bn][0] == "project" and imports[bn][1] in self.mods:
                    tm, tn = self.mods[imports[bn][1]], imports[bn][2]
                else:
                    tm, tn = None, None
                if tm is not None and tn in tm.classes and (tm.name, f"{tn}.{f.attr}") in self.funcs:
                    out.append((tm.name, f"{tn}.{f.attr}"))
            return out
        if isinstance(base, ast.Name) and base.id in imports and base.id not in {a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)}:
            kind, mod, attr = imports[base.id]
            if kind == "stdlib" and attr is None:
                self.stdlib(m, n, mod, f.attr)
                return []
            if kind == "stdlib":
                return []
            if kind == "project" and mod in self.mods:
                tm = self.mods[mod]
                if attr in tm.classes:
                    k = (mod, f"{attr}.{f.attr}")
                    self.live.add((mod, attr))
                    return [k] if k in self.funcs else []
        if isinstance(base, ast.Name) and base.id == "object" and f.attr in ("__setattr__", "__delattr__"):
            if fn.name not in ("__post_init__", "__init__", "__setattr__", "__delattr__"):
                self.bad(m, n, f"object.{f.attr} outside __init__/__post_init__")
            return []
        if isinstance(base, ast.Name) and base.id in m.classes:
            self.live.add((m.name, base.id))
            k = (m.name, f"{base.id}.{f.attr}")
            return [k] if k in self.funcs else []
        cands = [k for k in self.methods.get(f.attr, ()) if (k[0], k[1].split(".")[0]) in self.live]
        if f.attr in self.foreign and m.name not in self.cfg.wrapper_modules:
            self.bad(m, n, "foreign function called outside the wrappers: " + f.attr)
        if not cands and f.attr not in PURE_METHODS and f.attr not in self.foreign:
            self.bad(m, n, "method call with no live-class candidate and not a pure builtin method: ." + f.attr)
        return cands


class _Persistence:
    """Interprocedural persistence-level dataflow analysis."""

    def __init__(self, c: _ReachClosure, live: set[tuple[str, str]]):
        self.c = c
        self.cfg = c.cfg
        self.entry_set = set(c.cfg.entries)
        self.live = live
        self.problems: set[str] = set()
        self.final = False
        self.rounds = 0
        self.funcs = {k: c.funcs[k] for k in c.reach}
        self.ctypes_names = {
            x.value
            for mod in c.mods.values()
            for cd in mod.classes.values()
            for st in cd.body
            if isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_fields_" for t in st.targets)
            for x in ast.walk(st.value)
            if isinstance(x, ast.Constant) and type(x.value) is str
        }
        self.fields: dict[str, int] = {}
        self.ret: dict[tuple[str, str], int] = {}
        self.params: dict[tuple[tuple[str, str], str], int] = {}
        self.lam = INF
        self.method_self: dict[str, int] = {}
        self.pcls: dict[tuple[tuple[str, str], str], Any] = {}
        self.changed = True
        self.cache_imports: dict[int, tuple[ast.AST, dict[str, tuple[str, str | None, str | None]]]] = {}
        self.cache_names: dict[tuple[str, str], tuple[set[str], set[str], dict[str, list[ast.AST | None]]]] = {}
        self.new_named = any(
            (isinstance(n, ast.Attribute) and n.attr == "__new__") or (isinstance(n, ast.Name) and n.id == "__new__")
            for k in self.funcs
            for n in ast.walk(self.funcs[k][1])
        )
        for mod, cname in live:
            cd = c.mods[mod].classes.get(cname) if mod in c.mods else None
            for s in (cd.body if cd is not None else []):
                if isinstance(s, (ast.Assign, ast.AnnAssign)) and s.value is not None:
                    if isinstance(s.value, ast.Call) and _dotted(s.value.func) in ("field", "dataclasses.field"):
                        for kw in s.value.keywords:
                            bad_kw = (kw.arg == "default" and not self.immutable(c.mods[mod], kw.value)) or (
                                kw.arg == "default_factory"
                                and not (
                                    isinstance(kw.value, ast.Name)
                                    and kw.value.id in EMPTY_FACTORIES
                                    and kw.value.id not in c.mods[mod].globals
                                    and kw.value.id not in c.mods[mod].defs
                                    and kw.value.id not in c.mods[mod].classes
                                    and kw.value.id not in c.mods[mod].imports
                                )
                            )
                            if bad_kw or kw.arg is None:
                                for t in (s.targets if isinstance(s, ast.Assign) else [s.target]):
                                    if isinstance(t, ast.Name):
                                        self.fields[t.id] = 0
                    elif not self.immutable(c.mods[mod], s.value):
                        for t in (s.targets if isinstance(s, ast.Assign) else [s.target]):
                            if isinstance(t, ast.Name):
                                self.fields[t.id] = 0
        self.subclassed = {
            (_dotted(b) or "").split(".")[-1]
            for m in c.mods.values()
            for cd in ast.walk(m.tree)
            if isinstance(cd, ast.ClassDef)
            for b in cd.bases
        }

    def low(self, table: dict[Any, int], key: Any, v: int) -> None:
        if v < table.get(key, INF):
            table[key] = v
            self.changed = True

    def field(self, name: str) -> int:
        return min(self.fields.get(name, INF), self.fields.get("*", INF))

    def attr_names(self, node: ast.AST) -> list[str]:
        names = list(self.c.name_values(self.m, self.fn, node))
        if isinstance(node, ast.Name):
            for f in ast.walk(self.fn):
                if (
                    isinstance(f, (ast.For, ast.comprehension))
                    and node.id in [x.id for x in ast.walk(f.target) if isinstance(x, ast.Name)]
                    and (_dotted(f.iter) or "").endswith("_fields_")
                ):
                    names += sorted(self.ctypes_names)
        return names or ["*"]

    def bad(self, m: ParsedModule, node: ast.AST | None, msg: str) -> None:
        if self.final:
            self.problems.add(f"{m.name}.py:{getattr(node, 'lineno', 0)}: {msg}")

    def immutable(self, m: ParsedModule, e: ast.AST | None, depth: int = 0) -> bool:
        if e is None or depth > 8:
            return False
        if isinstance(e, ast.Constant):
            return True
        if isinstance(e, ast.Tuple):
            return all(self.immutable(m, x, depth + 1) for x in e.elts)
        if isinstance(e, ast.UnaryOp):
            return self.immutable(m, e.operand, depth + 1)
        if isinstance(e, ast.BinOp):
            return self.immutable(m, e.left, depth + 1) and self.immutable(m, e.right, depth + 1)
        if isinstance(e, ast.Name):
            free = e.id not in m.globals and e.id not in m.defs and e.id not in m.classes and e.id not in m.imports
            if free:
                return e.id in PURE_BUILTINS
            if e.id in m.globals and e.id not in m.defs and e.id not in m.classes:
                return self.immutable(m, m.globals[e.id], depth + 1)
            if e.id in m.imports and m.imports[e.id][0] == "project" and m.imports[e.id][1] in self.c.mods:
                tm = self.c.mods[m.imports[e.id][1]]
                attr = m.imports[e.id][2]
                if attr and attr in tm.globals and attr not in tm.defs and attr not in tm.classes:
                    return self.immutable(tm, tm.globals[attr], depth + 1)
            return False
        if isinstance(e, ast.Call) and not e.keywords:
            name = _dotted(e.func) or ""
            head = name.split(".")[0]
            if name in IMMUTABLE_CALLS:
                ok = head not in m.globals and head not in m.defs and head not in m.classes and head not in m.imports
            elif name.endswith("Struct"):
                ok = head in m.imports and m.imports[head][0] == "stdlib" and (m.imports[head][1] or "").split(".")[0] == "struct"
            else:
                ok = False
            return ok and all(self.immutable(m, x, depth + 1) for x in e.args)
        return False

    def imports_of(self, m: ParsedModule, fn: ast.AST) -> dict[str, tuple[str, str | None, str | None]]:
        key = id(fn)
        if key not in self.cache_imports:
            self.cache_imports[key] = (fn, dict(m.imports, **self.c.scope_imports(fn)))
        return self.cache_imports[key][1]

    def free_level(self, m: ParsedModule, fn: ast.AST, name: str) -> int:
        imports = self.imports_of(m, fn)
        if name in imports:
            kind, mod, attr = imports[name]
            if kind == "project" and mod in self.c.mods and attr is not None:
                tm = self.c.mods[mod]
                if attr in tm.globals and attr not in tm.defs and attr not in tm.classes and self.immutable(tm, tm.globals[attr]):
                    return INF
            return 0
        if name in m.defs or name in m.classes:
            return 0
        if name in m.globals:
            return INF if self.immutable(m, m.globals[name]) else 0
        return INF

    def stdlib_root(self, m: ParsedModule, fn: ast.AST, node: ast.AST | None) -> str | None:
        if not isinstance(node, ast.Name):
            return None
        imports = self.imports_of(m, fn)
        if node.id in imports and imports[node.id][0] == "stdlib":
            return (imports[node.id][1] or "").split(".")[0]
        return None

    def function(self, k: tuple[str, str]) -> None:
        m, fn, cls = self.funcs[k]
        self.k, self.m, self.fn = k, m, fn
        if k not in self.cache_names:
            a = fn.args
            own = (
                [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
                + ([a.vararg.arg] if a.vararg else [])
                + ([a.kwarg.arg] if a.kwarg else [])
            )
            self.cache_names[k] = (
                _bound_names(fn.body, own),
                {x.name for x in ast.walk(fn) if isinstance(x, ast.FunctionDef) and x is not fn},
                {},
            )
        self.names, self.nested_names, self.cache_defs = self.cache_names[k]
        self.benign = fn.name in ("__setattr__", "__delattr__") and self.c.benign_hook(fn)
        self.maxenv: dict[str, int] = {}
        a = fn.args
        own = (
            [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
            + ([a.vararg.arg] if a.vararg else [])
            + ([a.kwarg.arg] if a.kwarg else [])
        )
        if cls is not None and self.c.implicit(fn):
            for p in [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs][1:]:
                self.low(self.params, (k, p), 0)
        env: dict[str, int] = {}
        self.own_params = set(own)
        for i, p in enumerate(own):
            lv = self.params.get((k, p), INF)
            if k in self.entry_set and (self.cfg.entry_params is None or p in self.cfg.entry_params):
                lv = 0
            if k in self.c.escaped and k not in self.entry_set:
                lv = 0
            if cls is not None and i == 0 and (self.c.implicit(fn) or fn.name in self.method_self):
                lv = min(lv, self.method_self.get(fn.name, 0) if not self.c.implicit(fn) else 0)
            if cls is not None and i > 0 and fn.name in self.method_self:
                lv = 0
            if any(_dotted(d) == "classmethod" for d in fn.decorator_list) and i == 0:
                lv = 0
            env[p] = lv
            if k in self.entry_set or k in self.c.escaped or (cls is not None and i == 0 and self.c.implicit(fn)) or fn.name in self.method_self:
                self.join_cls((k, p), TOP)
        self.defaults(m, fn)
        body = fn.body
        if self.seal_guard(m, fn, cls):
            self.block(body[:1], env, {})
            env["self"] = INF
            body = body[1:]
        keys: dict[str, int] = {}
        self.block(body, env, keys)
        for x in ast.walk(fn):
            if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) and x is not fn:
                inner = dict(self.maxenv)
                for arg in ast.walk(x.args):
                    if isinstance(arg, ast.arg):
                        inner[arg.arg] = 0
                self.block(x.body, inner, {}, nested=True)

    def defaults(self, m: ParsedModule, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for g in [fn] + [x for x in ast.walk(fn) if isinstance(x, FUNCS) and x is not fn]:
            for d in list(g.args.defaults) + [x for x in g.args.kw_defaults if x is not None]:
                if not self.immutable(m, d):
                    self.bad(m, d, f"mutable default of {getattr(g, 'name', 'lambda')}: {ast.unparse(d)[:60]}")

    def seal_guard(self, m: ParsedModule, fn: ast.FunctionDef | ast.AsyncFunctionDef, cls: str | None) -> bool:
        if cls is None or cls in self.subclassed or self.new_named or not fn.body:
            return False
        s = fn.body[0]
        if not (isinstance(s, ast.If) and not s.orelse and len(s.body) == 1 and isinstance(s.body[0], (ast.Return, ast.Raise))):
            return False
        t = s.test
        if not (isinstance(t, ast.Call) and _dotted(t.func) == "getattr" and len(t.args) == 3 and ast.unparse(t) == "getattr(self, '_sealed', False)"):
            return False
        return self.sealing(m, cls)

    def sealing(self, m: ParsedModule, cname: str) -> bool:
        cd = m.classes.get(cname)
        if cd is None:
            return False
        slots = [s.value for s in cd.body if isinstance(s, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__slots__" for t in s.targets)]
        if not (slots and isinstance(slots[0], ast.Tuple) and any(isinstance(e, ast.Constant) and e.value == "_sealed" for e in slots[0].elts)):
            return False
        init = [f for f in cd.body if isinstance(f, ast.FunctionDef) and f.name == "__init__"]
        if not init or ast.unparse(init[0].body[-1]) != "self._sealed = True":
            return False
        hooks: set[str] = set()
        for b in cd.bases:
            bn = _dotted(b)
            bc = m.classes.get(bn) if bn else None
            for f in (bc.body if bc is not None else []):
                if (
                    isinstance(f, ast.FunctionDef)
                    and f.name in ("__setattr__", "__delattr__")
                    and self.c.benign_hook(f)
                    and isinstance(f.body[0], ast.If)
                    and ast.unparse(f.body[0].test) == "getattr(self, '_sealed', False)"
                ):
                    hooks.add(f.name)
        own = {f.name for f in cd.body if isinstance(f, ast.FunctionDef)}
        return hooks == {"__setattr__", "__delattr__"} and not (own & {"__setattr__", "__delattr__", "__getattr__", "__getattribute__"})

    def block(self, stmts: Sequence[ast.stmt], env: dict[str, int], keys: dict[str, int], nested: bool = False) -> None:
        for s in stmts:
            self.stmt(s, env, keys, nested)

    def dunder(self, names: AbstractSet[str]) -> int:
        return min([self.ret.get(k, INF) for name in names for k in self.c.methods.get(name, ()) if k in self.funcs] + [INF])

    def stmt(self, s: ast.stmt, env: dict[str, int], keys: dict[str, int], nested: bool) -> None:
        def eval_e(e: ast.AST | None) -> int:
            return self.expr(e, env, keys)

        if isinstance(s, ast.Global):
            self.bad(self.m, s, "global statement in reachable code: " + ", ".join(s.names))
            return
        if isinstance(s, ast.Assign):
            split = self.dict_split(s.value, env, keys)
            v = eval_e(s.value)
            for t in s.targets:
                self.assign(t, v, env, keys, split)
        elif isinstance(s, ast.AnnAssign):
            if s.value is not None:
                self.assign(s.target, eval_e(s.value), env, keys, self.dict_split(s.value, env, keys))
        elif isinstance(s, ast.AugAssign):
            v = eval_e(s.value)
            if isinstance(s.target, ast.Name):
                cur = self.name(s.target.id, env, keys) if (s.target.id in env or s.target.id in self.names) else self.free_level(self.m, self.fn, s.target.id)
                if cur == 0 and not self.scalar_local(s.target.id, set()):
                    self.bad(self.m, s, "augmented assignment on a persistent object: " + s.target.id)
                self.set_name(s.target.id, min(cur, _inc(_dec(v))), env, keys, keep_keys=True)
            else:
                cur = eval_e(s.target)
                if cur == 0 and not self.scalar_expr(s.target, set()):
                    self.bad(self.m, s, "augmented assignment on a persistent element: " + ast.unparse(s.target)[:80])
                self.store(s.target, v, env, keys, "augmented store")
        elif isinstance(s, ast.Delete):
            for t in s.targets:
                if isinstance(t, (ast.Attribute, ast.Subscript)):
                    self.store(t, INF, env, keys, "delete")
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            if isinstance(s.target, (ast.Tuple, ast.List)) and isinstance(s.iter, ast.Call):
                probe = dict(env), dict(keys)
                if self.positional(s.iter, s.target, *probe):
                    def body(e: dict[str, int], kk: dict[str, int]) -> None:
                        self.positional(s.iter, s.target, e, kk)
                        self.block(s.body, e, kk, nested)

                    self.loop(env, keys, body)
                    self.block(s.orelse, env, keys, nested)
                    return
            it = self.iter_level(s.iter, env, keys)
            self.loop(env, keys, lambda e, kk: (self.assign(s.target, it, e, kk, None), self.block(s.body, e, kk, nested)))
            self.block(s.orelse, env, keys, nested)
        elif isinstance(s, ast.While):
            self.loop(env, keys, lambda e, kk: (self.expr(s.test, e, kk), self.block(s.body, e, kk, nested)))
            self.block(s.orelse, env, keys, nested)
        elif isinstance(s, ast.If):
            eval_e(s.test)
            e1, k1 = dict(env), dict(keys)
            self.block(s.body, e1, k1, nested)
            e2, k2 = dict(env), dict(keys)
            self.block(s.orelse, e2, k2, nested)
            env.clear()
            env.update(_join(e1, e2))
            keys.clear()
            keys.update(_join(k1, k2))
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for w in s.items:
                v = eval_e(w.context_expr)
                if w.optional_vars is not None:
                    self.assign(w.optional_vars, v, env, keys, None)
            self.block(s.body, env, keys, nested)
        elif isinstance(s, ast.Try):
            e0, k0 = dict(env), dict(keys)
            self.block(s.body, env, keys, nested)
            outs = [(dict(env), dict(keys))]
            for h in s.handlers:
                eh, kh = _join(dict(e0), env), _join(dict(k0), keys)
                if h.type is not None:
                    self.expr(h.type, eh, kh)
                if h.name:
                    self.set_name(h.name, 0, eh, kh)
                self.block(h.body, eh, kh, nested)
                outs.append((eh, kh))
            self.block(s.orelse, outs[0][0], outs[0][1], nested)
            for eo, ko in outs[1:]:
                _join(outs[0][0], eo)
                _join(outs[0][1], ko)
            env.clear()
            env.update(outs[0][0])
            keys.clear()
            keys.update(outs[0][1])
            self.block(s.finalbody, env, keys, nested)
        elif isinstance(s, ast.Return):
            if s.value is not None:
                v = eval_e(s.value)
                if not nested:
                    self.low(self.ret, self.k, v)
        elif isinstance(s, ast.Expr):
            eval_e(s.value)
        elif isinstance(s, ast.Raise):
            eval_e(s.exc)
            eval_e(s.cause)
        elif isinstance(s, ast.Assert):
            eval_e(s.test)
            eval_e(s.msg)
        elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Pass, ast.Break, ast.Continue, ast.Import, ast.ImportFrom, ast.Nonlocal)):
            pass
        else:
            self.bad(self.m, s, "statement not modelled by the persistence analysis: " + type(s).__name__)

    def positional(self, it: ast.AST, target: ast.AST, env: dict[str, int], keys: dict[str, int]) -> bool:
        if not (
            isinstance(it, ast.Call)
            and isinstance(it.func, ast.Name)
            and it.func.id in ("zip", "enumerate")
            and not it.keywords
            and not any(isinstance(x, ast.Starred) for x in it.args)
            and isinstance(target, (ast.Tuple, ast.List))
            and not any(isinstance(x, ast.Starred) for x in target.elts)
        ):
            return False
        f = it.func.id
        if f in env or f in self.names or f in self.m.globals or f in self.m.defs or f in self.m.classes or f in self.imports_of(self.m, self.fn):
            return False
        if f == "zip" and len(it.args) == len(target.elts):
            items = [self.iter_level(x, env, keys) for x in it.args]
        elif f == "enumerate" and len(it.args) == 1 and len(target.elts) == 2:
            items = [INF, self.iter_level(it.args[0], env, keys)]
        else:
            return False
        for t, lv in zip(target.elts, items):
            self.assign(t, lv, env, keys, None)
        return True

    def loop(self, env: dict[str, int], keys: dict[str, int], body: Any) -> None:
        for _ in range(12):
            before, kb = dict(env), dict(keys)
            body(env, keys)
            _join(env, before)
            _join(keys, kb)
            if env == before and keys == kb:
                return
        self.bad(self.m, None, "loop level fixpoint did not converge")

    def name(self, n: str, env: dict[str, int], keys: dict[str, int]) -> int:
        lv = env.get(n, INF)
        return min(lv, _inc(keys[n])) if n in keys else lv

    def set_name(self, n: str, v: int, env: dict[str, int], keys: dict[str, int], keep_keys: bool = False) -> None:
        env[n] = v
        if not keep_keys:
            keys.pop(n, None)
        if v < self.maxenv.get(n, INF):
            self.maxenv[n] = v

    def assign(self, t: ast.AST, v: int, env: dict[str, int], keys: dict[str, int], split: tuple[int, int] | None) -> None:
        if isinstance(t, ast.Name):
            if split is not None:
                vals, ks = split
                self.set_name(t.id, _inc(vals), env, keys)
                keys[t.id] = ks
                if ks < self.maxenv.get(t.id, INF):
                    self.maxenv[t.id] = ks
            else:
                self.set_name(t.id, v, env, keys)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for x in t.elts:
                self.assign(
                    x.value if isinstance(x, ast.Starred) else x,
                    _inc(_dec(v)) if isinstance(x, ast.Starred) else _dec(v),
                    env,
                    keys,
                    None,
                )
        elif isinstance(t, ast.Starred):
            self.assign(t.value, v, env, keys, None)
        elif isinstance(t, (ast.Attribute, ast.Subscript)):
            self.store(t, v, env, keys, "store")

    def store(self, t: ast.Attribute | ast.Subscript, v: int, env: dict[str, int], keys: dict[str, int], what: str) -> None:
        if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id in keys:
            obj = env.get(t.value.id, INF)
            kl = self.expr(t.slice, env, keys)
            if obj == 0:
                self.bad(self.m, t, f"{what} into a persistent object: {ast.unparse(t)[:80]}")
            if what != "delete":
                env[t.value.id] = min(obj, _inc(v))
                keys[t.value.id] = min(keys[t.value.id], kl)
            return
        obj = self.expr(t.value, env, keys)
        if isinstance(t, ast.Subscript):
            self.expr(t.slice, env, keys)
        if obj == 0:
            self.bad(self.m, t, f"{what} into a persistent object: {ast.unparse(t)[:80]}")
        if what == "delete":
            return
        if isinstance(t, ast.Attribute):
            self.low(self.fields, t.attr, v)
        else:
            self.contains(t.value, _inc(v), env, keys)

    def contains(self, x: ast.AST, lv: int, env: dict[str, int], keys: dict[str, int]) -> None:
        while isinstance(x, ast.Subscript):
            x = x.value
            lv = _inc(lv)
        if isinstance(x, ast.Name) and x.id in self.names:
            env[x.id] = min(env.get(x.id, INF), lv)
            if x.id in keys:
                keys[x.id] = min(keys[x.id], _dec(lv))
            if env[x.id] < self.maxenv.get(x.id, INF):
                self.maxenv[x.id] = env[x.id]
        elif isinstance(x, ast.Attribute):
            self.low(self.fields, x.attr, lv)

    def dict_split(self, e: ast.AST, env: dict[str, int], keys: dict[str, int]) -> tuple[int, int] | None:
        if isinstance(e, ast.Dict):
            vs = [self.expr(v, dict(env), dict(keys)) for v in e.values]
            ks = [self.expr(x, dict(env), dict(keys)) for x in e.keys if x is not None]
            if any(x is None for x in e.keys):
                return None
            return min(vs + [INF]), min(ks + [INF])
        if isinstance(e, ast.DictComp):
            ce, ck = dict(env), dict(keys)
            self.generators(e.generators, ce, ck)
            return self.expr(e.value, ce, ck), self.expr(e.key, ce, ck)
        return None

    def iter_level(self, e: ast.AST, env: dict[str, int], keys: dict[str, int]) -> int:
        if isinstance(e, ast.Name) and e.id in keys:
            lv = keys[e.id]
        elif (
            isinstance(e, ast.Call)
            and isinstance(e.func, ast.Attribute)
            and isinstance(e.func.value, ast.Name)
            and e.func.value.id in keys
            and not e.args
        ):
            n = e.func.value.id
            self.expr(e, env, keys)
            if e.func.attr == "keys":
                lv = keys[n]
            elif e.func.attr == "values":
                lv = _dec(env.get(n, INF))
            elif e.func.attr == "items":
                lv = _inc(min(keys[n], _dec(env.get(n, INF))))
            else:
                lv = _dec(self.expr(e, env, keys))
        else:
            lv = _dec(self.expr(e, env, keys))
        return min(lv, self.dunder({"__next__"}), _dec(self.dunder({"__iter__"})))

    def generators(self, gens: Sequence[ast.comprehension], env: dict[str, int], keys: dict[str, int]) -> None:
        for g in gens:
            if not self.positional(g.iter, g.target, env, keys):
                it = self.iter_level(g.iter, env, keys)
                self.assign(g.target, it, env, keys, None)
            for cond in g.ifs:
                self.expr(cond, env, keys)

    def expr(self, e: ast.AST | None, env: dict[str, int], keys: dict[str, int]) -> int:
        def eval_e(x: ast.AST | None) -> int:
            return self.expr(x, env, keys)

        if e is None or isinstance(e, ast.Constant):
            return INF
        if isinstance(e, ast.JoinedStr):
            for x in e.values:
                eval_e(x)
            return INF
        if isinstance(e, ast.FormattedValue):
            eval_e(e.value)
            return INF
        if isinstance(e, ast.Name):
            if e.id == "cls" and any(_dotted(d) == "classmethod" for d in self.fn.decorator_list):
                return 0
            if e.id in env or e.id in self.names:
                return self.name(e.id, env, keys)
            return self.free_level(self.m, self.fn, e.id)
        if isinstance(e, ast.Attribute):
            if e.attr in INTROSPECTIVE:
                eval_e(e.value)
                return 0
            if e.attr in MUTATORS and isinstance(e.value, ast.Name) and e.value.id in BUILTIN_TYPES and e.value.id not in env and e.value.id not in self.names:
                self.bad(self.m, e, "mutating method of a builtin type taken as a value: " + ast.unparse(e)[:80])
            base = eval_e(e.value)
            field = self.field(e.attr)
            if e.attr in MUTATING and base == 0 and not self.benign:
                self.bad(self.m, e, "mutating method of a persistent object taken as a value: " + ast.unparse(e)[:80])
            if e.attr in self.c.methods:
                self.low(self.method_self, e.attr, base)
            if isinstance(e.value, ast.Name) and e.value.id not in self.names and base == 0:
                imports = self.imports_of(self.m, self.fn)
                if e.value.id in imports and imports[e.value.id][0] == "stdlib" and (imports[e.value.id][1] or "").split(".")[0] == "math":
                    v = field
                else:
                    v = min(_dec(base), field)
            else:
                v = min(_dec(base), field)
            props = [
                k for k in self.c.methods.get(e.attr, ())
                if k in self.funcs and self.funcs[k][2] is not None and self.c.implicit(self.funcs[k][1])
            ]
            return min([v] + [self.ret.get(k, INF) for k in props])
        if isinstance(e, ast.Subscript):
            eval_e(e.slice)
            if isinstance(e.value, ast.Name) and e.value.id in keys:
                base_lv = _dec(env.get(e.value.id, INF))
            else:
                base_lv = _dec(eval_e(e.value))
            return min(base_lv, self.dunder({"__getitem__"}))
        if isinstance(e, ast.Starred):
            return eval_e(e.value)
        if isinstance(e, (ast.Tuple, ast.List, ast.Set)):
            return _inc(min([_dec(eval_e(x.value)) if isinstance(x, ast.Starred) else eval_e(x) for x in e.elts] + [INF]))
        if isinstance(e, ast.Dict):
            parts: list[int] = []
            for k, v in zip(e.keys, e.values):
                if k is None:
                    parts.append(_dec(eval_e(v)))
                else:
                    parts.extend([eval_e(k), eval_e(v)])
            return _inc(min(parts + [INF]))
        if isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            ce, ck = dict(env), dict(keys)
            self.generators(e.generators, ce, ck)
            parts = [self.expr(e.key, ce, ck), self.expr(e.value, ce, ck)] if isinstance(e, ast.DictComp) else [self.expr(e.elt, ce, ck)]
            return _inc(min(parts))
        if isinstance(e, ast.BoolOp):
            return min(eval_e(x) for x in e.values)
        if isinstance(e, ast.BinOp):
            return min(_inc(min(_dec(eval_e(e.left)), _dec(eval_e(e.right)))), self.dunder(BINARY))
        if isinstance(e, ast.UnaryOp):
            eval_e(e.operand)
            return min(INF, self.dunder(UNARY))
        if isinstance(e, ast.Compare):
            eval_e(e.left)
            for x in e.comparators:
                eval_e(x)
            return min(INF, self.dunder(COMPARE))
        if isinstance(e, ast.IfExp):
            eval_e(e.test)
            return min(eval_e(e.body), eval_e(e.orelse))
        if isinstance(e, ast.NamedExpr):
            v = eval_e(e.value)
            self.assign(e.target, v, env, keys, None)
            return v
        if isinstance(e, ast.Lambda):
            inner = dict(self.maxenv)
            inner.update(env)
            for arg in ast.walk(e.args):
                if isinstance(arg, ast.arg):
                    inner[arg.arg] = 0
            v = self.expr(e.body, inner, dict(keys))
            if v < self.lam:
                self.lam = v
                self.changed = True
            return INF
        if isinstance(e, ast.Call):
            return self.call(e, env, keys)
        if isinstance(e, ast.Slice):
            eval_e(e.lower)
            eval_e(e.upper)
            eval_e(e.step)
            return INF
        if isinstance(e, (ast.Await, ast.Yield, ast.YieldFrom)):
            self.bad(self.m, e, "generator/await in reachable code")
            return 0
        self.bad(self.m, e, "expression not modelled by the persistence analysis: " + type(e).__name__)
        return 0

    def targets(self, call: ast.Call, env: dict[str, int] | None) -> list[tuple[tuple[str, str] | None, str]]:
        f = call.func
        c = self.c
        m = self.m
        fn = self.fn
        imports = self.imports_of(m, fn)
        out: list[tuple[tuple[str, str] | None, str]] = []

        def construct(mod: str, cname: str) -> None:
            for s in ("__init__", "__new__"):
                if (mod, f"{cname}.{s}") in self.funcs:
                    out.append(((mod, f"{cname}.{s}"), "construct"))
            out.append(((mod, cname), "fields"))

        if isinstance(f, ast.Name):
            if f.id in self.nested_names and (env is None or f.id not in env):
                return [(None, "nested")]
            if f.id == "cls" and any(_dotted(d) == "classmethod" for d in fn.decorator_list):
                cd = c.enclosing_class(fn)
                if cd is not None:
                    construct(m.name, cd.name)
                return out
            if f.id in self.names:
                return [(x, "unresolved") for x in self.escaped()] + [(None, "unresolved")]
            if f.id in imports and imports[f.id][0] == "project" and imports[f.id][1] in c.mods:
                tm = c.mods[imports[f.id][1]]
                attr = imports[f.id][2]
                for _ in range(4):
                    if attr and attr in tm.defs:
                        return [((tm.name, attr), "function")]
                    if attr and attr in tm.classes:
                        construct(tm.name, attr)
                        return out
                    if attr and attr in tm.imports and tm.imports[attr][0] == "project" and tm.imports[attr][1] in c.mods:
                        tm_next, attr = tm.imports[attr][1], tm.imports[attr][2]
                        if tm_next is None:
                            break
                        tm = c.mods[tm_next]
                        continue
                    break
                return [(x, "unresolved") for x in self.escaped()] + [(None, "unresolved")]
            if f.id in m.defs:
                return [((m.name, f.id), "function")]
            if f.id in m.classes:
                construct(m.name, f.id)
                return out
            if f.id in self.nested_names:
                return [(None, "nested")]
            return []
        if isinstance(f, ast.Attribute):
            base = f.value
            if isinstance(base, ast.Call) and isinstance(base.func, ast.Name) and base.func.id == "super":
                cd = c.enclosing_class(fn)
                for b in (cd.bases if cd is not None else []):
                    bn = _dotted(b)
                    if bn in m.classes:
                        tm, tn = m, bn
                    elif bn in imports and imports[bn][0] == "project" and imports[bn][1] in c.mods:
                        tm, tn = c.mods[imports[bn][1]], imports[bn][2]
                    else:
                        tm, tn = None, None
                    if tm is not None and tn and (tm.name, f"{tn}.{f.attr}") in self.funcs:
                        out.append(((tm.name, f"{tn}.{f.attr}"), "instance"))
                return out
            if isinstance(base, ast.Name) and base.id not in self.names:
                cls_of: tuple[str, str] | None = None
                if base.id in m.classes:
                    cls_of = (m.name, base.id)
                elif base.id in imports and imports[base.id][0] == "project" and imports[base.id][1] in c.mods:
                    imp_mod, imp_attr = imports[base.id][1], imports[base.id][2]
                    if imp_mod and imp_attr and imp_attr in c.mods[imp_mod].classes:
                        cls_of = (imp_mod, imp_attr)
                if cls_of is not None:
                    k = (cls_of[0], f"{cls_of[1]}.{f.attr}")
                    return [(k, "unbound")] if k in self.funcs else []
                if base.id in imports and imports[base.id][0] == "stdlib":
                    return []
            return [(k, "instance") for k in c.methods.get(f.attr, ()) if (k[0], k[1].split(".")[0]) in self.live and k in self.funcs]
        return [(x, "unresolved") for x in self.escaped()] + [(None, "unresolved")]

    def escaped(self) -> list[tuple[str, str]]:
        return [k for k in self.c.escaped if k in self.funcs]

    def decorated(self, k: tuple[str, str], name: str) -> bool:
        return any(_dotted(d) == name for d in self.funcs[k][1].decorator_list)

    def bind(
        self,
        k: tuple[str, str],
        how: str,
        receiver: int,
        args: Sequence[tuple[bool, int]],
        keywords: Sequence[tuple[str | None, int]],
    ) -> None:
        _, f, cls = self.funcs[k]
        a = f.args
        pos = [x.arg for x in a.posonlyargs + a.args]
        if how == "construct" and pos:
            pos = pos[1:]
        elif how == "instance" and cls is not None and not self.decorated(k, "staticmethod"):
            if pos:
                self.low(self.params, (k, pos[0]), 0 if self.decorated(k, "classmethod") else receiver)
                pos = pos[1:]
        elif how == "unbound" and self.decorated(k, "classmethod") and pos:
            pos = pos[1:]
        star = min([lv for (st, lv) in args if st] + [lv for (nm, lv) in keywords if nm is None] + [INF])
        if star < INF:
            for p in pos + [x.arg for x in a.kwonlyargs] + ([a.vararg.arg] if a.vararg else []) + ([a.kwarg.arg] if a.kwarg else []):
                self.low(self.params, (k, p), _dec(star))
        plain = [lv for (st, lv) in args if not st]
        for i, lv in enumerate(plain):
            if i < len(pos):
                self.low(self.params, (k, pos[i]), lv)
            elif a.vararg:
                self.low(self.params, (k, a.vararg.arg), _inc(lv))
        kwonly = [x.arg for x in a.kwonlyargs]
        for nm, lv in keywords:
            if nm is None:
                continue
            if nm in pos or nm in kwonly:
                self.low(self.params, (k, nm), lv)
            elif a.kwarg:
                self.low(self.params, (k, a.kwarg.arg), _inc(lv))

    def post_init(self, mod: str, cname: str, level: int) -> None:
        k = (mod, f"{cname}.__post_init__")
        if k in self.funcs:
            self.low(self.params, (k, "self"), level)

    def dataclass_fields(self, mod: str, cname: str) -> list[str]:
        cd = self.c.mods[mod].classes[cname]
        return [
            s.target.id
            for s in cd.body
            if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name) and "ClassVar" not in ast.unparse(s.annotation)
        ]

    def call(self, e: ast.Call, env: dict[str, int], keys: dict[str, int]) -> int:
        f = e.func
        m = self.m

        def shadow(n: str) -> bool:
            return n in env or n in self.names or n in m.globals or n in m.defs or n in m.classes or n in self.imports_of(m, self.fn)

        if isinstance(f, ast.Name) and f.id == "getattr" and not shadow("getattr") and len(e.args) >= 2:
            obj = e.args[0]
            lv = self.expr(obj, dict(env), dict(keys))
            names = self.attr_names(e.args[1])
            builtin_type = isinstance(obj, ast.Name) and obj.id in BUILTIN_TYPES and not shadow(obj.id)
            if (lv == 0 or builtin_type) and (names == ["*"] or any(n in MUTATORS or n in INTROSPECTIVE for n in names)):
                self.bad(m, e, "getattr of a mutating/introspective attribute on a persistent object or builtin type: " + ast.unparse(e)[:80])
            if any(n in INTROSPECTIVE for n in names):
                self._call_inner(e, env, keys)
                return 0
        if isinstance(f, ast.Name) and f.id in ("eval", "exec", "compile", "__import__", "globals", "locals", "vars") and not shadow(f.id):
            self.bad(m, e, "forbidden builtin in reachable code: " + f.id)

        result = self._call_inner(e, env, keys)
        arg_levels = [self.expr(x.value if isinstance(x, ast.Starred) else x, dict(env), dict(keys)) for x in e.args]
        kw_levels = [self.expr(x.value, dict(env), dict(keys)) for x in e.keywords]
        lowest = min(arg_levels + kw_levels + [INF])
        resolved = bool(self.targets(e, env))
        if isinstance(f, ast.Name) and not resolved and not shadow(f.id):
            if f.id == "filter" and len(e.args) == 2:
                result = min(result, _inc(_dec(arg_levels[1])))
            elif f.id == "map" and e.args:
                fa = e.args[0]
                items = INF if (isinstance(fa, ast.Name) and fa.id in SCALAR_BUILTINS and not shadow(fa.id)) else self.lam if isinstance(fa, ast.Lambda) else 0
                result = min(result, _inc(items))
            elif f.id in CALL_DUNDERS:
                result = min(result, self.dunder(CALL_DUNDERS[f.id]))
            elif (
                f.id not in SCALAR_BUILTINS
                and f.id not in FRESH_BUILTINS
                and f.id not in PAIR_BUILTINS
                and f.id not in PURE_BUILTINS
                and f.id not in ("next", "iter", "min", "max", "sum", "memoryview", "type", "super", "setattr", "delattr", "getattr", "hasattr")
                and lowest == 0
            ):
                self.bad(m, e, "unmodelled builtin call with a persistent argument: " + ast.unparse(e)[:80])
        if isinstance(f, ast.Attribute):
            meth = f.attr
            recv = (
                self.expr(f.value, dict(env), dict(keys))
                if not (isinstance(f.value, ast.Call) and isinstance(f.value.func, ast.Name) and f.value.func.id == "super")
                else env.get("self", INF)
            )
            if meth in ARG_WRITER_METHODS and len(arg_levels) > ARG_WRITER_METHODS[meth] and arg_levels[ARG_WRITER_METHODS[meth]] == 0:
                self.bad(m, e, f"{meth} writes into a persistent argument: {ast.unparse(e)[:80]}")
            if resolved and recv == 0 and meth in MUTATORS:
                self.bad(m, e, "builtin mutator name on a persistent receiver: " + ast.unparse(f)[:80])
        return result

    def _call_inner(self, e: ast.Call, env: dict[str, int], keys: dict[str, int]) -> int:
        def eval_e(x: ast.AST) -> int:
            return self.expr(x, env, keys)

        f = e.func
        m = self.m
        receiver = INF
        split_recv: str | None = None
        if isinstance(f, ast.Attribute):
            if isinstance(f.value, ast.Call) and isinstance(f.value.func, ast.Name) and f.value.func.id == "super":
                receiver = env.get("self", INF)
            elif isinstance(f.value, ast.Name) and f.value.id in keys:
                split_recv = f.value.id
                receiver = env.get(split_recv, INF)
            else:
                receiver = eval_e(f.value)
        elif not isinstance(f, ast.Name):
            eval_e(f)
        args = [(isinstance(x, ast.Starred), eval_e(x)) for x in e.args]
        keywords = [(x.arg, eval_e(x.value)) for x in e.keywords]
        lowest = min([lv for _, lv in args] + [lv for _, lv in keywords] + [INF])
        tg = self.targets(e, env)
        result = INF
        resolved = False
        for key, how in tg:
            if key is not None and how in ("function", "instance", "unbound", "construct"):
                self.bind_classes(key, how, e)
        for key, how in tg:
            if how == "nested":
                result = min(result, 0)
                resolved = True
                continue
            if key is None:
                result = min(result, self.lam, _inc(lowest))
                resolved = True
                continue
            if how == "fields":
                mod, cname = key
                resolved = True
                if (mod, cname) in self.c.dataclasses:
                    flds = self.dataclass_fields(mod, cname)
                    plain = [lv for (st, lv) in args if not st]
                    for i, lv in enumerate(plain):
                        if i < len(flds):
                            self.low(self.fields, flds[i], lv)
                    for nm, lv in keywords:
                        for fl in ([nm] if nm is not None else flds):
                            self.low(self.fields, fl, lv if nm is not None else _dec(lv))
                    for st, lv in args:
                        if st:
                            for fl in flds:
                                self.low(self.fields, fl, _dec(lv))
                self.post_init(mod, cname, _inc(lowest))
                result = min(result, _inc(lowest))
                continue
            resolved = True
            self.bind(key, how, receiver, args, keywords)
            result = min(result, _inc(lowest) if how == "construct" else self.ret.get(key, INF))
            if how == "unresolved":
                result = min(result, self.lam, _inc(lowest))

        if isinstance(f, ast.Name) and not resolved:
            root = self.stdlib_root(m, self.fn, f)
            if root is not None:
                attr = self.imports_of(m, self.fn)[f.id][2]
                result = self.stdlib(root, attr or "", e, args, keywords, lowest)
            elif f.id == "type":
                result = 0
            elif f.id == "super":
                result = env.get("self", INF)
            elif f.id in ("setattr", "delattr"):
                if args and args[0][1] == 0:
                    self.bad(m, e, f"{f.id} on a persistent object: {ast.unparse(e)[:80]}")
                if f.id == "setattr" and len(args) >= 3:
                    for nm in self.attr_names(e.args[1]):
                        self.low(self.fields, nm, args[2][1])
                result = INF
            elif f.id in ("getattr", "hasattr"):
                nms = self.c.name_values(m, self.fn, e.args[1]) if len(e.args) > 1 else []
                fl = (
                    min([self.field(nm) for nm in self.attr_names(e.args[1])] if len(e.args) > 1 else [INF])
                    if nms or len(e.args) < 2 or self.attr_names(e.args[1]) != ["*"]
                    else min(list(self.fields.values()) + [INF])
                )
                result = INF if f.id == "hasattr" else min(_dec(args[0][1]) if args else INF, fl, args[2][1] if len(args) > 2 else INF)
            elif f.id == "next":
                if args and args[0][1] == 0:
                    self.bad(m, e, "next() on a persistent iterator: " + ast.unparse(e)[:80])
                result = min([_dec(args[0][1])] + [lv for _, lv in args[1:]]) if args else INF
            elif f.id == "iter":
                result = (0 if args[0][1] == 0 else _inc(_dec(args[0][1]))) if args else INF
            elif f.id in ("min", "max"):
                result = min([_dec(lv) for _, lv in args] + [lv for _, lv in args if len(args) > 1] + [INF])
            elif f.id == "memoryview":
                result = args[0][1] if args else INF
            elif f.id == "sum":
                result = min([_dec(lv) for _, lv in args] + [INF])
            elif f.id in FRESH_BUILTINS:
                result = _inc(min([_dec(lv) for _, lv in args] + [_dec(lv) for _, lv in keywords] + [INF]))
            elif f.id in PAIR_BUILTINS:
                result = _inc(_inc(min([_dec(lv) for _, lv in args] + [INF])))
            elif f.id in SCALAR_BUILTINS or f.id in PURE_BUILTINS:
                result = INF
            else:
                result = 0
        elif isinstance(f, ast.Attribute) and not resolved:
            meth = f.attr
            root = self.stdlib_root(m, self.fn, f.value) if not (isinstance(f.value, ast.Name) and f.value.id in self.names) else None
            if isinstance(f.value, ast.Name) and f.value.id == "object" and f.value.id not in self.names and meth in ("__setattr__", "__delattr__"):
                if args and args[0][1] == 0 and not self.benign:
                    self.bad(m, e, f"object.{meth} on a persistent object")
                if meth == "__setattr__" and len(args) >= 3 and not self.benign:
                    for nm in self.attr_names(e.args[1]):
                        self.low(self.fields, nm, args[2][1])
                result = INF
            elif isinstance(f.value, ast.Name) and f.value.id in PURE_BUILTINS and f.value.id not in self.names and self.free_level(m, self.fn, f.value.id) == INF:
                if meth in MUTATING and args and args[0][1] == 0:
                    self.bad(m, e, f"mutating unbound {_dotted(f)} on a persistent object")
                if meth in INSERTING and len(args) > 1 and e.args:
                    self.contains(e.args[0], _inc(min(lv for _, lv in args[1:])), env, keys)
                result = INF if meth in SCALAR_METHODS else min(_dec(lv) for _, lv in args) if args else INF
            elif root is not None:
                result = self.stdlib(root, meth, e, args, keywords, lowest)
            elif meth in self.c.foreign:
                if lowest == 0:
                    self.bad(m, e, "foreign call with a persistent argument: " + ast.unparse(e)[:80])
                result = INF
            else:
                result = self.method(meth, f, receiver, split_recv, args, lowest, env, keys)
        elif isinstance(f, ast.Attribute):
            meth = f.attr
            if meth in PURE_METHODS:
                result = min(result, self.method(meth, f, receiver, split_recv, args, lowest, env, keys))
        return result

    def method(
        self,
        meth: str,
        f: ast.Attribute,
        receiver: int,
        split_recv: str | None,
        args: Sequence[tuple[bool, int]],
        lowest: int,
        env: dict[str, int],
        keys: dict[str, int],
    ) -> int:
        if receiver == 0 and meth not in READONLY_METHODS and meth not in MUTATING:
            self.bad(self.m, f, f"method {meth} on a persistent object is not on the read-only allow-list: {ast.unparse(f)[:80]}")
        if meth in MUTATING and receiver == 0:
            self.bad(self.m, f, "mutating call on a persistent object: " + ast.unparse(f)[:80])
        if meth in INSERTING and lowest < INF:
            if split_recv is not None:
                env[split_recv] = min(env.get(split_recv, INF), _inc(min(lv for _, lv in args[-1:]) if args else INF))
                if meth == "setdefault" and args:
                    keys[split_recv] = min(keys[split_recv], args[0][1])
                if meth == "update":
                    keys[split_recv] = min(keys[split_recv], _dec(lowest))
            else:
                self.contains(f.value, _inc(lowest), env, keys)
        if meth in SCALAR_METHODS:
            return INF
        if split_recv is not None:
            if meth == "keys":
                return _inc(keys[split_recv])
            if meth == "items":
                return _inc(_inc(min(keys[split_recv], _dec(receiver))))
            if meth in ("get", "pop", "setdefault"):
                return min([_dec(receiver)] + [lv for _, lv in args[1:]])
            receiver = min(receiver, _inc(keys[split_recv]))
        if meth == "items":
            return _inc(_inc(_dec(receiver)))
        if meth in FRESH_METHODS:
            return _inc(min(_dec(receiver), _dec(lowest)))
        return min(_dec(receiver), lowest)

    def stdlib(
        self,
        root: str,
        attr: str,
        e: ast.Call,
        args: Sequence[tuple[bool, int]],
        keywords: Sequence[tuple[str | None, int]],
        lowest: int,
    ) -> int:
        key = (root, attr)
        if key in ARG_WRITERS:
            i = ARG_WRITERS[key]
            if len(args) > i and args[i][1] == 0:
                self.bad(self.m, e, f"{root}.{attr} writes into a persistent argument")
            return INF
        allowed = STDLIB_READ.get(root, ())
        if root in STDLIB_READ and (allowed is None or attr in allowed):
            if root == "dataclasses":
                if attr == "replace":
                    for nm, lv in keywords:
                        for fl in ([nm] if nm is not None else ["*"]):
                            self.low(self.fields, fl, lv if nm is not None else _dec(lv))
                    res = _inc(min(_dec(args[0][1]) if args else INF, lowest))
                    for mod, cname in self.c.dataclasses & set(self.live):
                        self.post_init(mod, cname, res)
                    return res
                if attr == "fields":
                    return 0
                return INF
            if root == "types" and attr == "MappingProxyType":
                return args[0][1] if args else INF
            if root == "ctypes" and attr == "byref":
                return args[0][1] if args else INF
            if root in SCALAR_STDLIB or root in ("ctypes", "typing", "collections"):
                return INF if root != "collections" else _inc(min(_dec(lowest), INF))
            return 0
        if lowest == 0:
            self.bad(self.m, e, f"stdlib call not on the read-only allow-list with a persistent argument: {root}.{attr}")
        return 0

    def bind_classes(self, k: tuple[str, str], how: str, e: ast.Call) -> None:
        _, f, cls = self.funcs[k]
        a = f.args
        pos = [x.arg for x in a.posonlyargs + a.args]
        if how == "construct" and pos:
            pos = pos[1:]
        elif how == "instance" and cls is not None and not self.decorated(k, "staticmethod") and pos:
            self.join_cls((k, pos[0]), TOP)
            pos = pos[1:]
        elif how == "unbound" and self.decorated(k, "classmethod") and pos:
            pos = pos[1:]
        every = pos + [x.arg for x in a.kwonlyargs] + ([a.vararg.arg] if a.vararg else []) + ([a.kwarg.arg] if a.kwarg else [])
        if any(isinstance(x, ast.Starred) for x in e.args) or any(x.arg is None for x in e.keywords):
            for p in every:
                self.join_cls((k, p), TOP)
            return
        for i, x in enumerate(e.args):
            if i < len(pos):
                self.join_cls((k, pos[i]), self.classes_of(x))
            elif a.vararg:
                self.join_cls((k, a.vararg.arg), TOP)
        for x in e.keywords:
            target = x.arg if x.arg in every else (a.kwarg.arg if a.kwarg else x.arg)
            if target:
                self.join_cls((k, target), self.classes_of(x.value))

    def join_cls(self, key: tuple[tuple[str, str], str], value: Any) -> None:
        old = self.pcls.get(key, frozenset())
        new = TOP if TOP in (old, value) else old | value
        if new != old:
            self.pcls[key] = new
            self.changed = True

    def classes_of(self, e: ast.AST, depth: int = 0) -> Any:
        if depth > 6:
            return TOP
        if isinstance(e, ast.Call):
            tg = self.targets(e, None)
            if tg and all(how in ("fields", "construct") for _, how in tg):
                return frozenset(key for key, how in tg if how == "fields")
            if self.stdlib_root(self.m, self.fn, e.func if isinstance(e.func, ast.Name) else None) == "dataclasses" and _dotted(e.func) == "replace" and e.args:
                return self.classes_of(e.args[0], depth + 1)
            return TOP
        if isinstance(e, ast.IfExp):
            a, b = self.classes_of(e.body, depth + 1), self.classes_of(e.orelse, depth + 1)
            return TOP if TOP in (a, b) else a | b
        if isinstance(e, ast.Name) and e.id in self.names:
            if e.id in self.own_params:
                return self.pcls.get((self.k, e.id), frozenset())
            out: frozenset[tuple[str, str]] = frozenset()
            for d in self.definitions(e.id):
                c = self.classes_of(d, depth + 1) if d is not None else TOP
                if c == TOP:
                    return TOP
                out |= c
            return out
        return TOP

    def definitions(self, name: str) -> list[ast.AST | None]:
        if name in self.cache_defs:
            return self.cache_defs[name]
        out: list[ast.AST | None] = []
        self.cache_defs[name] = out
        for n in ast.walk(self.fn):
            if isinstance(n, (ast.Assign, ast.AnnAssign)):
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                    if isinstance(t, ast.Name) and t.id == name:
                        out.append(n.value)
                    elif isinstance(t, (ast.Tuple, ast.List)) and any(isinstance(x, ast.Name) and x.id == name for x in ast.walk(t)):
                        if (
                            isinstance(n.value, (ast.Tuple, ast.List))
                            and len(n.value.elts) == len(t.elts)
                            and not any(isinstance(x, ast.Starred) for x in t.elts + n.value.elts)
                        ):
                            out.extend(v for x, v in zip(t.elts, n.value.elts) if isinstance(x, ast.Name) and x.id == name)
                            if any(not isinstance(x, ast.Name) and any(isinstance(y, ast.Name) and y.id == name for y in ast.walk(x)) for x in t.elts):
                                out.append(None)
                        else:
                            out.append(None)
            elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
                out.append(ast.BinOp(left=ast.Name(id=name, ctx=ast.Load()), op=n.op, right=n.value))
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension, ast.NamedExpr)) and any(isinstance(x, ast.Name) and x.id == name for x in ast.walk(n.target)):
                out.append(None)
            elif isinstance(n, (ast.With, ast.AsyncWith)) and any(
                w.optional_vars is not None and any(isinstance(x, ast.Name) and x.id == name for x in ast.walk(w.optional_vars))
                for w in n.items
            ):
                out.append(None)
            elif isinstance(n, ast.ExceptHandler) and n.name == name:
                out.append(None)
            elif isinstance(n, (ast.Import, ast.ImportFrom)) and any((x.asname or x.name.split(".")[0]) == name for x in n.names):
                out.append(None)
        return out

    def scalar_local(self, name: str, seen: set[str]) -> bool:
        if name in seen:
            return True
        if name in self.own_params:
            return False
        defs = self.definitions(name)
        return bool(defs) and all(d is not None and self.scalar_expr(d, seen | {name}) for d in defs)

    def scalar_expr(self, e: ast.AST, seen: set[str]) -> bool:
        if isinstance(e, ast.Constant):
            return type(e.value) in (int, float, bool, str, bytes)
        if isinstance(e, ast.Name):
            if e.id in self.names:
                return self.scalar_local(e.id, seen)
            v = self.m.globals.get(e.id) if e.id not in self.m.defs and e.id not in self.m.classes and e.id not in self.imports_of(self.m, self.fn) else None
            return (
                v is not None
                and self.immutable(self.m, v)
                and all(
                    isinstance(x, (ast.Constant, ast.BinOp, ast.UnaryOp, ast.operator, ast.unaryop))
                    and (not isinstance(x, ast.Constant) or type(x.value) in (int, float, bool, str, bytes))
                    for x in ast.walk(v)
                )
            )
        if isinstance(e, ast.BinOp):
            return self.scalar_expr(e.left, seen) and self.scalar_expr(e.right, seen)
        if isinstance(e, ast.UnaryOp):
            return self.scalar_expr(e.operand, seen)
        if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name) and e.value.id in self.names:
            cs = self.classes_of(e.value)
            return cs != TOP and bool(cs) and all(self.guarded(c, e.attr) for c in cs)
        return False

    def guarded(self, ckey: tuple[str, str], f: str) -> bool:
        mod, cname = ckey
        cd = self.c.mods[mod].classes.get(cname) if mod in self.c.mods else None
        if cd is None or any(isinstance(x, ast.FunctionDef) and x.name in ("__init__", "__new__", "__setattr__") for x in cd.body):
            return False
        if not any(ast.unparse(d) == "dataclass(frozen=True)" for d in cd.decorator_list):
            return False
        if f not in self.dataclass_fields(mod, cname):
            return False
        for other in self.c.mods.values():
            for oc in other.classes.values():
                if any((_dotted(b) or "").split(".")[-1] == cname for b in oc.bases):
                    return False
        post = [x for x in cd.body if isinstance(x, ast.FunctionDef) and x.name == "__post_init__"]
        if not post or any(isinstance(n, (ast.Return, ast.Yield, ast.YieldFrom)) for n in ast.walk(post[0])):
            return False
        for n in ast.walk(post[0]):
            if isinstance(n, ast.Call) and _dotted(n.func) in ("object.__setattr__", "object.__delattr__", "setattr", "delattr"):
                names = self.c.name_values(self.c.mods[mod], post[0], n.args[1]) if len(n.args) > 1 else []
                if not names or f in names:
                    return False

        def exact(x: ast.AST, op: type[ast.cmpop]) -> bool:
            return (
                isinstance(x, ast.Compare)
                and len(x.ops) == 1
                and isinstance(x.ops[0], op)
                and isinstance(x.left, ast.Call)
                and _dotted(x.left.func) == "type"
                and len(x.left.args) == 1
                and ast.unparse(x.left.args[0]) == "self." + f
                and isinstance(x.comparators[0], ast.Name)
                and x.comparators[0].id in ("int", "float", "bool", "str", "bytes")
            )

        def disj(x: ast.AST) -> bool:
            return exact(x, ast.IsNot) or (isinstance(x, ast.BoolOp) and isinstance(x.op, ast.Or) and any(disj(v) for v in x.values))

        for s in post[0].body:
            if isinstance(s, ast.If) and s.body and all(isinstance(x, ast.Raise) for x in s.body) and disj(s.test):
                return True
        return False

    def iterators(self) -> None:
        for k in self.funcs:
            m, fn, _ = self.funcs[k]
            names = {x.id for x in ast.walk(fn) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store)}
            for n in ast.walk(fn):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in names and n.id in m.globals and n.id not in m.defs and n.id not in m.classes:
                    v = m.globals[n.id]
                    if isinstance(v, ast.GeneratorExp) or (isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id in ITERATOR_CALLS):
                        self.problems.add(f"{m.name}.py:{n.lineno}: module-level iterator read by reachable code: {n.id}")

    def run(self) -> _Persistence:
        while self.changed:
            self.changed = False
            self.rounds += 1
            for k in sorted(self.funcs):
                self.function(k)
            if self.rounds > 100:
                raise RuntimeError("persistence fixpoint did not converge")
        self.final = True
        for k in sorted(self.funcs):
            self.function(k)
        self.iterators()
        return self


def _import_time_classes(mods: dict[str, ParsedModule]) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()

    def cls_of(m: ParsedModule, node: ast.AST) -> tuple[str, str] | None:
        head = _dotted(node) or ""
        if head in m.classes:
            return (m.name, head)
        if head in m.imports and m.imports[head][0] == "project" and m.imports[head][1] in mods:
            imp_mod, imp_attr = m.imports[head][1], m.imports[head][2]
            if imp_mod and imp_attr and imp_attr in mods[imp_mod].classes:
                return (imp_mod, imp_attr)
        for mm in mods.values():
            for x in ast.walk(mm.tree):
                if isinstance(x, ast.ClassDef) and x.name == head and mm is m:
                    mm.classes.setdefault(head, x)
                    return (mm.name, head)
        return None

    def def_of(m: ParsedModule, node: ast.AST) -> tuple[ParsedModule, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        head = _dotted(node) or ""
        if head in m.defs:
            return (m, m.defs[head])
        if head in m.imports and m.imports[head][0] == "project" and m.imports[head][1] in mods:
            imp_mod, imp_attr = m.imports[head][1], m.imports[head][2]
            if imp_mod and imp_attr and imp_attr in mods[imp_mod].defs:
                tm = mods[imp_mod]
                return (tm, tm.defs[imp_attr])
        return None

    todo: list[tuple[ParsedModule, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    seen: set[int] = set()

    def scan_calls(m: ParsedModule, node: ast.AST) -> None:
        for x in ast.walk(node):
            if not isinstance(x, ast.Call):
                continue
            k = cls_of(m, x.func)
            if k:
                out.add(k)
                continue
            d = def_of(m, x.func)
            if d and id(d[1]) not in seen:
                seen.add(id(d[1]))
                todo.append(d)
            if isinstance(x.func, ast.Attribute):
                k = cls_of(m, x.func.value)
                if k:
                    out.add(k)
                    cd = mods[k[0]].classes.get(k[1])
                    for f in (cd.body if cd is not None else []):
                        if isinstance(f, ast.FunctionDef) and f.name == x.func.attr and id(f) not in seen:
                            seen.add(id(f))
                            todo.append((mods[k[0]], f))

    for m in mods.values():
        def visit(node: ast.AST) -> None:
            for ch in ast.iter_child_nodes(node):
                if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    for d in getattr(ch, "decorator_list", []) + list(ch.args.defaults) + [x for x in ch.args.kw_defaults if x is not None]:
                        scan_calls(m, d)
                    continue
                if isinstance(ch, ast.Call):
                    scan_calls(m, ch)
                visit(ch)

        visit(m.tree)
        for x in ast.walk(m.tree):
            if isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and x.func.attr == "__new__":
                for a in x.args:
                    k = cls_of(m, a)
                    if k:
                        out.add(k)
    while todo:
        m, f = todo.pop()
        for s in f.body:
            scan_calls(m, s)
    return out


_RUNTIME_HELPER = r"""
import importlib, importlib.util, json, pathlib, struct, sys, types

spec = json.loads(sys.stdin.read())
pkg_dir = pathlib.Path(spec["package_dir"])
pkg_name = spec["package_name"]
parent_dir = str(pkg_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

init_py = pkg_dir / "__init__.py"
if pkg_dir.name == pkg_name and init_py.is_file():
    importlib.import_module(pkg_name)
else:
    if init_py.is_file():
        s = importlib.util.spec_from_file_location(pkg_name, init_py, submodule_search_locations=[str(pkg_dir)])
        m = importlib.util.module_from_spec(s)
        sys.modules[pkg_name] = m
        s.loader.exec_module(m)
    else:
        pkg_mod = types.ModuleType(pkg_name)
        pkg_mod.__path__ = [str(pkg_dir)]
        pkg_mod.__package__ = pkg_name
        sys.modules[pkg_name] = pkg_mod

def frozen(v, d=0):
    if d > 64:
        return False
    if v is None or type(v) in (bool, int, float, complex, str, bytes, range):
        return True
    if type(v) in (tuple, frozenset):
        return all(frozen(x, d + 1) for x in v)
    if type(v) is struct.Struct or type(v) is types.GenericAlias:
        return True
    if type(v) is types.MappingProxyType:
        return all(frozen(k, d + 1) and frozen(x, d + 1) for k, x in v.items())
    return False

out = {}
try:
    for name, path in spec["overrides"].items():
        full = pkg_name + "." + name
        s = importlib.util.spec_from_file_location(full, path)
        m = importlib.util.module_from_spec(s)
        sys.modules[full] = m
        s.loader.exec_module(m)
    for name in spec["modules"]:
        m = importlib.import_module(pkg_name + "." + name)
        kinds = {}
        for n in spec["names"].get(name, []):
            if not hasattr(m, n):
                kinds[n] = "opaque"
                continue
            v = getattr(m, n)
            if frozen(v):
                kinds[n] = "frozen"
            elif type(v) in (dict, list, set) and all(frozen(x) for x in (list(v.items()) if type(v) is dict else v)):
                kinds[n] = "data"
            else:
                kinds[n] = "opaque"
        out[name] = kinds
    print(json.dumps({"ok": True, "kinds": out}))
except BaseException as e:
    print(json.dumps({"ok": False, "error": repr(e)[:300]}))
"""


def _runtime_kinds(
    mods: dict[str, ParsedModule],
    names: dict[str, list[str]],
    cfg: VerifierConfig,
) -> dict[str, Any]:
    overrides = {
        m: str(mod.path)
        for m, mod in mods.items()
        if Path(mod.path).resolve() != (cfg.package_dir / f"{m}.py").resolve()
    }
    spec = {
        "package_dir": str(cfg.package_dir),
        "package_name": cfg.package_name,
        "overrides": overrides,
        "modules": sorted(mods),
        "names": names,
    }
    proc = subprocess.run(
        [sys.executable, "-s", "-B", "-c", _RUNTIME_HELPER],
        input=json.dumps(spec),
        capture_output=True,
        text=True,
        timeout=cfg.timeout,
    )
    try:
        lines = proc.stdout.strip().splitlines()
        return json.loads(lines[-1]) if lines else {"ok": False, "error": "empty helper stdout"}
    except Exception:
        return {"ok": False, "error": "runtime helper failed: " + (proc.stderr or "")[-300:]}


def _std_attr_ok(module: str | None, attr: str | None, stdlib: Mapping[str, set[str] | None]) -> bool:
    if (module, attr) == ("contextlib", "contextmanager"):
        return True
    if module is None or attr is None:
        return False
    allowed = stdlib.get(module)
    return allowed is not None and attr in allowed


class _S1S2Closure:
    """Module-level categories (S1/S2) for the import closure."""

    def __init__(self, mods: dict[str, ParsedModule], cfg: VerifierConfig):
        self.mods = mods
        self.cfg = cfg
        self.problems: list[str] = []
        self.cat: dict[tuple[str, str], tuple[Any, ...]] = {}
        bindings: dict[str, dict[str, list[ast.AST | None]]] = {m: {} for m in mods}
        globals_: set[tuple[str, str]] = set()

        for m, mod in mods.items():
            for s in mod.tree.body:
                if _is_docstring(s) or isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if not _is_docstring(s):
                        bindings[m].setdefault(s.name, []).append(s)  # type: ignore[union-attr]
                    continue
                if isinstance(s, ast.Import):
                    for a in s.names:
                        bindings[m].setdefault(a.asname or a.name.split(".")[0], []).append(s)
                    continue
                if isinstance(s, ast.ImportFrom):
                    if any(a.name == "*" for a in s.names):
                        self.bad(mod, s, "S1 star import")
                        continue
                    if s.level and not s.module:
                        self.bad(mod, s, "S1 project module object import")
                        continue
                    if s.level > 1:
                        self.bad(mod, s, "S1 parent-package import")
                        continue
                    for a in s.names:
                        bindings[m].setdefault(a.asname or a.name, []).append(s)
                    continue
                if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                    bindings[m].setdefault(s.targets[0].id, []).append(s)
                    continue
                if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name) and s.value is not None:
                    bindings[m].setdefault(s.target.id, []).append(s)
                    continue
                self.bad(mod, s, "S1 module-level statement not allowed: " + type(s).__name__)
                for x in ast.walk(s):
                    if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store):
                        bindings[m].setdefault(x.id, []).append(None)
            for x in ast.walk(mod.tree):
                if isinstance(x, (ast.Global, ast.Nonlocal)):
                    globals_.update((m, n) for n in x.names)

        self.bindings = bindings
        assigned = {
            m: sorted(n for n, b in bs.items() if any(isinstance(s, (ast.Assign, ast.AnnAssign)) for s in b))
            for m, bs in bindings.items()
        }
        rt = _runtime_kinds(mods, assigned, cfg)
        self.runtime = rt
        if not rt.get("ok"):
            self.problems.append(f"closure: S2 import of the closure failed: {rt.get('error')}")
        kinds = rt.get("kinds", {})
        for m, bs in bindings.items():
            for n, b in bs.items():
                s = b[0]
                if None in b or (m, n) in globals_:
                    self.cat[(m, n)] = ("opaque", "bound outside S1 or through global")
                    continue
                if any(isinstance(x, (ast.Assign, ast.AnnAssign)) for x in b):
                    self.cat[(m, n)] = (kinds.get(m, {}).get(n, "opaque"),)
                    continue
                if len(b) != 1:
                    self.cat[(m, n)] = ("opaque", f"bound {len(b)} times")
                    continue
                if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.cat[(m, n)] = ("def", m, n)
                elif isinstance(s, ast.ClassDef):
                    self.cat[(m, n)] = ("class", m, n)
                elif isinstance(s, ast.Import):
                    self.cat[(m, n)] = ("stdmod", [a.name for a in s.names if (a.asname or a.name.split(".")[0]) == n][0])
                elif isinstance(s, ast.ImportFrom):
                    a = [a for a in s.names if (a.asname or a.name) == n][0]
                    self.cat[(m, n)] = ("proj", s.module, a.name) if s.level == 1 else ("stdattr", s.module, a.name)
                else:
                    self.cat[(m, n)] = (kinds.get(m, {}).get(n, "opaque"),)

    def bad(self, mod: ParsedModule, node: ast.AST, msg: str) -> None:
        self.problems.append(f"{Path(mod.path).name}:{getattr(node, 'lineno', 0)}: {msg}")

    def resolve(self, m: str, n: str, seen: set[tuple[str, str]] | None = None) -> tuple[Any, ...] | None:
        seen = seen or set()
        if (m, n) in seen:
            return ("opaque",)
        seen.add((m, n))
        c = self.cat.get((m, n))
        if c is None:
            return None
        if c[0] == "proj":
            if c[1] not in self.mods:
                return ("opaque",)
            return self.resolve(c[1], c[2], seen) or ("opaque",)
        if c[0] == "stdattr":
            if (c[1], c[2]) == ("__future__", "annotations"):
                return ("frozen",)
            return ("stdattr", c[1], c[2]) if _std_attr_ok(c[1], c[2], self.cfg.stdlib) else ("opaque",)
        if c[0] == "stdmod":
            return c if c[1] in self.cfg.stdlib else ("opaque",)
        return c


class _Scope:
    def __init__(
        self,
        node: ast.AST | None,
        parent: _Scope | None,
        kind: str,
        method_self: str | None = None,
        cls_param: str | None = None,
    ):
        self.node = node
        self.parent = parent
        self.kind = kind
        self.names: dict[str, list[tuple[Any, ...]]] = {}
        self.self_name = method_self
        self.cls_name = cls_param

    def lookup(self, n: str) -> tuple[_Scope | None, list[tuple[Any, ...]] | None]:
        s: _Scope | None = self
        while s is not None:
            if n in s.names:
                return s, s.names[n]
            s = s.parent
        return None, None


class _Subset:
    """S3-S9 formal restricted-subset verifier over the mention-closed graph W."""

    def __init__(
        self,
        mods: dict[str, ParsedModule],
        c3: _ReachClosure,
        live3: set[tuple[str, str]],
        cfg: VerifierConfig,
    ):
        self.mods = mods
        self.cfg = cfg
        self.cl = _S1S2Closure(mods, cfg)
        self.problems = list(self.cl.problems)
        self.c3 = c3
        self.funcs = c3.funcs
        self.class_methods: dict[tuple[str, str], list[tuple[str, str]]] = {}
        for k, (m, _, cname) in self.funcs.items():
            if cname:
                self.class_methods.setdefault((m.name, cname), []).append(k)
        self.live = set(live3)
        self.walked: set[tuple[str, str]] = set()
        self.parents: dict[int, ast.AST] = {}
        for mod in mods.values():
            for p in ast.walk(mod.tree):
                for ch in ast.iter_child_nodes(p):
                    self.parents[id(ch)] = p
        self.inprogress: set[tuple[Any, ...]] = set()

    def bad(self, m: ParsedModule, node: ast.AST, msg: str) -> None:
        self.problems.append(f"{Path(m.path).name}:{getattr(node, 'lineno', 0)}: {msg}")

    def class_node(self, key: tuple[str, str]) -> ast.ClassDef | None:
        mod = self.mods.get(key[0])
        return mod.classes.get(key[1]) if mod else None

    def instance_methods(self, attr: str) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        out: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        for key in self.live:
            cn = self.class_node(key)
            if cn is None:
                continue
            for f in cn.body:
                if (
                    isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and f.name == attr
                    and not any(isinstance(d, ast.Name) and d.id in ("classmethod", "staticmethod") for d in f.decorator_list)
                ):
                    out.append(f)
        return out

    def run(self) -> _Subset:
        todo = set(self.c3.reach) | {(m, q) for m, q in self.cfg.input_entries if (m, q) in self.funcs} | {
            e for e in self.cfg.entries if e in self.funcs
        }
        self.live |= set(self.cfg.input_classes)
        while True:
            for key in list(self.live):
                cn = self.class_node(key)
                if cn is None:
                    continue
                todo |= set(self.class_methods.get(key, []))
                for b in cn.bases:
                    if isinstance(b, ast.Name):
                        c = self.cl.resolve(key[0], b.id)
                        if c and c[0] == "class" and (c[1], c[2]) not in self.live:
                            self.live.add((c[1], c[2]))
            new = todo - self.walked
            if not new:
                break
            for k in sorted(new):
                if k not in self.funcs:
                    continue
                self.walked.add(k)
                self.walk_function(k)
            todo = set(self.walked)
            if not (todo - self.walked) and not self.pending_live():
                break
        for key in sorted(self.live):
            self.check_class(key)
        self.check_tables_everywhere()
        return self

    def pending_live(self) -> bool:
        return any(k not in self.walked for key in self.live for k in self.class_methods.get(key, []))

    def mention(self, c: tuple[Any, ...] | None) -> None:
        if c is None:
            return
        if c[0] == "def" and (c[1], c[2]) in self.funcs and (c[1], c[2]) not in self.walked:
            self.walked.add((c[1], c[2]))
            self.walk_function((c[1], c[2]))
        elif c[0] == "class":
            self.live.add((c[1], c[2]))

    def walk_function(self, key: tuple[str, str]) -> None:
        m, f, cname = self.funcs[key]
        method = cname is not None
        decos = list(f.decorator_list)
        for d in decos:
            self.check_decorator(m, d, method)
        is_static = any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in decos)
        is_cls = any(isinstance(d, ast.Name) and d.id == "classmethod" for d in decos)
        params = f.args.posonlyargs + f.args.args
        self_name = params[0].arg if method and params and not is_static and not is_cls else None
        cls_name = params[0].arg if method and params and is_cls else None
        if method and f.name.startswith("__") and f.name.endswith("__") and f.name not in DUNDER_DEFS_OK:
            self.bad(m, f, f"S8 dunder definition not allowed: {cname}.{f.name}")
        mod_scope = _Scope(None, None, "module")
        self.check_defaults(m, f, mod_scope)
        sc = _Scope(f, mod_scope, "function", self_name, cls_name)
        sc.names = _local_bindings(f)
        for s in f.body:
            self.visit(m, s, sc)

    def check_decorator(self, m: ParsedModule, d: ast.AST, method: bool) -> None:
        if isinstance(d, ast.Name) and d.id in METHOD_DECORATORS and method:
            return
        if isinstance(d, ast.Attribute) and d.attr in ("setter", "deleter") and isinstance(d.value, ast.Name) and method:
            return
        if isinstance(d, ast.Name):
            c = self.cl.resolve(m.name, d.id)
            if c and c[0] == "stdattr" and (c[1], c[2]) == ("contextlib", "contextmanager"):
                return
        self.bad(m, d, "S9 decorator not allowed: " + ast.unparse(d)[:60])

    def frozen_expr(self, m: ParsedModule, e: ast.AST, scope: _Scope) -> bool:
        if isinstance(e, ast.Constant):
            return True
        if isinstance(e, ast.Tuple):
            return all(self.frozen_expr(m, x, scope) for x in e.elts)
        if isinstance(e, ast.UnaryOp):
            return self.frozen_expr(m, e.operand, scope)
        if isinstance(e, ast.BinOp):
            return self.frozen_expr(m, e.left, scope) and self.frozen_expr(m, e.right, scope)
        if isinstance(e, ast.Name):
            c = self.cl.resolve(m.name, e.id)
            return bool(c) and c[0] in ("frozen", "def", "class")
        return False

    def check_defaults(self, m: ParsedModule, f: ast.FunctionDef | ast.AsyncFunctionDef, scope: _Scope) -> None:
        a = f.args
        for d in a.defaults + [x for x in a.kw_defaults if x is not None]:
            if not self.frozen_expr(m, d, scope):
                self.bad(m, d, "S9 default is not a frozen expression: " + ast.unparse(d)[:60])

    def visit(self, m: ParsedModule, n: ast.AST, sc: _Scope, parent: ast.AST | None = None) -> None:
        if isinstance(n, (ast.Global, ast.Nonlocal)):
            self.bad(m, n, "S5 global/nonlocal")
            return
        if isinstance(n, ast.ClassDef):
            self.bad(m, n, "S5 nested class definition")
            return
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in n.decorator_list:
                self.visit(m, d, sc, n)
                self.bad(m, d, "S9 decorator on nested function: " + ast.unparse(d)[:60])
            for d in n.args.defaults + [x for x in n.args.kw_defaults if x is not None]:
                self.visit(m, d, sc, n)
            self.annotations(m, n, sc)
            inner = _Scope(n, sc, "function", sc.self_name if sc.kind == "function" else None, sc.cls_name)
            inner.names = _local_bindings(n)
            inner.self_name = sc.self_name if sc.self_name and sc.self_name not in inner.names else None
            inner.cls_name = sc.cls_name if sc.cls_name and sc.cls_name not in inner.names else None
            for s in n.body:
                self.visit(m, s, inner, n)
            return
        if isinstance(n, ast.Lambda):
            for d in n.args.defaults + [x for x in n.args.kw_defaults if x is not None]:
                self.visit(m, d, sc, n)
            inner = _Scope(n, sc, "function")
            inner.names = _local_bindings(n)
            inner.self_name = sc.self_name if sc.self_name and sc.self_name not in inner.names else None
            inner.cls_name = sc.cls_name if sc.cls_name and sc.cls_name not in inner.names else None
            self.visit(m, n.body, inner, n)
            return
        if isinstance(n, COMPS):
            gens = n.generators
            self.visit(m, gens[0].iter, sc, n)
            inner = _Scope(n, sc, "comp")
            inner.self_name, inner.cls_name = sc.self_name, sc.cls_name
            for g in gens:
                for x in _target_names(g.target):
                    inner.names.setdefault(x, []).append(("for", g))
            if inner.self_name in inner.names:
                inner.self_name = None
            if inner.cls_name in inner.names:
                inner.cls_name = None
            for i, g in enumerate(gens):
                if i:
                    self.visit(m, g.iter, inner, n)
                self.visit(m, g.target, inner, g)
                for c in g.ifs:
                    self.visit(m, c, inner, n)
            for part in ((n.key, n.value) if isinstance(n, ast.DictComp) else (n.elt,)):
                self.visit(m, part, inner, n)
            return
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
            self.stores(m, n, sc)
        if isinstance(n, ast.Call):
            self.call(m, n, sc)
        if isinstance(n, ast.Attribute):
            self.attribute(m, n, sc)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            self.name(m, n, sc)
        if isinstance(n, ast.AnnAssign):
            self.visit(m, n.target, sc, n)
            if n.value is not None:
                self.visit(m, n.value, sc, n)
            if not self.future_annotations(m):
                self.visit(m, n.annotation, sc, n)
            return
        for c in ast.iter_child_nodes(n):
            self.visit(m, c, sc, n)

    def future_annotations(self, m: ParsedModule) -> bool:
        return any(
            isinstance(s, ast.ImportFrom) and s.module == "__future__" and any(a.name == "annotations" for a in s.names)
            for s in m.tree.body
        )

    def annotations(self, m: ParsedModule, f: ast.FunctionDef | ast.AsyncFunctionDef, sc: _Scope) -> None:
        if self.future_annotations(m):
            return
        a = f.args
        for x in a.posonlyargs + a.args + a.kwonlyargs + [v for v in (a.vararg, a.kwarg) if v]:
            if x.annotation is not None:
                self.visit(m, x.annotation, sc, f)
        if f.returns is not None:
            self.visit(m, f.returns, sc, f)

    def category(self, m: ParsedModule, name: str, sc: _Scope) -> tuple[Any, ...]:
        s, b = sc.lookup(name)
        if s is not None and b is not None:
            imp = [x for x in b if x[0] == "import"]
            if imp:
                if len(b) != 1:
                    return ("opaque",)
                n, al = imp[0][1], imp[0][2]
                if isinstance(n, ast.ImportFrom):
                    if n.level == 1 and n.module:
                        return self.cl.resolve(n.module, al.name) or ("opaque",)
                    if n.level:
                        return ("opaque",)
                    if (n.module, al.name) == ("__future__", "annotations"):
                        return ("frozen",)
                    return ("stdattr", n.module, al.name) if _std_attr_ok(n.module, al.name, self.cfg.stdlib) else ("opaque",)
                return ("stdmod", al.name) if al.name in self.cfg.stdlib else ("opaque",)
            return ("local", s, b)
        c = self.cl.resolve(m.name, name)
        if c is not None:
            return c
        return ("builtin", name)

    def parent(self, n: ast.AST) -> ast.AST | None:
        return self.parents.get(id(n))

    def read_position(self, n: ast.AST, mod: ParsedModule | None = None) -> bool:
        if self.direct_read(n):
            return True
        return mod is not None and self.flows_readonly(n, mod)

    def direct_read(self, n: ast.AST) -> bool:
        p = self.parent(n)
        if isinstance(p, ast.Subscript) and p.value is n:
            return isinstance(p.ctx, ast.Load) and not self.is_store_base(p)
        if isinstance(p, ast.Compare):
            if n in p.comparators:
                return all(isinstance(o, (ast.In, ast.NotIn, ast.Eq, ast.NotEq, ast.Is, ast.IsNot)) for o in p.ops)
            return all(isinstance(o, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)) for o in p.ops)
        if isinstance(p, (ast.For, ast.AsyncFor)) and p.iter is n:
            return True
        if isinstance(p, ast.comprehension) and p.iter is n:
            return True
        if isinstance(p, ast.Call) and n in p.args and isinstance(p.func, ast.Name) and p.func.id in READ_CALLS:
            return True
        if (
            isinstance(p, ast.Call)
            and p.args[:1] == [n]
            and isinstance(p.func, ast.Attribute)
            and isinstance(p.func.value, ast.Name)
        ):
            mod_name = self.std_module_name(p.func.value)
            if mod_name and (mod_name, p.func.attr) in STD_READ_CALLS:
                return True
        if isinstance(p, ast.Attribute) and p.value is n and p.attr in READ_METHODS:
            q = self.parent(p)
            return isinstance(q, ast.Call) and q.func is p
        if isinstance(p, ast.Starred):
            q = self.parent(p)
            return isinstance(q, (ast.Call, ast.List, ast.Tuple, ast.Set)) and not isinstance(getattr(q, "ctx", None), ast.Store)
        if isinstance(p, ast.Dict) and n in p.values and p.keys[p.values.index(n)] is None:
            return True
        return False

    def std_module_name(self, e: ast.Name) -> str | None:
        mod = self.module_of(e)
        if mod is None:
            return None
        c = self.cl.resolve(mod.name, e.id)
        return c[1] if c and c[0] == "stdmod" else None

    def module_of(self, node: ast.AST) -> ParsedModule | None:
        top = node
        while self.parents.get(id(top)) is not None:
            top = self.parents[id(top)]
        for mod in self.mods.values():
            if mod.tree is top:
                return mod
        return None

    def is_store_base(self, n: ast.AST) -> bool:
        p = self.parent(n)
        return isinstance(p, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)) and (
            n in getattr(p, "targets", []) or getattr(p, "target", None) is n
        )

    def name(self, m: ParsedModule, n: ast.Name, sc: _Scope) -> None:
        c = self.category(m, n.id, sc)
        k = c[0]
        if k == "class" or (k == "local" and sc.cls_name and n.id == sc.cls_name):
            if not self.class_value_ok(m, n, sc):
                self.bad(m, n, f"S7 class object {n.id} used as a value")
        if k == "local" or k in ("def", "class", "frozen", "stdattr"):
            self.mention(c if k in ("def", "class") else None)
            return
        if k == "data":
            if not self.read_position(n, m):
                self.bad(m, n, f"S4 module data {n.id} used outside a read-only position")
            return
        if k == "stdmod":
            p = self.parent(n)
            if not (isinstance(p, ast.Attribute) and p.value is n):
                self.bad(m, n, f"S3 module object {n.id} used as a value")
            return
        if k == "builtin":
            if n.id in self.cfg.builtins_ok:
                return
            if n.id in SPECIAL_BUILTINS:
                p = self.parent(n)
                if n.id == "object" and isinstance(p, ast.Attribute) and p.value is n and p.attr in ("__setattr__", "__delattr__"):
                    return
                if n.id == "type" and isinstance(p, ast.Call) and p.func is n and len(p.args) == 1 and not p.keywords:
                    return
                if n.id == "super" and isinstance(p, ast.Call) and p.func is n and not p.args and not p.keywords:
                    return
                if n.id in ("getattr", "setattr", "hasattr", "delattr") and isinstance(p, ast.Call) and p.func is n:
                    return
                self.bad(m, n, f"S3 builtin {n.id} only in its allowed form")
                return
            self.bad(m, n, f"S3 name not allowed in verified code: {n.id}")
            return
        detail = ", ".join(map(str, c[1:])) or k
        self.bad(m, n, f"S3 opaque module-level name {n.id} ({detail})")

    def attribute(self, m: ParsedModule, n: ast.Attribute, sc: _Scope) -> None:
        a = n.attr
        if a in BANNED_ATTRS:
            self.bad(m, n, "S6 attribute not allowed: ." + a)
            return
        if a in TABLE_ATTRS:
            if not isinstance(n.ctx, ast.Load) or not self.read_position(n, m):
                self.bad(m, n, f"S4 class table .{a} used outside a read-only position")
            return
        if a == "__getattribute__":
            p = self.parent(n)
            if not (isinstance(p, ast.Call) and p.func is n and len(p.args) == 1 and not p.keywords and self.safe_attr_name(m, p.args[0], sc)):
                self.bad(m, n, "S6 .__getattribute__ only called with a literal non-dunder name")
            return
        if a.startswith("__") and a.endswith("__"):
            if a not in DUNDER_ATTRS_OK:
                self.bad(m, n, "S6 dunder attribute not allowed: ." + a)
                return
            if a in ("__setattr__", "__delattr__", "__init__"):
                p = self.parent(n)
                if not (isinstance(p, ast.Call) and p.func is n):
                    self.bad(m, n, f"S6 .{a} only called directly")
                    return
                v = n.value
                if a == "__init__" and isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "super" and not v.args:
                    return
                if not (p.args and isinstance(p.args[0], ast.Name) and sc.self_name and p.args[0].id == sc.self_name):
                    self.bad(m, n, f"S6 .{a}(...) only on the method self")
                elif a != "__init__" and not (isinstance(v, ast.Name) and v.id == "object"):
                    self.bad(m, n, f"S6 .{a} only as object.{a}(self, ...)")
            return
        base = self.class_ref(m, n.value, sc)
        if base and self.instance_methods(a):
            p = self.parent(n)
            ok = isinstance(p, ast.Call) and p.func is n and bool(p.args) and isinstance(p.args[0], ast.Name) and bool(sc.self_name) and p.args[0].id == sc.self_name
            if not ok:
                self.bad(m, n, f"S7 unbound instance method {ast.unparse(n.value)[:30]}.{a} not called with self")
        if isinstance(n.value, ast.Name):
            c = self.category(m, n.value.id, sc)
            if c[0] == "stdmod":
                top = c[1]
                if top != "ctypes" and not _std_attr_ok(top, a, self.cfg.stdlib):
                    self.bad(m, n, f"S3 stdlib attribute not allowed: {c[1]}.{a}")
                ctypes_allowed = self.cfg.stdlib.get("ctypes") or set()
                if top == "ctypes" and (a not in ctypes_allowed or (a == "CDLL" and not (isinstance(sc.node, ast.FunctionDef) and sc.node.name == "__init__"))):
                    self.bad(m, n, "S3 ctypes attribute not allowed in verified code: ctypes." + a)

    def class_ref(self, m: ParsedModule, e: ast.AST, sc: _Scope) -> bool:
        if isinstance(e, ast.Name):
            if sc.cls_name and e.id == sc.cls_name:
                return True
            c = self.category(m, e.id, sc)
            return c[0] == "class"
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == "type":
            return True
        return False

    def fresh_local(self, m: ParsedModule, name: str, sc: _Scope) -> bool:
        s, b = sc.lookup(name)
        if s is None or b is None or (s is not sc and s.kind != "function"):
            return False
        for src in b:
            if src[0] != "assign":
                return False
            v = src[1].value
            if not isinstance(v, ast.Call):
                return False
            f = v.func
            if isinstance(f, ast.Name):
                c = self.category(m, f.id, sc)
                if c[0] == "class" or (c[0] == "builtin" and f.id in EMPTY_FACTORIES | {"dict", "object"}):
                    continue
                return False
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                c = self.category(m, f.value.id, sc)
                if c[0] == "stdmod" and c[1] == "ctypes":
                    continue
            return False
        return True

    def safe_attr_name(self, m: ParsedModule, e: ast.AST, sc: _Scope) -> bool:
        def ok(v: Any) -> bool:
            return isinstance(v, str) and not v.startswith("__") and v not in BANNED_ATTRS and v not in TABLE_ATTRS

        if isinstance(e, ast.Constant):
            return ok(e.value)
        if not isinstance(e, ast.Name):
            return False
        s, b = sc.lookup(e.id)
        if s is None or b is None or len(b) != 1 or b[0][0] != "for":
            return False
        g = b[0][1]
        it = g.iter
        return isinstance(g.target, ast.Name) and isinstance(it, (ast.Tuple, ast.List)) and all(isinstance(x, ast.Constant) and ok(x.value) for x in it.elts)

    def ctor_param(self, m: ParsedModule, name: str, sc: _Scope) -> bool:
        s, b = sc.lookup(name)
        if s is None or s.kind != "function" or not b or any(x[0] != "assign" for x in b):
            return False
        f = s.node
        if not isinstance(f, ast.FunctionDef) or f.name not in m.defs or m.defs[f.name] is not f:
            return False
        pos = [x.arg for x in f.args.posonlyargs + f.args.args]
        for src in b:
            v = src[1].value
            if not (isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id in pos and len(s.names.get(v.func.id, [])) == 1):
                return False
            if not self.callers_pass_classes(m, f.name, pos.index(v.func.id), v.func.id):
                return False
        return True

    def callers_pass_classes(self, m: ParsedModule, fname: str, index: int, pname: str) -> bool:
        refs = 0
        for mod in self.mods.values():
            for x in ast.walk(mod.tree):
                if not (isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)):
                    continue
                c = self.cl.resolve(mod.name, x.id)
                if c != ("def", m.name, fname):
                    continue
                fe = self.enclosing_function(x)
                if isinstance(fe, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and x.id in _local_bindings(fe):
                    continue
                refs += 1
                p = self.parent(x)
                if not (isinstance(p, ast.Call) and p.func is x):
                    return False
                arg = p.args[index] if index < len(p.args) else next((k.value for k in p.keywords if k.arg == pname), None)
                if isinstance(arg, ast.Name) and (self.cl.resolve(mod.name, arg.id) or ("",))[0] == "class":
                    continue
                if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and self.cl.resolve(mod.name, arg.value.id) == ("stdmod", "ctypes"):
                    continue
                return False
        return refs > 0

    def store_target_ok(self, m: ParsedModule, base: ast.AST, sc: _Scope) -> bool:
        if isinstance(base, ast.Name):
            if sc.self_name and base.id == sc.self_name:
                return True
            return self.fresh_local(m, base.id, sc) or self.ctor_param(m, base.id, sc)
        return False

    def ctypes_signature(self, m: ParsedModule, x: ast.Attribute, sc: _Scope) -> bool:
        if x.attr not in ("argtypes", "restype") or m.name not in self.cfg.wrapper_modules:
            return False
        if not (isinstance(sc.node, ast.FunctionDef) and sc.node.name == "__init__" and sc.self_name):
            return False
        v = x.value
        if isinstance(v, ast.Attribute) and isinstance(v.value, ast.Name) and v.value.id == sc.self_name:
            return True
        if isinstance(v, ast.Name):
            s, b = sc.lookup(v.id)
            return s is sc and b is not None and all(src[0] == "assign" and self.self_chain(src[1].value, sc.self_name, 2) for src in b)
        return False

    @staticmethod
    def self_chain(e: ast.AST, self_name: str, depth: int) -> bool:
        k = 0
        while isinstance(e, ast.Attribute):
            e, k = e.value, k + 1
        return isinstance(e, ast.Name) and e.id == self_name and k >= depth

    def stores(self, m: ParsedModule, n: ast.AST, sc: _Scope) -> None:
        targets = n.targets if isinstance(n, (ast.Assign, ast.Delete)) else [n.target]  # type: ignore[attr-defined]
        for t in targets:
            for x in ast.walk(t):
                if (
                    isinstance(x, ast.Attribute)
                    and isinstance(x.ctx, (ast.Store, ast.Del))
                    and not self.store_target_ok(m, x.value, sc)
                    and not self.ctypes_signature(m, x, sc)
                ):
                    self.bad(m, x, "S5 attribute store only on the method self or a fresh local: " + ast.unparse(x)[:60])

    def class_value_ok(self, m: ParsedModule, n: ast.AST, sc: _Scope) -> bool:
        if isinstance(n, ast.Name) and self.flowable_class(m, n.id, sc):
            return True
        p = self.parent(n)
        if isinstance(p, ast.Call) and p.func is n:
            return True
        if isinstance(p, ast.Attribute) and p.value is n:
            return True
        if isinstance(p, ast.Compare):
            return True
        q = p
        if isinstance(q, ast.Tuple) and isinstance(getattr(q, "ctx", None), ast.Load):
            q = self.parent(q)
        if isinstance(q, ast.Call) and isinstance(q.func, ast.Name) and q.func.id in ("isinstance", "issubclass") and len(q.args) == 2 and (q.args[1] is n or q.args[1] is p):
            return True
        if isinstance(q, ast.ExceptHandler) and (q.type is n or q.type is p):
            return True
        if isinstance(p, ast.Raise) and p.exc is n:
            return True
        if isinstance(p, ast.Call) and n in p.args:
            d = self.project_def(m, p.func)
            if d is not None:
                pos = d[1].args.posonlyargs + d[1].args.args
                i = p.args.index(n)
                return i < len(pos) and self.param_class_ok(d[0], d[1], pos[i].arg)
        return False

    def flowable_class(self, m: ParsedModule, name: str, sc: _Scope) -> bool:
        c = self.category(m, name, sc)
        if c[0] != "class":
            return False
        seen: set[tuple[str, str]] = set()
        todo = [(c[1], c[2])]
        while todo:
            key = todo.pop()
            if key in seen:
                continue
            seen.add(key)
            cn = self.class_node(key)
            if cn is None:
                return False
            for f in cn.body:
                if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and not any(
                    isinstance(d, ast.Name) and d.id in ("classmethod", "staticmethod") for d in f.decorator_list
                ):
                    return False
            for b in cn.bases:
                if isinstance(b, ast.Name):
                    bc = self.cl.resolve(key[0], b.id)
                    if bc and bc[0] == "class":
                        todo.append((bc[1], bc[2]))
                    elif bc is not None or b.id not in BASES_OK:
                        return False
        return True

    def param_class_ok(self, mod: ParsedModule, f: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
        key = ("cls", id(f), name)
        if key in self.inprogress:
            return True
        self.inprogress.add(key)
        try:
            if len(_local_bindings(f).get(name, [])) != 1:
                return False
            sc = _Scope(f, _Scope(None, None, "module"), "function")
            sc.names = _local_bindings(f)
            for x in ast.walk(f):
                if isinstance(x, ast.Name) and x.id == name and isinstance(x.ctx, ast.Load) and not self.shadowed_in(f, x):
                    p = self.parent(x)
                    if isinstance(p, ast.Attribute) and p.value is x and self.instance_methods(p.attr):
                        return False
                    if not self.class_value_ok(mod, x, sc):
                        return False
            return True
        finally:
            self.inprogress.discard(key)

    def call(self, m: ParsedModule, n: ast.Call, sc: _Scope) -> None:
        f = n.func
        if isinstance(f, ast.Name) and f.id == "type" and self.category(m, f.id, sc)[0] == "builtin" and not self.class_value_ok(m, n, sc):
            self.bad(m, n, "S7 type(...) result used as a value")
        if isinstance(f, ast.Name) and f.id in ("setattr", "delattr") and self.category(m, f.id, sc)[0] == "builtin":
            if not (n.args and self.store_target_ok(m, n.args[0], sc)):
                self.bad(m, n, f"S5 {f.id} only on the method self or a fresh local")
        if isinstance(f, ast.Name) and f.id in ("getattr", "hasattr") and self.category(m, f.id, sc)[0] == "builtin" and len(n.args) >= 2:
            name = n.args[1]
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                v = name.value
                if v in BANNED_ATTRS or v in TABLE_ATTRS or (v.startswith("__") and v != "__name__"):
                    self.bad(m, n, f"S6 getattr of {v!r}")
                elif self.class_ref(m, n.args[0], sc) and self.instance_methods(v):
                    self.bad(m, n, f"S7 getattr of unbound instance method {v!r}")
            elif self.class_ref(m, n.args[0], sc) or self.module_ref(m, n.args[0], sc):
                self.bad(m, n, "S3 dynamic getattr on a class or module")

    def module_ref(self, m: ParsedModule, e: ast.AST, sc: _Scope) -> bool:
        return isinstance(e, ast.Name) and self.category(m, e.id, sc)[0] == "stdmod"

    def check_class(self, key: tuple[str, str]) -> None:
        m = self.mods.get(key[0])
        cn = self.class_node(key)
        if m is None or cn is None:
            return
        for kw in cn.keywords:
            self.bad(m, cn, f"S8 class keyword not allowed: {kw.arg}")
        for d in cn.decorator_list:
            ok = isinstance(d, ast.Name) and self.cl.resolve(m.name, d.id) == ("stdattr", "dataclasses", "dataclass")
            ok = ok or (
                isinstance(d, ast.Call)
                and isinstance(d.func, ast.Name)
                and self.cl.resolve(m.name, d.func.id) == ("stdattr", "dataclasses", "dataclass")
                and not d.args
                and all(isinstance(k.value, ast.Constant) for k in d.keywords)
            )
            if not ok:
                self.bad(m, d, "S8 class decorator not allowed: " + ast.unparse(d)[:60])
        structure = False
        for b in cn.bases:
            if isinstance(b, ast.Name):
                c = self.cl.resolve(m.name, b.id)
                if c and c[0] == "class":
                    continue
                if c is None and b.id in BASES_OK:
                    continue
            if isinstance(b, ast.Attribute) and b.attr == "Structure" and isinstance(b.value, ast.Name) and (self.cl.resolve(m.name, b.value.id) or ("",))[0] == "stdmod":
                structure = True
                continue
            self.bad(m, b, "S8 base class not allowed: " + ast.unparse(b)[:60])
        sc = _Scope(None, None, "module")
        for s in cn.body:
            if _is_docstring(s) or isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                t = s.targets[0].id
                if t == "__slots__" and isinstance(s.value, ast.Tuple) and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in s.value.elts):
                    continue
                if t == "_fields_" and structure:
                    continue
                if self.frozen_expr(m, s.value, sc):
                    continue
            if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name):
                if s.value is None or self.frozen_expr(m, s.value, sc) or self.field_ok(m, s.value):
                    continue
            self.bad(m, s, f"S8 class body statement not allowed in {key[1]}: {ast.unparse(s)[:70]}")

    def field_ok(self, m: ParsedModule, v: ast.AST) -> bool:
        if not (isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and self.cl.resolve(m.name, v.func.id) == ("stdattr", "dataclasses", "field") and not v.args):
            return False
        for k in v.keywords:
            if k.arg == "default" and self.frozen_expr(m, k.value, _Scope(None, None, "module")):
                continue
            if k.arg == "default_factory" and isinstance(k.value, ast.Name) and k.value.id in EMPTY_FACTORIES and self.cl.resolve(m.name, k.value.id) is None:
                continue
            if k.arg in ("init", "repr", "compare", "hash", "kw_only") and isinstance(k.value, ast.Constant):
                continue
            return False
        return True

    def check_tables_everywhere(self) -> None:
        walked_nodes = {id(self.funcs[k][1]) for k in self.walked}
        for mname, mod in self.mods.items():
            data = {n for (mm, n), _ in self.cl.cat.items() if mm == mname and (self.cl.resolve(mm, n) or ("",))[0] == "data"}
            for top in mod.tree.body:
                if id(top) in walked_nodes:
                    continue
                if isinstance(top, ast.ClassDef):
                    units: list[ast.AST] = [x for x in top.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) and id(x) not in walked_nodes]
                    units += [x for x in top.body if not isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))]
                else:
                    units = [top]
                for u in units:
                    self.scan_readonly(mod, u, data)

    def scan_readonly(self, mod: ParsedModule, unit: ast.AST, data: set[str]) -> None:
        parents = self.parents
        for x in ast.walk(unit):
            if isinstance(x, ast.Name) and x.id in data and not self.shadowed(x, parents):
                if isinstance(x.ctx, ast.Store) and parents.get(id(x)) is unit:
                    continue
                if not isinstance(x.ctx, ast.Load) or not self.read_position(x, mod):
                    self.bad(mod, x, f"S4 module data {x.id} used outside a read-only position (closure-wide)")
            if isinstance(x, ast.Attribute) and x.attr in TABLE_ATTRS and (not isinstance(x.ctx, ast.Load) or not self.read_position(x, mod)):
                self.bad(mod, x, f"S4 class table .{x.attr} used outside a read-only position (closure-wide)")

    def enclosing_function(self, n: ast.AST) -> ast.AST | None:
        p = self.parents.get(id(n))
        while p is not None and not isinstance(p, FUNCS):
            p = self.parents.get(id(p))
        return p

    def project_def(self, mod: ParsedModule, e: ast.AST) -> tuple[ParsedModule, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        if not isinstance(e, ast.Name):
            return None
        f = self.enclosing_function(e)
        if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and e.id in _local_bindings(f):
            return None
        c = self.cl.resolve(mod.name, e.id)
        if c and c[0] == "def" and c[1] in self.mods and c[2] in self.mods[c[1]].defs:
            return self.mods[c[1]], self.mods[c[1]].defs[c[2]]
        return None

    def param_readonly(self, mod: ParsedModule, f: ast.FunctionDef | ast.AsyncFunctionDef, index: int | None = None, kw: str | None = None) -> bool:
        a = f.args
        pos = a.posonlyargs + a.args
        if kw is not None:
            names = [x.arg for x in pos + a.kwonlyargs if x.arg == kw]
            if not names:
                return False
            name = names[0]
        else:
            if index is None or index >= len(pos):
                return False
            name = pos[index].arg
        return self.local_readonly(mod, f, name)

    def local_readonly(self, mod: ParsedModule, f: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
        key = (id(f), name)
        if key in self.inprogress:
            return True
        self.inprogress.add(key)
        try:
            return self._local_readonly(mod, f, name)
        finally:
            self.inprogress.discard(key)

    def _local_readonly(self, mod: ParsedModule, f: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
        b = _local_bindings(f).get(name, [])
        for src in b:
            if src[0] == "param":
                continue
            if src[0] != "assign" or not self.alias_value(mod, src[1].value, name):
                return False
        for x in ast.walk(f):
            if isinstance(x, ast.Name) and x.id == name and isinstance(x.ctx, ast.Load) and not self.shadowed_in(f, x):
                if not self.read_position(x, mod):
                    return False
        return True

    def alias_value(self, mod: ParsedModule, v: ast.AST, name: str) -> bool:
        if isinstance(v, ast.IfExp):
            return self.alias_value(mod, v.body, name) and self.alias_value(mod, v.orelse, name)
        if isinstance(v, ast.BoolOp):
            return all(self.alias_value(mod, x, name) for x in v.values)
        if isinstance(v, ast.Constant):
            return True
        if isinstance(v, ast.Name):
            if v.id == name:
                return True
            return (self.cl.resolve(mod.name, v.id) or ("",))[0] in ("data", "frozen")
        return False

    def shadowed_in(self, f: ast.AST, x: ast.Name) -> bool:
        p = self.parents.get(id(x))
        while p is not None and p is not f:
            if isinstance(p, FUNCS) and x.id in _local_bindings(p):
                return True
            if isinstance(p, COMPS) and any(x.id in _target_names(g.target) for g in p.generators):
                return True
            p = self.parents.get(id(p))
        return False

    def flows_readonly(self, n: ast.AST, mod: ParsedModule) -> bool:
        p = self.parent(n)
        if isinstance(p, ast.keyword):
            q = self.parent(p)
            if isinstance(q, ast.Call) and p.arg:
                d = self.project_def(mod, q.func)
                return d is not None and self.param_readonly(d[0], d[1], kw=p.arg)
            return False
        if isinstance(p, ast.Call) and n in p.args:
            d = self.project_def(mod, p.func)
            return d is not None and self.param_readonly(d[0], d[1], index=p.args.index(n))
        q, child = p, n
        while isinstance(q, (ast.IfExp, ast.BoolOp)) and child is not getattr(q, "test", None):
            child, q = q, self.parent(q)
        if child is not n and isinstance(q, ast.Assign) and q.value is child and len(q.targets) == 1 and isinstance(q.targets[0], ast.Name):
            f = self.enclosing_function(q)
            return isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and self.local_readonly(mod, f, q.targets[0].id)
        return False

    def shadowed(self, x: ast.Name, parents: dict[int, ast.AST]) -> bool:
        p = parents.get(id(x))
        while p is not None:
            if isinstance(p, FUNCS) and x.id in _local_bindings(p):
                return True
            if isinstance(p, COMPS) and any(x.id in _target_names(g.target) for g in p.generators):
                return True
            p = parents.get(id(p))
        return False


def _reachable_classes(c: _ReachClosure) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for mod, name in c.reach:
        if "." not in name:
            continue
        out.add((mod, name.split(".")[0]))
    return out


def verify_package_purity(
    package_dir: Path,
    package_name: str,
    entries: Sequence[tuple[str, str]],
    *,
    input_entries: Sequence[tuple[str, str]] = (),
    input_classes: Sequence[tuple[str, str]] = (),
    wrapper_modules: AbstractSet[str] = frozenset(),
    entry_params: AbstractSet[str] | None = None,
    allowed_stdlib: Mapping[str, AbstractSet[str] | None] | None = None,
    allowed_builtins: AbstractSet[str] | None = None,
    extra_seeds: Sequence[str] = (),
    overrides: Mapping[str, Path] | None = None,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Verify S1-S9 purity and statelessness over ``entries`` in ``package_dir``."""
    pkg_dir = Path(package_dir).resolve()
    entry_tuple = tuple((str(m), str(f)) for m, f in entries)
    if not entry_tuple:
        raise ValueError("at least one entry point (module, function) is required")

    stdlib_map: dict[str, set[str] | None] = (
        {k: (set(v) if v is not None else None) for k, v in DEFAULT_STDLIB.items()}
        if allowed_stdlib is None
        else {k: (set(v) if v is not None else None) for k, v in allowed_stdlib.items()}
    )
    builtins_set = frozenset(BUILTINS_OK if allowed_builtins is None else allowed_builtins)

    cfg = VerifierConfig(
        package_dir=pkg_dir,
        package_name=package_name,
        entries=entry_tuple,
        input_entries=tuple((str(m), str(f)) for m, f in input_entries),
        input_classes=tuple((str(m), str(c)) for m, c in input_classes),
        wrapper_modules=frozenset(wrapper_modules),
        entry_params=frozenset(entry_params) if entry_params is not None else None,
        stdlib=stdlib_map,
        builtins_ok=builtins_set,
        timeout=timeout,
    )

    seeds = list(
        dict.fromkeys(
            [m for m, _ in cfg.entries]
            + [m for m, _ in cfg.input_entries]
            + [m for m, _ in cfg.input_classes]
            + list(extra_seeds)
        )
    )
    mods = load_closure(pkg_dir, seeds, overrides=overrides)
    _harden_modules(mods)
    extra = _import_time_classes(mods)

    while True:
        c = _ReachClosure(mods, cfg)
        inp = c.walk([k for k in cfg.input_entries if k in c.funcs], set(cfg.input_classes) | extra, rules=False)
        live = set(cfg.input_classes) | extra | inp.constructed | inp.live
        while True:
            c.walk(list(cfg.entries), live, rules=True)
            if c.live <= live:
                break
            live |= c.live
        more = _reachable_classes(c) - live - extra
        if not more:
            break
        extra |= more

    missing_entries = [f"{m}.{fn}" for m, fn in cfg.entries if (m, fn) not in c.funcs]
    persistence = _Persistence(c, live).run()
    r3_problems = list(c.problems) + sorted(persistence.problems)

    subset = _Subset(mods, c, live, cfg).run()
    all_problems = [f"missing entry point: {e}" for e in missing_entries] + r3_problems + sorted(set(subset.problems))
    # Deduplicate while preserving order
    problems = list(dict.fromkeys(all_problems))

    return {
        "schema": "sim-verify-purity-verifier-v1",
        "status": "PASS" if not problems else "FAIL",
        "package_name": package_name,
        "package_dir": str(pkg_dir),
        "entries": [f"{m}.{fn}" for m, fn in cfg.entries],
        "modules": sorted(mods),
        "reachable_functions": len(c.reach),
        "walked_functions": len(subset.walked),
        "live_classes": sorted(f"{m}.{cls}" for m, cls in subset.live),
        "module_data": {
            f"{m}.{n}": v[0]
            for (m, n), v in sorted(subset.cl.cat.items())
            if v[0] in ("frozen", "data", "opaque")
        },
        "runtime_import_ok": bool(subset.cl.runtime.get("ok")),
        "persistence_rounds": persistence.rounds,
        "problems": problems,
    }


def _parse_entry(spec: str) -> tuple[str, str]:
    if ":" in spec:
        mod, fn = spec.split(":", 1)
    elif "." in spec:
        mod, fn = spec.split(".", 1)
    else:
        raise argparse.ArgumentTypeError(f"entry must be MODULE:FUNC or MODULE.FUNC, got {spec!r}")
    return mod.strip(), fn.strip()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify S1-S9 package purity and statelessness.")
    parser.add_argument("--package-dir", type=Path, required=True)
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--entry", action="append", required=True, help="Entry function as MODULE:FUNC")
    parser.add_argument("--input-entry", action="append", default=[], help="Input builder as MODULE:FUNC")
    parser.add_argument("--input-class", action="append", default=[], help="Input class as MODULE:CLASS")
    parser.add_argument("--wrapper", action="append", default=[], help="Wrapper module allowed to use ctypes")
    parser.add_argument("--report", type=Path, help="Optional JSON report output path")
    args = parser.parse_args(argv)

    result = verify_package_purity(
        args.package_dir,
        args.package_name,
        [_parse_entry(x) for x in args.entry],
        input_entries=[_parse_entry(x) for x in args.input_entry],
        input_classes=[_parse_entry(x) for x in args.input_class],
        wrapper_modules=frozenset(args.wrapper),
    )
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "status": result["status"],
                "modules": len(result["modules"]),
                "walked_functions": result["walked_functions"],
                "live_classes": len(result["live_classes"]),
                "problems": len(result["problems"]),
            }
        )
    )
    for p in result["problems"][:100]:
        print(" ", p, file=sys.stderr)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
