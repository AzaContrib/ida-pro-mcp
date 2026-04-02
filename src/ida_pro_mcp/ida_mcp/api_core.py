"""Core API Functions - IDB metadata and basic queries"""

import re
import sre_parse
import time
from typing import Annotated, Any, NotRequired, TypedDict

import ida_auto
import idaapi
import ida_bytes
import ida_funcs
import ida_hexrays
import idautils
import ida_loader
import ida_nalt
import ida_typeinf
import idc

from . import compat

from .rpc import tool
from .sync import idasync
from .utils import (
    ConvertedNumber,
    EntityQuery,
    Function,
    FunctionQuery,
    Global,
    Import,
    ListQuery,
    NumberConversion,
    Page,
    ImportQuery,
    get_function,
    normalize_dict_list,
    normalize_list_input,
    parse_address,
    paginate,
    pattern_filter,
)


class ServerHealthResult(TypedDict):
    status: str
    uptime_sec: float
    idb_path: str | None
    module: str
    input_path: str
    imagebase: str
    auto_analysis_ready: bool | None
    hexrays_ready: bool
    strings_cache_ready: bool
    strings_cache_size: int


class ServerWarmupStep(TypedDict, total=False):
    step: str
    ok: bool
    ms: float
    error: str


class ServerWarmupResult(TypedDict):
    ok: bool
    steps: list[ServerWarmupStep]
    health: ServerHealthResult


class LookupFuncResult(TypedDict):
    query: str
    fn: Function | None
    error: str | None


class IntConvertResult(TypedDict):
    input: str
    result: ConvertedNumber | None
    error: str | None


class FunctionQueryRow(Function, total=False):
    has_type: bool
    size_int: int


class FunctionQueryPage(TypedDict, total=False):
    data: list[FunctionQueryRow]
    next_offset: int | None
    error: str | None


class EntityQueryPage(TypedDict, total=False):
    kind: str
    data: list[dict[str, Any]]
    next_offset: int | None
    total: int
    error: str | None


class ImportsQueryPage(TypedDict):
    data: list[Import]
    next_offset: int | None


class IdbSaveResult(TypedDict):
    ok: bool
    path: str | None
    error: NotRequired[str]


class FindRegexResult(TypedDict, total=False):
    n: int
    matches: list[dict[str, Any]]
    cursor: dict[str, Any]
    error: str | None


# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None
_server_started_at = time.time()


def _get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access."""
    global _strings_cache
    if _strings_cache is None:
        _strings_cache = [(s.ea, str(s)) for s in idautils.Strings() if s is not None]
    return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    _strings_cache = None


# ============================================================================
# Encoded-string binary search helpers
# ============================================================================

# Maximum bytes to scan backwards from a binary-search hit to find the start
# of the enclosing string.  1 024 bytes == 512 UTF-16 chars, which is a
# generous upper bound for a single string literal.
_STR_LOOKBACK_BYTES = 1024

# IDA string-type constant for 4-byte-char C strings (UTF-32LE).
# Guarded with getattr for older IDA builds that may not expose it.
_STRTYPE_C_32 = getattr(ida_nalt, "STRTYPE_C_32", 0x50000000)

# Per-mode config: (python_codec, IDA_strtype, char_size_bytes)
# "UTF-8" is handled separately via the IDA string cache.
_ENCODING_CONFIGS: dict[str, tuple[str, int, int]] = {
    "UTF-16LE":    ("utf-16-le", ida_nalt.STRTYPE_C_16, 2),
    "UTF-32LE":    ("utf-32-le", _STRTYPE_C_32,         4),
    "windows-1252": ("cp1252",   ida_nalt.STRTYPE_C,     1),
}


def _extract_longest_literal(pattern: str) -> str:
    """Extract the longest contiguous run of literal characters from a regex.

    Uses sre_parse to properly interpret escape sequences so that meta-
    sequences like ``\\b`` or ``\\d`` are never mistakenly treated as literal
    characters.  BRANCH nodes (alternations) are explored and the longest
    literal found in any branch is returned.

    Returns the longest contiguous literal substring found in *pattern*, or an
    empty string when no literal run of any length exists (e.g. ``".*"``).
    """
    try:
        parsed = sre_parse.parse(pattern)
    except Exception:
        return ""

    return _best_literal_in(parsed)


def _best_literal_in(items: sre_parse.SubPattern) -> str:
    """Return the longest contiguous literal run inside a parsed regex *items*.

    Recursively descends into SUBPATTERN (groups) and BRANCH (alternations)
    nodes, tracking the current run of consecutive LITERAL opcodes.  Non-
    literal opcodes flush the current run and reset it.

    Args:
        items: A parsed ``sre_parse.SubPattern`` sequence of ``(opcode, arg)`` pairs.

    Returns:
        The longest contiguous literal string found, or ``""`` if none.
    """
    best = ""
    run: list[str] = []

    def _flush() -> None:
        nonlocal best
        candidate = "".join(run)
        if len(candidate) > len(best):
            best = candidate
        run.clear()

    for op, av in items:
        if op == sre_parse.LITERAL:
            run.append(chr(av))
        elif op == sre_parse.SUBPATTERN:
            _flush()
            sub = _best_literal_in(av[-1])
            if len(sub) > len(best):
                best = sub
        elif op == sre_parse.BRANCH:
            _flush()
            for branch in av[1]:
                branch_best = _best_literal_in(branch)
                if len(branch_best) > len(best):
                    best = branch_best
        else:
            _flush()
    _flush()
    return best


def _find_encoded_string_start(hit_ea: int, char_size: int) -> int:
    """Return the start address of the encoded string that contains *hit_ea*.

    Scans backwards (up to ``_STR_LOOKBACK_BYTES``) for a run of *char_size*
    zero bytes that marks the terminator of the preceding string.  The address
    immediately following that terminator is returned.  Falls back to *hit_ea*
    (aligned) when no terminator is found in the look-back window.
    """
    ea = hit_ea & ~(char_size - 1)  # align to char boundary
    lookback = min(ea, _STR_LOOKBACK_BYTES)
    if lookback < char_size:
        return ea

    raw = ida_bytes.get_bytes(ea - lookback, lookback)
    if not raw or len(raw) < char_size:
        return ea

    # Scan right-to-left for a null char (char_size zero bytes)
    pos = lookback - char_size
    while pos >= 0:
        if all(raw[pos + i] == 0 for i in range(char_size)):
            return ea - lookback + pos + char_size
        pos -= char_size

    return ea - lookback


def _search_encoded(
    regex: re.Pattern,
    encoding: str,
    strtype: int,
    char_size: int,
    max_count: int,
) -> list[tuple[int, str]]:
    """Binary-search the binary for strings in *encoding* that match *regex*.

    Encodes the longest literal run extracted from the pattern, searches for
    it as raw bytes, walks back to each string's start, decodes the full
    string via ``ida_bytes.get_strlit_contents``, and applies the regex.

    Args:
        regex:      Compiled regex (with ``re.IGNORECASE``) to filter results.
        encoding:   Python codec name (e.g. ``"utf-16-le"``, ``"cp1252"``).
        strtype:    IDA string-type constant (e.g. ``ida_nalt.STRTYPE_C_16``)
                    used to read the full null-terminated string at each hit.
        char_size:  Byte width of one character in *encoding* (1, 2, or 4).
        max_count:  Maximum number of matching ``(ea, text)`` pairs to return.

    Returns:
        Up to *max_count* ``(ea, text)`` pairs sorted by discovery order.
    """
    literal = _extract_longest_literal(regex.pattern)
    if len(literal) < 2:
        return []

    try:
        needle = literal.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return []

    mask = b"\xff" * len(needle)
    search_flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW

    min_ea = compat.inf_get_min_ea()
    max_ea = compat.inf_get_max_ea()

    results: list[tuple[int, str]] = []
    seen: set[int] = set()
    ea = min_ea

    while len(results) < max_count:
        hit = compat.raw_bin_search(ea, max_ea, needle, mask, search_flags)
        if hit == idaapi.BADADDR:
            break

        str_start = _find_encoded_string_start(hit, char_size)
        if str_start not in seen:
            seen.add(str_start)
            content = ida_bytes.get_strlit_contents(str_start, -1, strtype)
            if content:
                try:
                    text = content.decode(encoding)
                    if regex.search(text):
                        results.append((str_start, text))
                except (UnicodeDecodeError, ValueError):
                    pass

        ea = hit + char_size  # advance past current hit

    return results


def init_caches():
    """Build caches on plugin startup (called from Ctrl+M)."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    print(f"[MCP] Cached {len(strings)} strings in {(t1 - t0) * 1000:.0f}ms")


# ============================================================================
# Core API Functions
# ============================================================================


def _parse_func_query(query: str) -> int:
    """Fast path for common function query patterns. Returns ea or BADADDR."""
    q = query.strip()

    # 0x<hex> - direct address
    if q.startswith("0x") or q.startswith("0X"):
        try:
            return int(q, 16)
        except ValueError:
            pass

    # sub_<hex> - IDA auto-named function
    if q.startswith("sub_"):
        try:
            return int(q[4:], 16)
        except ValueError:
            pass

    return idaapi.BADADDR


def _coerce_sort_number(value, default: int = 0) -> int:
    """Parse decimal or prefixed string numbers used by generic entity rows."""
    if value in (None, ""):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def _collect_imports() -> list[Import]:
    """Collect all imports in the current database."""
    all_imports: list[Import] = []
    nimps = ida_nalt.get_import_module_qty()

    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"
            acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, all_imports)

        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return all_imports


def _segment_name_for_ea(ea: int) -> str | None:
    seg = idaapi.getseg(ea)
    if not seg:
        return None
    try:
        return idaapi.get_segm_name(seg)
    except Exception:
        return None


def _primary_text_key(kind: str) -> str:
    if kind == "strings":
        return "text"
    return "name"


def _collect_entities(kind: str) -> list[dict]:
    if kind == "functions":
        rows: list[dict] = []
        for ea in idautils.Functions():
            fn = idaapi.get_func(ea)
            if not fn:
                continue
            size_int = fn.end_ea - fn.start_ea
            rows.append(
                {
                    "kind": "function",
                    "addr": hex(fn.start_ea),
                    "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                    "size": hex(size_int),
                    "size_int": size_int,
                    "segment": _segment_name_for_ea(fn.start_ea),
                    "has_type": bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)),
                }
            )
        return rows

    if kind == "globals":
        rows = []
        for ea, name in idautils.Names():
            if idaapi.get_func(ea) or name is None:
                continue
            rows.append(
                {
                    "kind": "global",
                    "addr": hex(ea),
                    "name": name,
                    "size": idc.get_item_size(ea),
                    "segment": _segment_name_for_ea(ea),
                }
            )
        return rows

    if kind == "imports":
        rows = []
        for imp in _collect_imports():
            rows.append(
                {
                    "kind": "import",
                    "addr": imp["addr"],
                    "name": imp["imported_name"],
                    "module": imp["module"],
                }
            )
        return rows

    if kind == "strings":
        rows = []
        for ea, text in _get_strings_cache():
            rows.append(
                {
                    "kind": "string",
                    "addr": hex(ea),
                    "text": text,
                    "length": len(text),
                    "segment": _segment_name_for_ea(ea),
                }
            )
        return rows

    if kind == "names":
        rows = []
        imports_by_ea = {int(imp["addr"], 16): imp for imp in _collect_imports()}
        for ea, name in idautils.Names():
            is_function = bool(idaapi.get_func(ea))
            is_import = ea in imports_by_ea
            rows.append(
                {
                    "kind": "name",
                    "addr": hex(ea),
                    "name": name,
                    "segment": _segment_name_for_ea(ea),
                    "is_function": is_function,
                    "is_import": is_import,
                }
            )
        return rows

    return []


def _apply_projection(items: list[dict], fields: list[str] | None) -> list[dict]:
    if not fields:
        return items
    normalized = [str(f).strip() for f in fields if str(f).strip()]
    if not normalized:
        return items
    keep = set(normalized)
    keep.add("kind")
    projected = []
    for item in items:
        projected.append({k: v for k, v in item.items() if k in keep})
    return projected


def _build_health_payload() -> dict:
    auto_is_ok = getattr(ida_auto, "auto_is_ok", None)
    auto_analysis_ready = bool(auto_is_ok()) if callable(auto_is_ok) else None

    hexrays_ready = False
    try:
        hexrays_ready = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        hexrays_ready = False

    idb_path = None
    try:
        idb_path = idc.get_idb_path()
    except Exception:
        idb_path = None

    return {
        "status": "ok",
        "uptime_sec": round(time.time() - _server_started_at, 3),
        "idb_path": idb_path,
        "module": ida_nalt.get_root_filename(),
        "input_path": ida_nalt.get_input_file_path(),
        "imagebase": hex(idaapi.get_imagebase()),
        "auto_analysis_ready": auto_analysis_ready,
        "hexrays_ready": hexrays_ready,
        "strings_cache_ready": _strings_cache is not None,
        "strings_cache_size": len(_strings_cache) if _strings_cache is not None else 0,
    }


@tool
@idasync
def server_health() -> ServerHealthResult:
    """Health/ready probe for MCP server and current IDB state."""
    return _build_health_payload()


@tool
@idasync
def server_warmup(
    wait_auto_analysis: Annotated[bool, "Wait for auto analysis queue"] = True,
    build_caches: Annotated[bool, "Build core caches (currently strings)"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler plugin"] = True,
) -> ServerWarmupResult:
    """Warm up IDA subsystems to reduce first-call latency and transient failures."""
    steps = []

    if wait_auto_analysis:
        t0 = time.perf_counter()
        ida_auto.auto_wait()
        steps.append(
            {
                "step": "auto_wait",
                "ok": True,
                "ms": round((time.perf_counter() - t0) * 1000, 2),
            }
        )

    if build_caches:
        t0 = time.perf_counter()
        init_caches()
        steps.append(
            {
                "step": "init_caches",
                "ok": True,
                "ms": round((time.perf_counter() - t0) * 1000, 2),
            }
        )

    if init_hexrays:
        t0 = time.perf_counter()
        ok = bool(ida_hexrays.init_hexrays_plugin())
        step = {
            "step": "init_hexrays",
            "ok": ok,
            "ms": round((time.perf_counter() - t0) * 1000, 2),
        }
        if not ok:
            step["error"] = "Hex-Rays unavailable"
        steps.append(step)

    return {
        "ok": all(bool(step.get("ok")) for step in steps),
        "steps": steps,
        "health": _build_health_payload(),
    }


@tool
@idasync
def lookup_funcs(
    queries: Annotated[list[str] | str, "Address(es) or name(s)"],
) -> list[LookupFuncResult]:
    """Get functions by address or name (auto-detects)"""
    queries = normalize_list_input(queries)

    # Treat empty/"*" as "all functions" - but add limit
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        all_funcs = []
        for addr in idautils.Functions():
            all_funcs.append(get_function(addr))
            if len(all_funcs) >= 1000:
                break
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    results = []
    for query in queries:
        try:
            # Fast path: 0x<ea> or sub_<ea>
            ea = _parse_func_query(query)

            # Slow path: name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({"query": query, "fn": func, "error": None})
                else:
                    results.append(
                        {"query": query, "fn": None, "error": "Not a function"}
                    )
            else:
                results.append({"query": query, "fn": None, "error": "Not found"})
        except Exception as e:
            results.append({"query": query, "fn": None, "error": str(e)})

    return results


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "Convert numbers to various formats (hex, decimal, binary, ascii)",
    ],
) -> list[IntConvertResult]:
    """Convert numbers to different formats"""
    inputs = normalize_dict_list(inputs, lambda s: {"text": s, "size": 64})

    results = []
    for item in inputs:
        text = item.get("text", "")
        size = item.get("size")

        try:
            value = int(text, 0)
        except ValueError:
            results.append(
                {"input": text, "result": None, "error": f"Invalid number: {text}"}
            )
            continue

        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        try:
            bytes_data = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            results.append(
                {
                    "input": text,
                    "result": None,
                    "error": f"Number {text} is too big for {size} bytes",
                }
            )
            continue

        ascii_str = ""
        for byte in bytes_data.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break

        results.append(
            {
                "input": text,
                "result": ConvertedNumber(
                    decimal=str(value),
                    hexadecimal=hex(value),
                    bytes=bytes_data.hex(" "),
                    ascii=ascii_str,
                    binary=bin(value),
                ),
            }
        )

    return results


@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List functions with optional filtering and pagination",
    ],
) -> list[Page[Function]]:
    """List functions with optional filtering and offset/count pagination."""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_functions = [get_function(addr) for addr in idautils.Functions()]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_functions, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def func_query(
    queries: Annotated[
        list[FunctionQuery] | FunctionQuery | str,
        "Richer function query (size/type/name filters + pagination)",
    ],
) -> list[FunctionQueryPage]:
    """Query functions with richer filtering than list_funcs."""
    queries = normalize_dict_list(
        queries,
        lambda s: {
            "filter": s,
            "offset": 0,
            "count": 50,
            "sort_by": "addr",
            "descending": False,
        },
    )

    all_functions: list[dict] = []
    for addr in idautils.Functions():
        fn = idaapi.get_func(addr)
        if not fn:
            continue
        size_int = fn.end_ea - fn.start_ea
        fn_name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
        has_type = ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)
        all_functions.append(
            {
                "addr": hex(fn.start_ea),
                "name": fn_name,
                "size": hex(size_int),
                "size_int": size_int,
                "has_type": has_type,
            }
        )

    def apply_name_regex(items: list[dict], expr: str) -> list[dict]:
        if not expr:
            return items
        try:
            compiled = re.compile(expr)
        except re.error:
            return []
        return [item for item in items if compiled.search(item["name"])]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 50)
        sort_by = query.get("sort_by", "addr")
        descending = bool(query.get("descending", False))
        if sort_by not in ("addr", "name", "size"):
            sort_by = "addr"

        filtered = all_functions
        name_filter = query.get("filter", "")
        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "name")

        name_regex = query.get("name_regex", "")
        if name_regex:
            filtered = apply_name_regex(filtered, name_regex)

        min_size = query.get("min_size")
        if min_size is not None:
            filtered = [f for f in filtered if f["size_int"] >= int(min_size)]

        max_size = query.get("max_size")
        if max_size is not None:
            filtered = [f for f in filtered if f["size_int"] <= int(max_size)]

        if "has_type" in query:
            require_type = bool(query.get("has_type"))
            filtered = [f for f in filtered if bool(f["has_type"]) is require_type]

        if sort_by == "name":
            filtered.sort(key=lambda f: f["name"].lower(), reverse=descending)
        elif sort_by == "size":
            filtered.sort(key=lambda f: f["size_int"], reverse=descending)
        else:
            filtered.sort(key=lambda f: int(f["addr"], 16), reverse=descending)

        page = paginate(filtered, offset, count)
        page["data"] = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]
        results.append(page)

    return results


@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List global variables with optional filtering and pagination",
    ],
) -> list[Page[Global]]:
    """List globals with optional filtering and offset/count pagination."""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_globals: list[Global] = []
    for addr, name in idautils.Names():
        if not idaapi.get_func(addr) and name is not None:
            all_globals.append(Global(addr=hex(addr), name=name))

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def entity_query(
    queries: Annotated[
        list[EntityQuery] | EntityQuery | str,
        "Generic entity query with filtering, projection, and pagination",
    ],
) -> list[EntityQueryPage]:
    """Query IDB entities with typed filters, projection, and pagination."""
    queries = normalize_dict_list(
        queries,
        lambda s: {"kind": s, "offset": 0, "count": 100, "sort_by": "addr"},
    )
    results: list[dict] = []

    for query in queries:
        kind = str(query.get("kind", "functions") or "functions").lower()
        if kind not in {"functions", "globals", "imports", "strings", "names"}:
            results.append(
                {
                    "kind": kind,
                    "data": [],
                    "next_offset": None,
                    "total": 0,
                    "error": f"Unsupported kind: {kind}",
                }
            )
            continue

        rows = _collect_entities(kind)
        primary_key = _primary_text_key(kind)
        filter_pattern = str(query.get("filter", "") or "")
        if filter_pattern:
            rows = pattern_filter(rows, filter_pattern, primary_key)

        regex = str(query.get("regex", "") or "")
        if regex:
            try:
                compiled = re.compile(regex)
                rows = [row for row in rows if compiled.search(str(row.get(primary_key, "")))]
            except re.error:
                rows = []

        segment_filter = str(query.get("segment", "") or "")
        if segment_filter and kind in {"functions", "globals", "strings", "names"}:
            rows = pattern_filter(rows, segment_filter, "segment")

        module_filter = str(query.get("module", "") or "")
        if module_filter and kind == "imports":
            rows = pattern_filter(rows, module_filter, "module")

        min_addr = query.get("min_addr")
        if min_addr not in (None, ""):
            try:
                min_ea = parse_address(min_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) >= min_ea]
            except Exception:
                rows = []

        max_addr = query.get("max_addr")
        if max_addr not in (None, ""):
            try:
                max_ea = parse_address(max_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) <= max_ea]
            except Exception:
                rows = []

        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))
        if sort_by == "addr":
            rows.sort(key=lambda row: int(str(row.get("addr", "0x0")), 16), reverse=descending)
        elif sort_by in {"size", "length"}:
            rows.sort(
                key=lambda row: row.get("size_int", _coerce_sort_number(row.get(sort_by, 0))),
                reverse=descending,
            )
        else:
            rows.sort(key=lambda row: str(row.get(sort_by, "")).lower(), reverse=descending)

        offset = int(query.get("offset", 0) or 0)
        count = int(query.get("count", 100) or 100)
        page = paginate(rows, offset, count)
        data = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]

        fields_raw = query.get("fields")
        fields = None
        if fields_raw is not None:
            if isinstance(fields_raw, str):
                fields = normalize_list_input(fields_raw)
            elif isinstance(fields_raw, list):
                fields = [str(f) for f in fields_raw]
            else:
                fields = [str(fields_raw)]
        data = _apply_projection(data, fields)

        results.append(
            {
                "kind": kind,
                "data": data,
                "next_offset": page["next_offset"],
                "total": len(rows),
                "error": None,
            }
        )

    return results


@tool
@idasync
def imports(
    offset: Annotated[int, "Starting pagination index (default: 0)"],
    count: Annotated[int, "Maximum rows (0 returns all imports)"],
) -> Page[Import]:
    """List imports with module names using offset/count pagination."""
    return paginate(_collect_imports(), offset, count)


@tool
@idasync
def imports_query(
    queries: Annotated[
        list[ImportQuery] | ImportQuery | str,
        "Import query with import/module filters and pagination",
    ],
) -> list[ImportsQueryPage]:
    """Query imports with richer filtering than imports(offset,count)."""
    queries = normalize_dict_list(
        queries, lambda s: {"filter": s, "offset": 0, "count": 100}
    )
    all_imports = _collect_imports()
    results = []

    for query in queries:
        filtered = all_imports
        name_filter = query.get("filter", "")
        module_filter = query.get("module", "")

        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "imported_name")
        if module_filter:
            filtered = pattern_filter(filtered, module_filter, "module")

        results.append(
            paginate(filtered, query.get("offset", 0), query.get("count", 100))
        )

    return results


@tool
@idasync
def idb_save(
    path: Annotated[str, "Optional destination path (default: current IDB path)"] = "",
) -> IdbSaveResult:
    """Save active IDB to disk, optionally to a provided path."""
    try:
        save_path = path.strip() if path else ""
        if not save_path:
            save_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not save_path:
            return {"ok": False, "path": None, "error": "Could not resolve IDB path"}

        ok = bool(ida_loader.save_database(save_path, 0))
        result: dict = {"ok": ok, "path": save_path}
        if not ok:
            result["error"] = "save_database returned false"
        return result
    except Exception as e:
        return {"ok": False, "path": path or None, "error": str(e)}


@tool
@idasync
def find_regex(
    pattern: Annotated[str, "Regex pattern to search for in strings"],
    limit: Annotated[int, "Max matches (default: 30, max: 500)"] = 30,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
    mode: Annotated[
        str,
        (
            'Encoding to search. "UTF-8" (default) searches the IDA ASCII/UTF-8 string '
            'cache. "UTF-16LE" searches wide strings (Windows, Unreal Engine). '
            '"UTF-32LE" searches 4-byte wide strings. '
            '"windows-1252" searches single-byte ANSI strings using the Windows-1252 '
            'codepage. "All" searches every encoding and merges the results.'
        ),
    ] = "UTF-8",
) -> FindRegexResult:
    """Search strings by case-insensitive regex with offset/limit pagination.

    Use ``mode`` to target the encoding used by strings in the binary:

    * ``"UTF-8"`` (default) – searches IDA's built-in ASCII/UTF-8 string cache.
      Fast and sufficient for most ELF/Mach-O binaries.
    * ``"UTF-16LE"`` – binary-scans for wide strings (2-byte chars).  Essential
      for Windows PE files and Unreal Engine binaries where all ``TCHAR*``/
      ``FString`` literals are UTF-16LE.
    * ``"UTF-32LE"`` – binary-scans for 4-byte-char wide strings.
    * ``"windows-1252"`` – binary-scans for single-byte ANSI strings encoded in
      the Windows-1252 code page (covers high bytes 0x80-0xFF not in ASCII).
    * ``"All"`` – runs every encoding and merges the results (deduplicates by
      address, sorts by address ascending).
    """
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    mode = (mode or "UTF-8").strip()
    valid_modes = {"UTF-8", "UTF-16LE", "UTF-32LE", "windows-1252", "All"}
    if mode not in valid_modes:
        return {
            "n": 0,
            "matches": [],
            "cursor": {"done": True},
            "error": f"Unknown mode {mode!r}. Valid modes: {sorted(valid_modes)}",
        }

    regex = re.compile(pattern, re.IGNORECASE)
    need = offset + limit + 1  # collect one extra to detect "more"

    def _utf8_matches() -> list[tuple[int, str]]:
        return [
            (ea, text) for ea, text in _get_strings_cache() if regex.search(text)
        ]

    def _encoded_matches(enc_mode: str) -> list[tuple[int, str]]:
        codec, strtype, char_size = _ENCODING_CONFIGS[enc_mode]
        return _search_encoded(regex, codec, strtype, char_size, need)

    if mode == "UTF-8":
        all_matches: list[tuple[int, str]] = _utf8_matches()
    elif mode in _ENCODING_CONFIGS:
        all_matches = _encoded_matches(mode)
    else:  # "All"
        seen: set[int] = set()
        merged: list[tuple[int, str]] = []
        for ea, text in _utf8_matches():
            if ea not in seen:
                seen.add(ea)
                merged.append((ea, text))
        for enc_mode in _ENCODING_CONFIGS:
            for ea, text in _encoded_matches(enc_mode):
                if ea not in seen:
                    seen.add(ea)
                    merged.append((ea, text))
        merged.sort(key=lambda t: t[0])
        all_matches = merged

    skipped = 0
    matches = []
    more = False
    for ea, text in all_matches:
        if skipped < offset:
            skipped += 1
            continue
        if len(matches) >= limit:
            more = True
            break
        matches.append({"addr": hex(ea), "string": text})

    return {
        "n": len(matches),
        "matches": matches,
        "cursor": {"next": offset + limit} if more else {"done": True},
    }
