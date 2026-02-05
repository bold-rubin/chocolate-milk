#!/usr/bin/env python3
import os
import sys
import yaml
import angr


def func_name(func) -> str:
    # Similar intent to IDA get_func_name(): prefer symbol name, else fallback to hex
    name = getattr(func, "name", None)
    if name:
        return name
    addr = getattr(func, "addr", None)
    return hex(addr) if addr is not None else "UNKNOWN"


def is_imported_function(proj: angr.Project, func) -> bool:
    """
    IDA: SEG_XTRN.
    angr analogue:
      - anything that lives in the loader's extern object address space
      - (optionally) any SimProcedure/hooked function
    """
    addr = getattr(func, "addr", None)
    if addr is None:
        return True

    try:
        obj = proj.loader.find_object_containing(addr)
    except Exception:
        obj = None

    # extern_object is the special object ("cle##externs") for unresolved imports
    try:
        if obj is not None and obj is proj.loader.extern_object:
            return True
    except Exception:
        pass

    return False


def is_plt_function(func) -> bool:
    # angr has a first-class PLT marker
    return bool(getattr(func, "is_plt", False))


def is_interceptor_jump_only(proj: angr.Project, cfg, func) -> bool:
    """
    IDA: function is just 'jmp __interceptor_*'.
    angr approximation: single-block, single-instruction unconditional jump to a known function whose name contains '__interceptor_'.
    This is heuristic and may need tuning per-arch/compiler.
    """
    try:
        blocks = list(func.blocks)
    except Exception:
        return False

    if len(blocks) != 1:
        return False

    b = blocks[0]
    csb = getattr(b, "capstone", None)
    if csb is None or not hasattr(csb, "insns"):
        return False

    insns = csb.insns
    if len(insns) != 1:
        return False

    insn = insns[0].insn
    mnem = (insn.mnemonic or "").lower()
    if not mnem.startswith("jmp"):
        return False

    # Best-effort: parse immediate jump target from op_str (works for common x86/x64 "jmp 0x...").
    op = (insn.op_str or "").strip()
    try:
        if op.startswith("0x"):
            target = int(op, 16)
        else:
            return False
    except Exception:
        return False

    tgt = cfg.kb.functions.function(addr=target, create=False)
    if tgt is None:
        return False

    return "__interceptor_" in func_name(tgt)


def should_skip_function(proj: angr.Project, cfg, func) -> bool:
    name = func_name(func)
    return (
        (not name)
        or name.startswith(".")
        or ("asan" in name)
        or ("__sanitizer" in name)
        or bool(getattr(func, "is_simprocedure", False))  # exclude hooked externs/syscalls
        or is_imported_function(proj, func)
        or is_interceptor_jump_only(proj, cfg, func)
        or is_plt_function(func)
    )


def iter_call_targets(cfg, func):
    """
    Use angr's callsite interface (closest to IDA's 'scan for call instructions').
    """
    for callsite in func.get_call_sites():
        tgt = func.get_call_target(callsite)
        if tgt is None:
            continue
        # Some analyses may return multiple targets; normalize.
        if isinstance(tgt, (list, set, tuple)):
            for t in tgt:
                if isinstance(t, int):
                    yield t
        elif isinstance(tgt, int):
            yield tgt


def build_call_tree(proj: angr.Project, cfg, root_name: str):
    out = {}

    root = cfg.kb.functions.function(name=root_name, create=False)
    if root is None:
        return out

    visited = set()
    stack = [root.addr]

    while stack:
        cur_addr = stack.pop()
        if cur_addr in visited:
            continue
        visited.add(cur_addr)

        cur = cfg.kb.functions.function(addr=cur_addr, create=False)
        if cur is None or should_skip_function(proj, cfg, cur):
            continue

        callees = set()
        for tgt_addr in iter_call_targets(cfg, cur):
            callee = cfg.kb.functions.function(addr=tgt_addr, create=False)
            if callee is None or should_skip_function(proj, cfg, callee):
                continue
            callees.add(func_name(callee))
            stack.append(callee.addr)

        out[func_name(cur)] = sorted(callees)

    return out


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary> [root_func_name]")
        sys.exit(2)

    bin_path = sys.argv[1]
    root_name = sys.argv[2] if len(sys.argv) >= 3 else "LLVMFuzzerTestOneInput"

    # Keep analysis scoped to the main binary unless you explicitly want libs.
    proj = angr.Project(bin_path, auto_load_libs=False)

    cfg = proj.analyses.CFGFast(
        normalize=True,
        data_references=True,
        resolve_indirect_jumps=True,
    )

    callgraph = build_call_tree(proj, cfg, root_name)
    if not callgraph:
        callgraph = build_call_tree(proj, cfg, "main")

    out_name = f"{os.path.basename(bin_path)}_callgraph.yaml"
    with open(out_name, "w", encoding="utf-8") as f:
        yaml.safe_dump(callgraph, f, sort_keys=False)

    print(f"[+] Final filtered call graph written to {out_name}")
    print(f"[+] Functions: {len(callgraph)}")


if __name__ == "__main__":
    main()
