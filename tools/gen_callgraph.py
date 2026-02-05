import ida_nalt
import idaapi
import idautils
import idc
import yaml

idaapi.auto_wait()


def get_function_name(ea):
    """Return function name or fallback to hex address."""
    name = idc.get_func_name(ea)
    return name if name else hex(ea)


def is_imported_function(ea):
    """True if the function is an imported external symbol."""
    seg = idaapi.getseg(ea)
    return seg and seg.type == idaapi.SEG_XTRN


def is_interceptor_jump_only(func_ea):
    """True if function is just a jmp to __interceptor_*"""
    end_ea = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
    for head in idautils.Heads(func_ea, end_ea):
        if idc.print_insn_mnem(head).startswith("jmp"):
            target = idc.get_operand_value(head, 0)
            name = get_function_name(target)
            if "__interceptor_" in name:
                return True
    return False


def is_plt_function(ea):
    """True if function lies in a PLT section (e.g. .plt or .plt.sec)."""
    seg = idaapi.getseg(ea)
    if not seg:
        return False
    seg_name = idaapi.get_segm_name(seg)
    return ".plt" in seg_name


def should_skip_function(ea, name):
    """Return True if this function should be excluded from the call graph."""
    return (
        not name  # unnamed
        or name.startswith(".")  # compiler stubs / thunks
        or "asan" in name
        or "__sanitizer" in name
        or is_imported_function(ea)
        or is_interceptor_jump_only(ea)
        or is_plt_function(ea)
    )


def build_call_tree(root_func_name="LLVMFuzzerTestOneInput"):
    callgraph = {}

    root_ea = idc.get_name_ea_simple(root_func_name)
    if root_ea == idc.BADADDR:
        print(f"[!] Could not find function {root_func_name}")
        return callgraph

    visited = set()
    stack = [root_ea]

    while stack:
        current_ea = stack.pop()
        current_name = get_function_name(current_ea)

        if current_ea in visited or should_skip_function(current_ea, current_name):
            continue
        visited.add(current_ea)

        callees = []

        func = idaapi.get_func(current_ea)
        if not func:
            continue

        for head in idautils.Heads(func.start_ea, func.end_ea):
            if idc.print_insn_mnem(head) == "call":
                target = idc.get_operand_value(head, 0)
                if idaapi.get_func(target):
                    target_name = get_function_name(target)
                    if should_skip_function(target, target_name):
                        continue
                    callees.append(target_name)
                    stack.append(target)

        callgraph[current_name] = list(set(callees))

    return callgraph


def main():
    print("[+] Building call graph from IDA database...")
    callgraph = build_call_tree("LLVMFuzzerTestOneInput")
    if not callgraph:
        # Try with main as the root function
        callgraph = build_call_tree("main")
    binary_name = ida_nalt.get_root_filename()
    with open(f"{binary_name}_callgraph.yaml", "w") as f:
        yaml.dump(callgraph, f, sort_keys=False)
    print(f"[+] Final filtered call graph written to {binary_name}_callgraph.yaml")
    print(f"[+] Functions: {len(callgraph)}")


if __name__ == "__main__":
    main()
    idc.qexit(0)
