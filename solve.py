#!/usr/bin/env python3

import angr
import claripy

def solve_with_angr(alphanumeric=True):
    """
    Solve using angr - start after fgets
    """
    print(f"[*] Loading binary...")
    p = angr.Project('./chal', auto_load_libs=False)

    # Create 8-byte symbolic input
    flag = [claripy.BVS(f'byte_{i}', 8) for i in range(8)]

    base = p.loader.main_object.min_addr

    # Start AFTER fgets at address 0x1543
    start_addr = base + 0x1543

    # Create a blank state at that address
    state = p.factory.blank_state(addr=start_addr,
                                   add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY})

    # Calculate where the input buffer is on the stack
    # From disassembly: input is at -0x220(%rbp)
    # We need to set up rbp first
    state.regs.rbp = 0x7ffffffffff0000  # Arbitrary stack address
    input_addr = state.regs.rbp - 0x220

    # Write our symbolic input to that address
    for i in range(8):
        state.memory.store(input_addr + i, flag[i])
    # Add newline
    state.memory.store(input_addr + 8, claripy.BVV(ord('\n'), 8))

    print(f"[*] Starting at {hex(start_addr)}, input at {hex(state.solver.eval(input_addr))}")

    # Apply constraints
    if alphanumeric:
        print("[*] Constraining to alphanumeric...")
        for byte in flag:
            state.solver.add(claripy.Or(
                claripy.And(byte >= 0x30, byte <= 0x39),  # 0-9
                claripy.And(byte >= 0x41, byte <= 0x5a),  # A-Z
                claripy.And(byte >= 0x61, byte <= 0x7a)   # a-z
            ))
    else:
        print("[*] Constraining to have at least one non-printable...")
        non_printable = claripy.Or(*[
            claripy.Or(byte < 0x20, byte > 0x7e) for byte in flag
        ])
        state.solver.add(non_printable)

    # Hook check_license
    check_license_addr = base + 0x13f1

    class CheckLicenseHook(angr.SimProcedure):
        def run(self):
            return 0x539

    p.hook(check_license_addr, CheckLicenseHook())
    print(f"[*] Hooked check_license at {hex(check_license_addr)}")

    # Create simulation manager
    sm = p.factory.simulation_manager(state)

    # Target addresses
    success_addr = base + 0x1be2
    fail_addr = base + 0x1c01

    print(f"[*] Exploring (success={hex(success_addr)})...")

    # Explore
    sm.explore(find=success_addr, avoid=fail_addr)

    if sm.found:
        print(f"[+] Found solution!")
        found_state = sm.found[0]
        result = b""
        for byte in flag:
            result += bytes([found_state.solver.eval(byte)])
        return result

    print(f"[-] No solution found")
    print(f"    Found: {len(sm.found)}, Active: {len(sm.active)}, Deadended: {len(sm.deadended)}")
    return None

def main():
    import time

    print("=" * 60)
    print("Lab6 - Symbolic Execution with angr")
    print("=" * 60)

    # Solve for 1.txt (alphanumeric)
    print("\n[Task 1] Finding alphanumeric solution...")
    t1 = time.time()
    sol1 = solve_with_angr(alphanumeric=True)
    t1 = time.time() - t1

    if sol1:
        with open('1.txt', 'wb') as f:
            f.write(sol1 + b'\n')
        print(f"[+] Solution: {sol1.decode('ascii', errors='replace')}")
        print(f"[+] Saved to 1.txt (time: {t1:.2f}s)")

        # Verify
        import subprocess
        result = subprocess.run(['./chal'], input=sol1 + b'\n', capture_output=True)
        if b"Correct" in result.stdout:
            print("[+] Verified!")
        else:
            print("[-] Verification failed")
    else:
        print("[-] Failed to find solution for 1.txt")
        t1 = 0

    # Solve for 2.txt (non-printable)
    print("\n[Task 2] Finding non-printable solution...")
    t2 = time.time()
    sol2 = solve_with_angr(alphanumeric=False)
    t2 = time.time() - t2

    if sol2:
        with open('2.txt', 'wb') as f:
            f.write(sol2 + b'\n')
        print(f"[+] Solution: {repr(sol2)}")
        print(f"[+] Saved to 2.txt (time: {t2:.2f}s)")

        # Verify
        result = subprocess.run(['./chal'], input=sol2 + b'\n', capture_output=True)
        if b"Correct" in result.stdout:
            print("[+] Verified!")
        else:
            print("[-] Verification failed")
    else:
        print("[-] Failed to find solution for 2.txt")
        t2 = 0

    print("\n" + "=" * 60)
    print(f"Total time: {t1 + t2:.2f}s")
    print("=" * 60)

if __name__ == '__main__':
    main()
