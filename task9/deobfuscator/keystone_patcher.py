#!/usr/bin/env python3
import keystone
import argparse
import sys

g_code_buffer = None

def apply_patch(pos, patch):
    global g_code_buffer
    g_code_buffer = g_code_buffer[:pos] + patch + g_code_buffer[pos + len(patch):]
    print("patch applied at: %x"  % pos)

def main():
    global g_code_buffer
    
    parser = argparse.ArgumentParser(description="Assemble with Keystone")
    parser.add_argument('--inp',dest="inp",default="111_halts.asm" ,help="Listing with patches", required=False)
    parser.add_argument('--shc',dest="shc",default="serpentine_00000000069D0000.bin",help="Input shellcode file", required=False)
    parser.add_argument('--out',dest="out",default="111_halts.shc",help="Output file", required=False)
    parser.add_argument('--verbose',dest="verbose",default=False, help="Enable verbose mode", required=False, type=bool)
    parser.add_argument('--base',dest="base",default="0x1408aa000", help="Base address", required=False, type=lambda x: int(x,0))
    args = parser.parse_args()
    #SHC_1_BASE = 0x1408aa000
    #SHC_2_BASE = 0x1410aa000
    
    print("Input: %s" % args.inp)
    print("Output: %s" % args.out)
    print("Base: 0x%x" % args.base)
    # Specify the starting address
    start_address = args.base

    # Initialize Keystone with the x86 architecture in 64-bit mode
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    assembly_code = None

    with open(args.shc, 'rb') as f:
        shellcode_mem = f.read()
        g_code_buffer = shellcode_mem
        
    out_filename = args.out
    out_file = open(out_filename, "wb")

    # Read the assembly code from a file
    with open(args.inp, "r") as patches_file:
        for line in patches_file:
            parts = line.strip().split(';')
            if len(parts) != 2:
                print("Invalid format: %s" % line)
                continue
            offset = int(parts[0], 16)
            curr_address = offset + start_address

            assembly_code = parts[1]
            if len(assembly_code) == 0:
                continue
            try:
                # Assemble the code
                assembled_code, _ = ks.asm(assembly_code, addr=curr_address)
                real_size = len(assembled_code)
                if args.verbose:
                    print("0x%x: %s" % (curr_address, assembly_code) )
                if args.verbose:
                    for byte in assembled_code:
                        print(f"{byte:02X}", end=" ")
                    print("\n")
                apply_patch(offset, bytes(assembled_code)) 
                
            except keystone.KsError as e:
                print(f"Assembly failed: {e}")
    out_file.write(bytes(g_code_buffer))
    print("\nAssembled code has been written to '%s'." % out_filename)
    
if __name__ == "__main__":
    sys.exit(main())
    