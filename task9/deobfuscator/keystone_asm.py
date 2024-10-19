#!/usr/bin/env python3
import keystone
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Assemble with Keystone")
    parser.add_argument('--inp',dest="inp",default="111_code.asm",help="Input assembly file")
    parser.add_argument('--out',dest="out",default="111_code.shc",help="Output file")
    parser.add_argument('--verbose',dest="verbose",default=False, help="Enable verbose mode", required=False, type=bool)
    parser.add_argument('--base',dest="base",default="0x1410AA000", help="Base address", required=False, type=lambda x: int(x,0))
    args = parser.parse_args()

    print("Input: %s" % args.inp)
    print("Output: %s" % args.out)
    print("Base: 0x%x" % args.base)
    # Specify the starting address
    start_address = args.base

    # Initialize Keystone with the x86 architecture in 64-bit mode
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    assembly_code = None
    curr_address = start_address

    out_filename = args.out
    out_file = open(out_filename, "wb")

    # Read the assembly code from a file
    with open(args.inp, "r") as asm_file:
        for line in asm_file:
            assembly_code = line.strip()
            if len(assembly_code) == 0:
                continue
            try:
                # Assemble the code
                assembled_code, _ = ks.asm(assembly_code, addr=curr_address)
                real_size = len(assembled_code)
                if args.verbose:
                    print("0x%x: %s" % (curr_address, assembly_code) )
                curr_address += real_size
                if args.verbose:
                    for byte in assembled_code:
                        print(f"{byte:02X}", end=" ")
                    print("\n")

                out_file.write(bytes(assembled_code))
                
            except keystone.KsError as e:
                print(f"Assembly failed: {e}")
                
    print("\nAssembled code has been written to '%s'." % out_filename)
    
if __name__ == "__main__":
    sys.exit(main())
    