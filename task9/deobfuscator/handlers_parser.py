#!/usr/bin/env python3
import binascii
import argparse
import sys

g_code_buffer = None
g_debug2 = True
g_debug3 = False
g_prev_hndl = 0
g_indx = 0
g_handlers_dict = {}
g_all_opcodes = set()


def parse_opcodes(ui_addr, count_of_codes):
    buf = g_code_buffer
        
    UWOP_PUSH_NONVOL     = 0 # 1 node
    UWOP_ALLOC_LARGE     = 1 #2 or 3 nodes
    UWOP_ALLOC_SMALL     = 2 # 1 node
    UWOP_SET_FPREG       = 3 #1 node
    UWOP_SAVE_NONVOL     = 4 #2 nodes
    UWOP_SAVE_NONVOL_FAR = 5 #3 nodes
    UWOP_SAVE_XMM128     = 8  #2 nodes
    UWOP_SAVE_XMM128_FAR = 9 #3 nodes
    UWOP_PUSH_MACHFRAME  = 10 #1 node
    
    opcode_to_nodes = {}
    opcode_to_nodes[UWOP_PUSH_NONVOL] = 1
    opcode_to_nodes[UWOP_ALLOC_LARGE] = 2 #or 3 nodes
    opcode_to_nodes[UWOP_ALLOC_SMALL] =  1 
    opcode_to_nodes[UWOP_SET_FPREG] = 1 
    opcode_to_nodes[UWOP_SAVE_NONVOL] = 2 
    opcode_to_nodes[UWOP_SAVE_NONVOL_FAR] = 3 
    opcode_to_nodes[UWOP_SAVE_XMM128] = 2 
    opcode_to_nodes[UWOP_SAVE_XMM128_FAR] = 3 
    opcode_to_nodes[UWOP_PUSH_MACHFRAME]  = 1 
    
    opcode_to_name = {}
    opcode_to_name[UWOP_PUSH_NONVOL] = 'UWOP_PUSH_NONVOL'
    opcode_to_name[UWOP_ALLOC_LARGE] = 'UWOP_ALLOC_LARGE'
    opcode_to_name[UWOP_ALLOC_SMALL] =  'UWOP_ALLOC_SMALL'
    opcode_to_name[UWOP_SET_FPREG] = 'UWOP_SET_FPREG'
    opcode_to_name[UWOP_SAVE_NONVOL] = 'UWOP_SAVE_NONVOL' 
    opcode_to_name[UWOP_SAVE_NONVOL_FAR] = 'UWOP_SAVE_NONVOL_FAR' 
    opcode_to_name[UWOP_SAVE_XMM128] = 'UWOP_SAVE_XMM128' 
    opcode_to_name[UWOP_SAVE_XMM128_FAR] = 'UWOP_SAVE_XMM128_FAR'
    opcode_to_name[UWOP_PUSH_MACHFRAME]  = 'UWOP_PUSH_MACHFRAME'
    
    id_to_reg = {}
    id_to_reg[0] = 'RAX'
    id_to_reg[1] = 'RCX'
    id_to_reg[2] = 'RDX'
    id_to_reg[3] = 'RBX'
    id_to_reg[4] = 'RSP'
    id_to_reg[5] = 'RBP'
    id_to_reg[6] = 'RSI'
    id_to_reg[7] = 'RDI'

    EL_SIZE = 2
    i = 0
    unwind_codes = []
    while i < count_of_codes:
        pos = ui_addr + 4 + i * EL_SIZE
        offset_in_prolog = buf[pos]
        unwind_op_code_and_info = buf[pos + 1]
        op_code = unwind_op_code_and_info & int('01111', 2)
        op_info = unwind_op_code_and_info >> 4
        nodes_count = opcode_to_nodes[op_code]
        if op_code == UWOP_ALLOC_LARGE and op_info == 1:
            nodes_count = 3
        print('\toffset: 0x%x ; op_code: %d ; op_info: %d -> %s ; Nodes: %d' % (offset_in_prolog, op_code, op_info, opcode_to_name[op_code], nodes_count))
        if op_code != UWOP_ALLOC_LARGE and op_code != UWOP_PUSH_MACHFRAME and op_code != UWOP_SET_FPREG:
            if op_info < 8 :
                reg = id_to_reg[op_info]
            if op_info >= 8:
                reg = "R" + str(op_info)
            print("\t\t"+reg)
            
        if op_code == UWOP_PUSH_MACHFRAME and op_info == 1:
            print("\t\tError Code")
        arg0 = None
        if nodes_count > 1:
            k = i + 1
            pos = ui_addr + 4 + k * EL_SIZE
            if op_code == UWOP_ALLOC_LARGE:
                if op_info == 1:
                    arg0 = int.from_bytes(buf[pos:pos+4], 'little', signed=False)
                else:
                    arg0 = buf[pos] * 8
                print("\t\tArg0: 0x%x" % (arg0))
            else:
                print("\tUNK")
        i += nodes_count
        unwind_codes.append((offset_in_prolog, op_code, op_info, nodes_count, arg0))
    return unwind_codes

def parse_unwind_info(ui_addr, hlt_addr):
    global g_debug2
    global g_debug3
    global g_indx
    global g_prev_hndl
    global g_handlers_dict
    global g_all_opcodes

    global g_debug2
    buf = g_code_buffer

    UNW_FLAG_UHANDLER = 0x2
    UNW_FLAG_EHANDLER = 0x1
    
    version_and_flags = buf[ui_addr]
    size_of_prolog = buf[ui_addr+1]
    count_of_codes = buf[ui_addr+2]
    frame_register_and_offset = buf[ui_addr + 3]
            
    version = version_and_flags & int('0111', 2)
    flags = (version_and_flags >> 3) & int('011111', 2)

    frame_register = frame_register_and_offset & int('01111', 2)
    frame_register_offset = frame_register_and_offset >> 4
    if version != 1 or flags > 4:
        #if g_debug2:
        #    print("!!!!Possibly invalid:")
        return # Invald

    if (flags != UNW_FLAG_EHANDLER):
        return
        
    #hndl_offset = count_of_codes
    hndl_offset = count_of_codes + (count_of_codes & 0x1)
    pos = ui_addr + 4 + hndl_offset * 2
    exception_hdlr_addr = int.from_bytes(buf[pos:pos+4], 'little', signed=False)
    if exception_hdlr_addr > len(g_code_buffer):
        if g_debug3:
            print("Invalid: exception_hdlr_addr out of scope: %x" % exception_hdlr_addr)
        return
    if exception_hdlr_addr < g_prev_hndl:
        diff = g_prev_hndl - exception_hdlr_addr
        if g_debug3:
            print("!! 0x%x smaller" %(exception_hdlr_addr)) 
    else:
        diff = exception_hdlr_addr - g_prev_hndl
        
    if diff > 0x300:
        if g_debug3:
            print("!! 0x%x %x" %(exception_hdlr_addr, diff)) 
        return

    g_handlers_dict[hlt_addr] = exception_hdlr_addr
    print("> Index: %d" % g_indx)
    g_indx +=1

    print("Version: %x ; Flags: %x ; SizeOfProlog: %x ; CountOfCodes: %x ; FrameReg: %x" % (version, flags, size_of_prolog, count_of_codes, frame_register))
    if (frame_register_offset != 0):
        print("FrameRegOffset: %x" % frame_register_offset)
        
    print("# HLT at 0x%x ->\tHandler: 0x%x" % (hlt_addr, exception_hdlr_addr))
    #print("Handler: 0x%x" % (exception_hdlr_addr)) 
    g_prev_hndl = exception_hdlr_addr
    unwind_codes = parse_opcodes(ui_addr, count_of_codes)

    for unwind_code in unwind_codes:
        op_code = unwind_code[1]
        if op_code > 10:
            print("!!!WARNING: op_code: %d" % op_code)
        g_all_opcodes.add(op_code)
        
    print("****\n")

def parse_handlers():

    for i in range(0,len(g_code_buffer)):
        b = g_code_buffer[i]
        if b == 0xf4:
            begin = i
            end = begin + 1
            unwind = end + g_code_buffer[i + 1] + 1
            unwind += unwind & 1
            if g_debug3:
                print("####")
                print("HLT at %x -> %x %x" % (i, unwind, g_code_buffer[unwind]))
            parse_unwind_info(unwind, i)

def main():
    global g_code_buffer
    global g_debug2
    global g_handlers_dict
    global g_all_opcodes
    parser = argparse.ArgumentParser(description="Task9 - parse exception handlers")
    parser.add_argument('--inp',dest="inp",default="serpentine_00000000069D0000.bin",help="Input shellcode file", required=False)
    parser.add_argument('--debug',dest="debug",default=True, help="Enable debug mode", required=False, type=bool)
    args = parser.parse_args()
 
    filename = args.inp #"serpentine_00000000069D0000.bin"
    g_debug2 = args.debug
    
    with open(filename, 'rb') as f:
        shellcode_mem = f.read()
        g_code_buffer = shellcode_mem
    
    parse_handlers()
    print("All handlers: %d" % len(g_handlers_dict))
    print("All opcodes:")
    print(g_all_opcodes)
    
if __name__ == "__main__":
    sys.exit(main())
    