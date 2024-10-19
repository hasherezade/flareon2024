#!/usr/bin/env python3
import capstone
from capstone import *
import binascii
import argparse
import sys

g_max_lines = (-1)
g_code_buffer = None
g_print_relative = True
g_debug = False
g_debug2 = False
g_debug3 = False
g_r12_value = None
g_r13_value = None
g_r14_value = None
g_r15_value = None
g_rbp_value = None
g_rdi_value = None
g_rsi_value = None
g_rbx_value = None
g_last_hlt = None
g_done = False
g_hlts_file = None
g_asm_file = None
g_indx = 0

g_prev_hndl = 0
g_processed = set()
g_redirects = { }
g_stored = { }
g_current_address = 0


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

        if g_debug:    
            if offset_in_prolog != 0:
                print('\toffset: 0x%x' % offset_in_prolog)
            
            print('\top_code: %d ; op_info: %d ->\t%s ; Nodes: %d' % (op_code, op_info, opcode_to_name[op_code], nodes_count))
        
        if op_code != UWOP_ALLOC_LARGE and op_code != UWOP_PUSH_MACHFRAME and op_code != UWOP_SET_FPREG:
            if op_info < 8 :
                reg = id_to_reg[op_info]
            if op_info >= 8:
                reg = "R" + str(op_info)
            if g_debug:
                print("\t\t"+reg)
            
        if op_code == UWOP_PUSH_MACHFRAME and op_info == 1:
            if g_debug:
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
                if g_debug:
                    print("\t\tArg0: 0x%x" % (arg0))
            else:
                if g_debug:
                    print("\tUNK")
        i += nodes_count
        unwind_codes.append((offset_in_prolog, op_code, op_info, nodes_count, arg0))
    return unwind_codes

def parse_unwind_info(ui_addr, hlt_addr):
    global g_debug2
    global g_debug3
    global g_indx
    global g_prev_hndl
    global g_all_opcodes
    global g_current_address
    global g_redirects
    global g_hlts_file
    global g_asm_file

    buf = g_code_buffer

    UNW_FLAG_EHANDLER = 0x1
    
    SHC_1_BASE = 0x1408aa000
    SHC_2_BASE = 0x1410aa000
    
    version_and_flags = buf[ui_addr]
    size_of_prolog = buf[ui_addr+1]
    count_of_codes = buf[ui_addr+2]
    frame_register_and_offset = buf[ui_addr + 3]
            
    version = version_and_flags & int('0111', 2)
    flags = (version_and_flags >> 3) & int('011111', 2)

    frame_register = frame_register_and_offset & int('01111', 2)
    frame_register_offset = frame_register_and_offset >> 4
    if version != 1 or flags > 4:
        return None # Invald

    if (flags != UNW_FLAG_EHANDLER):
        return None
        
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
    if g_debug:
        print("> Index: %d" % g_indx)
    g_indx +=1
    if g_debug:
        print("\tVersion: %x ; Flags: %x ; SizeOfProlog: %x ; FrameReg: %x" % (version, flags, size_of_prolog, frame_register))
        if (frame_register_offset != 0):
            print("\tFrameRegOffset: %x" % frame_register_offset)
    if g_debug:
        print("# HLT at 0x%x ->\tHandler: 0x%x" % (hlt_addr, exception_hdlr_addr))
    #print("Handler: 0x%x" % (exception_hdlr_addr)) 
    g_prev_hndl = exception_hdlr_addr
    unwind_codes = parse_opcodes(ui_addr, count_of_codes)
    if True:#unwind_codes or hlt_addr == 0:
        g_asm_file.write("jmp 0x%x\n" % (SHC_1_BASE + hlt_addr))
        g_asm_file.flush()
        
        print("# %x : jmp 0x%x\n" % (g_current_address, SHC_1_BASE + hlt_addr))
        g_current_address += 5
        
        g_hlts_file.write("%x;jmp 0x%x\n" % (exception_hdlr_addr, SHC_2_BASE + g_current_address))
        g_hlts_file.flush()
        
        print("## HNDL %x : jmp 0x%x\n" % (exception_hdlr_addr, SHC_2_BASE + g_current_address))
        g_redirects[hlt_addr] = g_current_address
    for unwind_code in unwind_codes:
        op_code = unwind_code[1]
        if op_code > 10:
            print("!!!WARNING: op_code: %d" % op_code)
    return exception_hdlr_addr
 

def get_reg_relative_value(insn, reg_name, reg_val):
    # Split the line into a list of strings using space as delimiter
    line = insn.op_str
    #addr = insn.address + insn.size
    substr = "[" + reg_name + " "
    pos = line.find(substr)
    if pos == (-1):
        print("Substring \'" + substr + "\' not found in: " + line)
        return None
    found = line[pos + len(substr):]
    is_add = None
    #print("Val = %x" % num)
    if found[0] == '-':
        is_add = False
    elif found[0] == '+':
        is_add = True
    else:
        print("Unknonwn operation: " + found[0])
        return None
        
    #skip operand
    found = found[1:]
    #print("found = %s" % found)
    pos = found.find("0x")
    if pos == (-1):
         pos = found.find(" ")
    number = found[pos:len(found)-1]
    #print("number = %s" % number)
    num = int(number,16)
    if is_add:
        reg_val = reg_val + num
    else:
        reg_val = reg_val - num
    return reg_val

def get_rip_relative_value(insn, base):
    # Split the line into a list of strings using space as delimiter
    line = insn.op_str
    addr = insn.address + insn.size
    addr = get_reg_relative_value(insn, 'rip', addr)
    if addr is None:
        return None
    return addr - base

def get_rip_relative_ah(insn, binary_code, base):
    addr = get_rip_relative_value(insn, base)
    if addr is None:
        return None
    val = binary_code[addr]
    #print("pos: %x val: %x -> %x" % (pos, val , val << 8))
    return val << 8

def replace_lea_op(insn):
    line = insn.op_str
    if insn.operands[0].type != capstone.x86.X86_OP_REG:
        print("Invalid operand")
        return None
    instr_size = 6
    reg_id = insn.operands[0].value.reg
    #print("Reg ID: %d : %s" % (reg_id , line))
    if reg_id >= capstone.x86.X86_REG_R8 and reg_id <= capstone.x86.X86_REG_R15:
        instr_size = 7
    #addr = insn.address + insn.size
    substr = "[rip "
    pos = line.find(substr)
    if pos == (-1):
        print("Substring \'" + substr + "\' not found in: " + line)
        return None
    return line[:pos + len(substr)] + " + " + hex(instr_size) + "]"
    
def mov_add_resolve(current_address, insn, prev_mnem):
    global g_stored
    global g_asm_file
    global g_current_address

    line = insn.mnemonic + " " + insn.op_str
    reg_id = insn.operands[0].value.reg
    is_imm = False
    if len(insn.operands) == 2 and insn.operands[0].type == capstone.x86.X86_OP_REG and insn.operands[1].type == capstone.x86.X86_OP_IMM:
        is_imm = True
        #print("IMM: %s" % line)
            
    if is_imm and (insn.mnemonic == 'mov' or insn.mnemonic == 'movabs'):
        #print("MOV: %d : %s %s" % (reg_id, insn.mnemonic, line))
        g_stored[reg_id] = (line, insn.operands[1].value.imm, insn.size)
        return True
    if reg_id in g_stored.keys() and g_stored[reg_id] is not None:
        disasm = g_stored[reg_id][0]
        stored_val = g_stored[reg_id][1]
        instr_size = g_stored[reg_id][2]
        g_stored[reg_id] = None # delete
        print_backlog = True
        if is_imm and insn.mnemonic == 'add':
            print_backlog = False
            val = stored_val + insn.operands[1].value.imm
            pos = disasm.find(',')
            if pos == (-1):
                print_backlog = True
            else:
                g_asm_file.write("%s, 0x%x\n" % (disasm[:pos] , val))
                g_asm_file.flush()
                #print(">> 0x%x : %s, 0x%x" % (g_current_address, disasm[:pos] , val))
                g_current_address += instr_size
                return True
        if print_backlog:          
            g_asm_file.write("%s\n" % (disasm))
            g_asm_file.flush()
            #print(">>>>>>>>> 0x%x : %s" % (g_current_address, disasm))
            g_current_address += instr_size
            return False
    return False

def is_obf_part(insn, line_cntr):
    if line_cntr == 1 and insn.mnemonic == 'pop' and insn.op_str.find("qword ptr [rip ") != (-1):
        return True
    if line_cntr == 2 and insn.mnemonic == 'push' and insn.op_str == 'rax':
        return True
    if line_cntr == 3 and insn.mnemonic == 'mov' and insn.op_str == 'rax, 0':
        return True
    if line_cntr == 4 and insn.mnemonic == 'mov' and insn.op_str.find('ah, byte ptr') != (-1):
        return True
    if line_cntr == 5 and insn.mnemonic == 'lea' and insn.op_str.find('eax, [eax') != (-1):
        return True
    if line_cntr == 6 and insn.mnemonic == 'mov' and insn.op_str.find('dword ptr [rip') != (-1):
        return True
    if line_cntr == 7 and insn.mnemonic == 'pop' and insn.op_str == 'rax':
        return True
    if line_cntr == 9 and insn.mnemonic == 'mov' and insn.op_str.find('dword ptr [rip') != (-1):
        return True
    if line_cntr == 10 and insn.mnemonic == 'push' and insn.op_str == 'rax':
        return True
    if line_cntr == 11 and insn.mnemonic == 'movabs' and insn.op_str.find('rax, ') != (-1):
        return True
    if line_cntr == 12 and insn.mnemonic == 'lea' and insn.op_str.find('rax, [rax') != (-1):
        return True
    if line_cntr == 13 and insn.mnemonic == 'xchg' and insn.op_str == 'qword ptr [rsp], rax':
        return True
    if line_cntr == 14 and insn.mnemonic == 'ret':
        return True
    if (insn.mnemonic == 'call' or insn.mnemonic == 'jmp') and (insn.operands[0].type == capstone.x86.X86_OP_IMM):
        return True
    if insn.mnemonic == 'hlt':
        return True
    return False
    
def disasm_line(md, base, RVA, max_lines, called_from=None, line_cntr=0):
        global g_code_buffer
        global g_r12_value
        global g_rbp_value
        global g_r13_value
        global g_r14_value
        global g_r15_value
        global g_rdi_value
        global g_rsi_value
        global g_rbx_value
        global g_last_hlt
        global g_processed
        global g_current_address
        global g_done
        
        eax_val = 0
        to_overwrite = None
        ret_value = called_from
        prev_mnem = None
        
        for insn in md.disasm(g_code_buffer[RVA:], base + RVA):
            if max_lines == 0:
                print("Max lines reached")           
                break
            max_lines -=1
            line_cntr +=1
            printed_addr = insn.address
            if g_print_relative:
                printed_addr = insn.address - base
            #print("0x%x -> %s    \t: %s %s" % (printed_addr, binascii.hexlify(insn.bytes).decode('utf-8'), insn.mnemonic, insn.op_str) )
            #print("\t %s" % binascii.hexlify(insn.bytes).decode('utf-8') )
            if not is_obf_part(insn, line_cntr):

                skip_instr = mov_add_resolve(g_current_address, insn, prev_mnem)
                prev_mnem = insn.mnemonic
                if skip_instr:
                    print("Skipping: %s %s" % (insn.mnemonic, insn.op_str))
                    continue
                
                op = insn.op_str
                if insn.mnemonic == 'lea':
                    op = replace_lea_op(insn)
                    #print("NEW OP: " + op) 

                if g_debug:
                    print("0x%x -> 0x%x: %s %s" % (line_cntr, printed_addr, insn.mnemonic, insn.op_str) )
                #else:
                #    print("%x : %s %s" % ( g_current_address, insn.mnemonic, insn.op_str) )
                    
                g_asm_file.write("%s %s\n" % (insn.mnemonic, op) )
                g_asm_file.flush()
                    
                g_current_address += insn.size
                #print("0x%08x: %s %s" % (printed_addr, insn.mnemonic, insn.op_str) )
            if line_cntr == 1 and called_from is not None:
                if insn.mnemonic == 'pop':
                    pos = get_rip_relative_value(insn, base)
                    if pos:
                        #print("POPPING ret to: %x fill with %x" % (pos, called_from) )
                        g_code_buffer = g_code_buffer[:pos] + called_from.to_bytes(8, 'little') + g_code_buffer[pos + 8:]
                    else:
                        print("Not popping ret")
            if insn.mnemonic == 'pop' and insn.op_str == 'rax':
                if to_overwrite:
                    addr = insn.address + insn.size
                    #print("To overwrite: %x: %s" % (addr, binascii.hexlify(to_overwrite).decode('utf-8')))
                    pos = addr - base
                    g_code_buffer = g_code_buffer[:pos] + to_overwrite + g_code_buffer[pos + 4:]
                    disasm_line(md, base, pos, g_max_lines, called_from, line_cntr)
                else:
                    print("Cannot parse")
                break
            if insn.mnemonic == 'hlt':
                if g_debug:
                    print("*****")
                g_last_hlt = (insn.address - base)
                break
            if insn.mnemonic == 'ret':
                #print("-----\n")
                if ret_value:
                    #print("Following the return value: %x" % ret_value)
                    disasm_line(md, base, ret_value, g_max_lines)
                else:
                    print("Ret value not filled")
                break
            if insn.mnemonic == 'mov' and insn.op_str[:2] == 'ah':
                hex_string = binascii.hexlify(insn.bytes[2:]).decode('utf-8')
                eax_val = get_rip_relative_ah(insn, g_code_buffer, base)
            if insn.mnemonic == 'lea':
                bytes1 = insn.bytes
                hex_string0 = binascii.hexlify(bytes1[:3]).decode('utf-8')
                if hex_string0 == "678d80":
                    #hex_str = binascii.hexlify(bytes1[3:]).decode('utf-8')
                    eax_n = int.from_bytes(bytes1[3:], 'little')
                    #print("eax_n : %x + %x = %x" % (eax_n, eax_val, eax_n + eax_val))
                    res = eax_n + eax_val
                    to_overwrite = res.to_bytes(4, 'little')
                elif hex_string0 == "488d40":
                    rel = get_reg_relative_value(insn, 'rax', 0)
                    if (rel is not None and called_from is not None):
                        #print("Rel: %x" % rel)
                        ret_value = (called_from + rel) - base
                        #print("Next: %x" % ret_value)
                elif hex_string0 == "4c8d25":
                    val = get_rip_relative_value(insn, base)
                    if (val is not None):
                        g_r12_value = val
                        #print("R12: %x" % g_r12_value)
                elif hex_string0 == "488d2d":
                    val = get_rip_relative_value(insn, base)
                    if (val is not None):
                        g_rbp_value = val
                        #print("RBP: %x" % g_rbp_value)
                elif hex_string0 == "4c8d2d":
                    val = get_rip_relative_value(insn, base)
                    if (val is not None):
                        g_r13_value = val
                elif hex_string0 == "4c8d35":
                    val = get_rip_relative_value(insn, base)
                    if (val is not None):
                        g_r14_value = val
                elif hex_string0 == "4c8d3d":
                    val = get_rip_relative_value(insn, base)
                    if (val is not None):
                        g_r15_value = val
                elif hex_string0 == "488d3d":
                    val = get_rip_relative_value(insn, base)
                    if (val is not None):
                        g_rdi_value = val
                elif hex_string0 == "488d35":
                    val = get_rip_relative_value(insn, base)
                    if (val is not None):
                        g_rsi_value = val
                elif hex_string0 == "488d1d":
                    val = get_rip_relative_value(insn, base)
                    if (val is not None):
                        g_rbx_value = val
                else:
                    print("NOPE: %s" % hex_string0)
            if insn.mnemonic == 'jmp':
                next_addr = None
                if (insn.operands[0].type == capstone.x86.X86_OP_IMM):
                    next_addr = insn.operands[0].value.imm - base
                elif insn.op_str == 'r12':
                    if g_debug:
                        print("Jmp R12 : %x" % g_r12_value)
                    next_addr = g_r12_value
                elif insn.op_str == 'rbp':
                    if g_debug:
                        print("Jmp RBP : %x" % g_rbp_value)
                    next_addr = g_rbp_value
                elif insn.op_str == 'r13':
                    if g_debug:
                        print("Jmp R13 : %x" % g_r13_value)
                    next_addr = g_r13_value
                elif insn.op_str == 'r14':
                    if g_debug:
                        print("Jmp R14 : %x" % g_r14_value)
                    next_addr = g_r14_value
                elif insn.op_str == 'r15':
                    if g_debug:
                        print("Jmp R15 : %x" % g_r15_value)
                    next_addr = g_r15_value
                elif insn.op_str == 'rdi':
                    if g_debug:
                        print("Jmp RDI : %x" % g_rdi_value)
                    next_addr = g_rdi_value
                elif insn.op_str == 'rsi':
                    if g_debug:
                        print("Jmp RSI : %x" % g_rsi_value)
                    next_addr = g_rsi_value
                elif insn.op_str == 'rbx':
                    if g_debug:
                        print("Jmp RBX : %x" % g_rbx_value)
                    next_addr = g_rbx_value
                else:
                    print("Jumping to " + insn.op_str)
                if next_addr is not None:
                    if next_addr in g_processed:
                        print("Loop detected. Break instead of jumping to: 0x%x" % next_addr)
                        g_done = True
                        break
                    g_processed.add(next_addr)
                    #print("\n### Jumping to: %x" % next_addr)
                    disasm_line(md, base, next_addr, g_max_lines, called_from, 0)
                    break
                print("\n#!!! Jump to unresolved address")
                break
            if insn.mnemonic == 'call':
                if (insn.operands[0].type != capstone.x86.X86_OP_IMM):
                    print("\n#!!! Calling unresolved address")
                    break
                called_address = insn.operands[0].value.imm
                #print("\n### Calling: %x" % called_address)
                disasm_line(md, base, called_address - base, g_max_lines, insn.address + insn.size, 0)
                break
        return g_last_hlt
    
def main():
    global g_code_buffer
    global g_debug
    global g_done
    global g_hlts_file
    global g_asm_file
    parser = argparse.ArgumentParser(description="Task9 - deobfuscate with Capstone")
    parser.add_argument('--inp',dest="inp",default="serpentine_00000000069D0000.bin",help="Input shellcode file", required=False)
    parser.add_argument('--out',dest="out",default="out.asm", help="Output file", required=False)
    parser.add_argument('--debug',dest="debug",default=False, help="Enable debug mode", required=False, type=bool)
    args = parser.parse_args()

    filename = args.inp #"serpentine_00000000069D0000.bin"
    g_debug = args.debug
    g_hlts_file = open("111_halts.asm", "w")
    g_asm_file = open("111_code.asm", "w")
    
    with open(filename, 'rb') as f:
        shellcode_mem = f.read()
        g_code_buffer = shellcode_mem

    base = 0x69D0000
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    
    rva = 0
    while True:
        if rva is None:
            break
        if g_done:
            break
        if g_debug:
            print("######")
            print("### RVA 0x%x:" % rva)
        hlt_rva = disasm_line(md, base , rva, g_max_lines)
        if hlt_rva is None:
            break
        unwind = (hlt_rva + 1) + g_code_buffer[hlt_rva + 1] + 1
        unwind += unwind & 1
        rva =  parse_unwind_info(unwind, hlt_rva)

if __name__ == "__main__":
    sys.exit(main())