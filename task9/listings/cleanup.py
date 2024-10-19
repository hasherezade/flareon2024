#!/usr/bin/env python3

import argparse
import sys

g_code_buffer = None

def clean(line1):
    pos1 = line1.find("[")
    pos2 = line1.find("]")
    return line1[pos1 + 1: pos2]
    
def find_common(line1, line2):
    s1 = clean(line1)
    s2 = clean(line2)
    parts1 = s1.strip().split(';')
    parts2 = s2.strip().split(';')
    for p in parts1:
        if p in parts2:
            #print ("Common: %s" % p)
            return p.strip()
    #print ("%s || %s" % (s1 , s2))
    return None

def parse_name(name):
    subs = 'x_'
    pos = name.find(subs)
    if pos == (-1):
        return None
    name = name[pos + len(subs):]
    pos = name.find(' ')
    val = int(name[:pos],10)
    return val
    
def print_constraints(needed):
    for x in needed:
        print("s.add(x_%d > PRINT_MIN)" % (x))
        print("s.add(x_%d < PRINT_MAX)" % (x))
        print("")

def process_res(line, num):
    print(line.replace("res", "res_" + str(num)))

def replace_m_val(line, stored_m):
	pos1 = stored_m.find('=')
	m_val = stored_m[pos1+1:]
	pos2 = line.find('= m')
	line.replace('m',m_val)
	return line
  
def main():
    global g_code_buffer
    
    parser = argparse.ArgumentParser(description="Assemble with Keystone")
    parser.add_argument('--f1',dest="f1",default="serpentine4_p1.exe.tag.listing.t1.txt" ,help="Listing 1", required=False)
    parser.add_argument('--f2',dest="f2",default="serpentine4_p1.exe.tag.listing.t2.txt" ,help="Listing 2", required=False)
    args = parser.parse_args()

    f1 = open(args.f1, 'r')
    f2 = open(args.f2, 'r')
    
    with open(args.f1) as file1:
        lines1 = [line.rstrip() for line in file1]
    
    with open(args.f2) as file2:
        lines2 = [line.rstrip() for line in file2]
    
    is_clean = True
    only_clean = set()
    args = set()
    count = 0
    stored_m = ""
    for i in range(len(lines1)):
        line = lines1[i]
        if line.find("##") != (-1):
            #print(args)
            if is_clean:
                process_res("s.add(res == 0)", count)
                print("")
                #print_constraints(args)
                #print(args)
                only_clean.update(args)
            args.clear()
            count +=1
            is_clean = True
        val = parse_name(line)
        
        if val is not None:
       		args.add(val)
        if line.startswith("m = "):
       		pos1 = line.find('=')
       		stored_m = line[pos1+1:].strip()
       		continue
       		
       	if line.find("= m"):
       		line = line.replace('m', stored_m)
       	
        if line.startswith("#"):
            common = find_common(lines1[i] , lines2[i])
            if common is None:
                is_clean = False
                print("WARNING: no common part")
            else:
                process_res(common, count)
        else:
            process_res(line, count)
    print(only_clean)
    #print_constraints(only_clean)
    
if __name__ == "__main__":
    sys.exit(main())
    