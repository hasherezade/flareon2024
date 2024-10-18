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
            return p
    #print ("%s || %s" % (s1 , s2))
    return None

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
    
    for i in range(len(lines1)):
        line = lines1[i]
        if line.startswith("#"):
            common = find_common(lines1[i] , lines2[i])
            if common is None:
                print("WARNING: no common part")
            else:
                print(common)
        else:
            print(line)

    
if __name__ == "__main__":
    sys.exit(main())
    