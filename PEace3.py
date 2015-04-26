#!/usr/bin/python
'''

 PEace
=======

A Python library for reading Portable Executable files.
Simple to use, simple to read.
PE = PEace('path_to_pe')

PE.Sections contains an array of all the PE Sections with their fields and values
PE.getSectionByName(b'.section') returns the section given by the name argument
PE.ImportModules contains an array listing all the imported functions
PE.ExportModules same as above, for exports

Also includes a function to read Null Terminated Byte Strings from files (C style)
string = self.readNTTS(file_offset)
Reads bytes until null byte is encountered.

Written by Ruben Ventura [tr3w]
the.tr3w at gmail dot com
(@tr3w_)

'''

import struct


class PEace(object):

    def __init__(self, path):

        try:
            self.f = open(path, 'rb')
        except IOError:
            raise Exception("[!] Cannot open file: %s" % IOError)

        self.DOSHeader            = self.getDOSHeader()
        self.PEHeader             = self.getPEHeader()
        self.ImageOptionalHeader  = self.getImageOptionalHeader()
        self.ImageDataDirectory   = self.getImageDataDirectory()
        self.Sections             = self.getSections()
        self.ImportModules        = self.getImports()
        self.ExportModules        = self.getExports()
        # print "Finished setting up for %s" % path



    def getDOSHeader(self):

        DOSHeader = self.f.read(0x40)

        if DOSHeader[:2] != b'MZ':
            raise Exception("[!] Invalid DOS header.")

        return DOSHeader



    def getPEHeader(self):

        self.PEHeaderOffset = unpackL(self.DOSHeader[0x3c:])
        self.f.seek(self.PEHeaderOffset)
        # read Signature and IMAGE_FILE_HEADER (0x14)
        PEHeader = self.f.read(0x18)

        if PEHeader[:4] != b'PE\0\0':
            raise Exception("[!] Invalid PE header.")

        if PEHeader[4:6] == b'\x4c\x01':
            pass#print '# 32-bit executable'
        elif PEHeader[4:6] == b'\x00\x02':
            pass#print '# 64-bit executable'
        else:
            pass# ' not a i386+ image'

        return PEHeader



    def getImageOptionalHeader(self):

        self.f.seek(self.PEHeaderOffset + len(self.PEHeader))
        SizeOfOptionalHeader = unpackH(self.PEHeader[0x14:0x16])
        ImageOptionalHeader = self.f.read(SizeOfOptionalHeader)

        return ImageOptionalHeader



    def getImageDataDirectory(self):

        # ImageDataDirectory (the last entry of the OptionalHeader) has 16 entries of 8 bytes each (0x80)
        NumberOfRvas = self.ImageOptionalHeader[len(self.ImageOptionalHeader) - 0x84 : len(self.ImageOptionalHeader) - 0x80]
        ImageDataDirectory = self.ImageOptionalHeader[len(self.ImageOptionalHeader) - 0x80 : len(self.ImageOptionalHeader)]
        #for i in xrange(0, NumberOfRvas):


        return ImageDataDirectory



    def getSections(self):

        NumberOfSections = unpackH(self.PEHeader[6:8])
        Sections = []
        f = self.f
        f.seek(self.PEHeaderOffset + len(self.PEHeader) + len(self.ImageOptionalHeader))
        for i in range(0, NumberOfSections):
            Sections.append({'Name'                : f.read(8),
                             'PhysicalAddress'     : unpackL(f.read(4)),
                             'VirtualAddress'      : unpackL(f.read(4)),
                             'SizeOfRawData'       : unpackL(f.read(4)),
                             'PointerToRawData'    : unpackL(f.read(4)),
                             'PointerToRelocations': unpackL(f.read(4)),
                             'PointerToLinenumbers': unpackL(f.read(4)),
                             'NumberOfRelocations' : unpackH(f.read(2)),
                             'NumberOfLineNumbers' : unpackH(f.read(2)),
                             'Characteristics'     : unpackL(f.read(4))
                             })
        return Sections



    def getSectionByName(self, Name):
        for section in self.Sections:
            if Name in section['Name']:
                return section

        return 0



    def getExports(self):

        f = self.f
        ExportSection = self.getSectionByName(b'.edata')
        if not ExportSection: return 0
        ExportOffset = ExportSection['PointerToRawData']
        ImageExportOffset = unpackL(self.ImageDataDirectory[:4])
        ExportSize = unpackL(self.ImageDataDirectory[4:8])

        f.seek(ExportOffset)
        ImageExportDirectory = f.read(ExportSize)

        NumberOfFunctions = unpackL(ImageExportDirectory[0x14:0x18])
        NumberOfNames = unpackL(ImageExportDirectory[0x18:0x1c])
        if NumberOfFunctions != NumberOfNames:
            #WTF?
            print('functions != names')
        AddressOfFunctions = unpackL(ImageExportDirectory[0x1c:0x20]) - ImageExportOffset + ExportOffset
        AddressOfNames = unpackL(ImageExportDirectory[0x20:0x24]) - ImageExportOffset + ExportOffset

        f.seek(AddressOfNames)
        ExportNamePointers = f.read(NumberOfNames * 4)

        ExportNamesPointers = [unpackL(ExportNamePointers[i:i+4]) - ImageExportOffset + ExportOffset for i in range(0, len(ExportNamePointers), 4)]
        ExportNamePointers = []
        i = 0
        for pointer in ExportNamesPointers:
            ExportNamePointers.append(self.readNTBS(pointer))

        return ExportNamePointers


    def getImports(self):

        ImportSection = self.getSectionByName(b'.idata')
        if not ImportSection: return 0
        ImportOffset = ImportSection['PointerToRawData']
        ImageImportOffset = unpackL(self.ImageDataDirectory[8:0xc])
        ImportSize = unpackL(self.ImageDataDirectory[0xc:0x10])
        ImageImportDirectory = []

        f = self.f
        f.seek(ImportOffset)
        for i in range(0x14, ImportSize, 0x14):
            ImageImportDirectory.append(f.read(0x14))

        ImportModules = []
        for module in ImageImportDirectory:
            if module == b'\x00' * 0x14: # extra validation cuz sometimes ImportSize says another thing
                break
            module_name = unpackL(module[0xc:0x10]) - ImageImportOffset + ImportOffset
            FirstThunk = unpackL(module[:4])
            offset_to_pointers = ImportOffset + FirstThunk - ImageImportOffset
            pointers = []
            f.seek(offset_to_pointers)
            while 1:
                pointer = unpackL(f.read(4))
                if not pointer:
                    break
                pointers.append(pointer - ImageImportOffset + ImportOffset)

            for p in pointers:
                ImportModules.append("%s : %s" % (self.readNTBS(module_name), self.readNTBS(p + 2)))

        return ImportModules



    def readNTBS(self, p):
        s = b''
        self.f.seek(p)
        while 1:
            s += self.f.read(1)
            if s[-1] == b"\x00":
                return s[:-1]



def unpackL(s):
    return struct.unpack("<L", s)[0]

def unpackH(s):
    return struct.unpack("<H", s)[0]
