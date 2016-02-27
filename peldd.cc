// The code in this file is licensed under the MIT License (MIT).


#include <parser-library/parse.h>

#include <iostream>
#include <deque>
#include <list>
#include <algorithm>
#include <stdexcept>
#include <stdlib.h>

using namespace std;

// XXX make static in library ...
extern ::uint32_t err;
extern std::string err_loc;

// XXX duplicated from parse.cc
struct section {
  string                sectionName;
  ::uint64_t            sectionBase;
  bounded_buffer        *sectionData;
  image_section_header  sec;
};

struct parsed_pe_internal {
  list<section>   secs;
};

// XXX library symbols are to generic
extern bool getHeader(bounded_buffer *file, pe_header &p, bounded_buffer *&rem);
extern bool getSections( bounded_buffer  *b, 
                  bounded_buffer  *fileBegin,
                  nt_header_32    &nthdr, 
                  list<section>   &secs);
extern bool getSecForVA(list<section> &secs, VA v, section &sec);

// most of the body is copied from ParsePEFromFile()
// (cf. pe-parse/parser-library/parse.cpp)
//
// That code is licensed as:
/*
The MIT License (MIT)

Copyright (c) 2013 Andrew Ruef

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
parsed_pe *names_prime(const char *filePath, deque<string> &ns) {
  //first, create a new parsed_pe structure
  parsed_pe *p = new parsed_pe();

  if(p == NULL) {
    PE_ERR(PEERR_MEM);
    return NULL;
  }

  //make a new buffer object to hold just our file data 
  p->fileBuffer = readFileToFileBuffer(filePath);

  if(p->fileBuffer == NULL) {
    delete p;
    // err is set by readFileToFileBuffer
    return NULL;
  }

  p->internal = new parsed_pe_internal();

  //get header information
  bounded_buffer  *remaining = NULL;
  if(getHeader(p->fileBuffer, p->peHeader, remaining) == false) {
    deleteBuffer(p->fileBuffer);
    delete p;
    // err is set by getHeader
    return NULL;
  }

  bounded_buffer  *file = p->fileBuffer;
  if(getSections(remaining, file, p->peHeader.nt, p->internal->secs) == false) {
    deleteBuffer(remaining);
    deleteBuffer(p->fileBuffer);
    delete p;
    PE_ERR(PEERR_SECT);
    return NULL;
  }

   
  //get imports
  data_directory importDir;
  if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
    importDir = p->peHeader.nt.OptionalHeader.DataDirectory[DIR_IMPORT];
  } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    importDir = p->peHeader.nt.OptionalHeader64.DataDirectory[DIR_IMPORT];
  } else {
    deleteBuffer(remaining);
    deleteBuffer(p->fileBuffer);
    delete p;
    PE_ERR(PEERR_MAGIC);
    return NULL;
  }

  if(importDir.Size != 0) {
    //get section for the RVA in importDir
    section c;
    VA addr;
    if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      addr = importDir.VirtualAddress + p->peHeader.nt.OptionalHeader.ImageBase;
    } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      addr = importDir.VirtualAddress + p->peHeader.nt.OptionalHeader64.ImageBase;
    } else {
      deleteBuffer(remaining);
      deleteBuffer(p->fileBuffer);
      delete p;
      PE_ERR(PEERR_MAGIC);
      return NULL;
    }

    if(getSecForVA(p->internal->secs, addr, c) == false) {
      deleteBuffer(remaining);
      deleteBuffer(p->fileBuffer);
      delete p;
      PE_ERR(PEERR_READ);
      return NULL;
    }

    //get import directory from this section
    ::uint32_t  offt = addr - c.sectionBase;
    do {
      //read each directory entry out
      import_dir_entry  curEnt;

      READ_DWORD_NULL(c.sectionData, offt, curEnt, LookupTableRVA);
      READ_DWORD_NULL(c.sectionData, offt, curEnt, TimeStamp);
      READ_DWORD_NULL(c.sectionData, offt, curEnt, ForwarderChain);
      READ_DWORD_NULL(c.sectionData, offt, curEnt, NameRVA);
      READ_DWORD_NULL(c.sectionData, offt, curEnt, AddressRVA);

      //are all the fields in curEnt null? then we break
      if( curEnt.LookupTableRVA == 0 && 
          curEnt.NameRVA == 0 &&
          curEnt.AddressRVA == 0) {
        break;
      }

      //then, try and get the name of this particular module...
      VA name;
      if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
        name = curEnt.NameRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
        name = curEnt.NameRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
      } else {
        deleteBuffer(remaining);
        deleteBuffer(p->fileBuffer);
        delete p;
        PE_ERR(PEERR_MAGIC);
        return NULL;
      }

      section nameSec;
      if(getSecForVA(p->internal->secs, name, nameSec) == false) {
        PE_ERR(PEERR_SECTVA);
        deleteBuffer(remaining);
        deleteBuffer(p->fileBuffer);
        delete p;
        return NULL;
      }

      ::uint32_t  nameOff = name - nameSec.sectionBase;

      // GS: replace original byte-by-byte copy version
      if (nameOff < nameSec.sectionData->bufLen) {
        auto p = nameSec.sectionData->buf;
        auto n = nameSec.sectionData->bufLen;
        auto b = p + nameOff;
        auto x = std::find(b, p + n, 0);
        ns.emplace_back(b, x);
      }

      offt += sizeof(import_dir_entry);
    } while(true);
  }

  deleteBuffer(remaining);

  return p;
}

static deque<string> names(const char *filename)
{
  deque<string> ns;
  auto p = names_prime(filename, ns);
  if (!p)
    throw runtime_error("Error reading PE structure: " + err_loc);
  deleteBuffer(p->fileBuffer);
  for (auto &s : p->internal->secs)
    delete s.sectionData;
  delete p->internal;
  delete p;
  return ns;
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    cerr << "call: " << *argv << " foo.exe\n"
      << "  or: " << *argv << " foo.dll\n";
    exit(1);
  }
  const char *filename = argv[1];
  try {
    auto ns = names(filename);
    for (auto &n : ns)
      cout << n << '\n';
  } catch (const exception &e) {
    cerr << "Error: " << e.what() << '\n';
    exit(1);
  }
}
