// The code in this file is licensed under the MIT License (MIT).


#include <parser-library/parse.h>

#include <iostream>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <map>
#include <stack>
#include <deque>
#include <list>
#include <algorithm>
#include <stdexcept>
#include <stdlib.h>
#include <string.h>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string/case_conv.hpp>

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
parsed_pe *names_prime(const char *filePath, deque<string> &ns,
    bool &is64) {
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
    // GS: also return this information
    is64 = false;
  } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    importDir = p->peHeader.nt.OptionalHeader64.DataDirectory[DIR_IMPORT];
    is64 = true;
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

static pair<deque<string>, bool> names(const char *filename)
{
  deque<string> ns;
  bool is64 = false;
  auto p = names_prime(filename, ns, is64);
  if (!p)
    throw runtime_error("Error reading PE structure: " + err_loc);
  deleteBuffer(p->fileBuffer);
  for (auto &s : p->internal->secs)
    delete s.sectionData;
  delete p->internal;
  delete p;
  return make_pair(std::move(ns), is64);
}

struct Arguments {
  bool resolve {false};
  bool transitive {false};
  bool include_main {false};
  deque<string> files;
  deque<string> search_path;
  const array<const char*, 1> mingw64_search_path = {{
    "/usr/x86_64-w64-mingw32/sys-root/mingw/bin"
  }};
  const array<const char*, 1> mingw64_32_search_path = {{
    "/usr/i686-w64-mingw32/sys-root/mingw/bin"
  }};
  unordered_set<string> whitelist;
  const array<const char*, 4> default_whitelist = {{
    // lower-case because windows is case insensitive ...
    "advapi32.dll",
    "kernel32.dll",
    "msvcrt.dll",
    "user32.dll"
  }};

  void parse(int argc, char **argv);
  void help(ostream &o, const char *argv0);
};
void Arguments::parse(int argc, char **argv)
{
  for (int i = 1; i < argc; ++i) {
    auto a = argv[i];
    if (!strcmp(a, "-a") || !strcmp(a, "--all")) {
      resolve = true;
      transitive = true;
      include_main = true;
    } else if (!strcmp(a, "-t") || !strcmp(a, "--transitive")) {
      transitive = true;
      resolve = true;
    } else if (!strcmp(a, "-r") || !strcmp(a, "--resolve")) {
      resolve = true;
    } else if (!strcmp(a, "-p") || !strcmp(a, "--path")) {
      if (++i >= argc)
        throw runtime_error("path argument is missing");
      search_path.push_back(argv[i]);
    } else if (!strcmp(a, "-w") || !strcmp(a, "--wlist")) {
      if (++i >= argc)
        throw runtime_error("whitelist argument is missing");
      whitelist.insert(argv[i]);
    } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
      help(cout, *argv);
      exit(0);
    } else if (!strcmp(a, "--")) {
      for (int k = i; k < argc; ++k)
        files.push_back(argv[k]);
    } else if (*a == '-') {
      throw runtime_error("Unknown option: " + string(a));
    } else {
      files.push_back(a);
    }
  }
  if (whitelist.empty())
    whitelist.insert(default_whitelist.begin(), default_whitelist.end());
}
void Arguments::help(ostream &o, const char *argv0)
{
  o << "call: " << *argv0 << " (OPTION)* foo.exe\n"
    << "  or: " << *argv0 << " (OPTION)* foo.dll\n"
       "\n\n\nwhere OPTION  is one of:\n"
       "  -h, --help        this screen\n"
       "  -r, --resolve     resolve a dependency using a search path\n"
       "  -t, --transitive  transitively list the dependencies, implies -r\n"
       "  -a, --all         imply -t,-r and include the input PEs\n"
       "  -p, --path        build custom search path\n"
       "  -w  --wlist       whitelist a library name\n\n"
       ;
}

class Path_Cache {
  private:
    unordered_map<string, unordered_map<string, string> > m_;
    string resolve(const unordered_map<string, string> &h,
        const string &filename);
  public:
    string resolve(const deque<string> &search_path, const string &filename);
};

string Path_Cache::resolve(const unordered_map<string, string> &h,
    const string &filename)
{
  auto fn = boost::to_lower_copy(filename);
  auto i = h.find(fn);
  if (i == h.end())
    throw range_error("Could not resolve: " + filename);
  return i->second;
}
string Path_Cache::resolve(const deque<string> &search_path,
    const string &filename)
{
  for (auto path : search_path) {
    try {
      auto i = m_.find(path);
      if (i == m_.end()) {
        unordered_map<string, string> xs;
        for (auto &e : boost::make_iterator_range(
              boost::filesystem::directory_iterator(path), {})) {
          auto fn = e.path().filename().generic_string();
          xs[boost::to_lower_copy(fn)] = std::move(fn);
        }
        auto r = m_.insert(make_pair(path, std::move(xs)));
        return path + "/" + resolve(r.first->second, filename);
      } else {
        return path + "/" + resolve(i->second, filename);
      }
    } catch (const range_error &e) {
      continue;
    }
  }
  throw runtime_error("Could not resovle: " + filename);
}

class Traverser {
  private:
    const Arguments &args;
    unordered_map<string, string> known_files; // basename, name
    stack<pair<string, string> > files;
    set<string> result_set;
  public:
    Traverser(const Arguments &args);
    void prepare_stack();
    void process_stack();
    void print_result();
};
Traverser::Traverser(const Arguments &args)
  :
    args(args)
{
  prepare_stack();
  process_stack();
  print_result();
}
void Traverser::prepare_stack()
{
  for (auto &a : args.files) {
    auto p = make_pair(boost::filesystem::path(a).filename().generic_string(), a);
    if (!known_files.count(p.first)) {
      if (args.include_main)
        result_set.insert(p.second);
      known_files.insert(p);
      files.push(std::move(p));
    }
  }

}
void Traverser::process_stack()
{
  Path_Cache path_cache;
  while (!files.empty()) {
    auto t = files.top();
    files.pop();
    deque<string> search_path;
    auto p = names(t.second.c_str());
    auto &ns = p.first;
    auto is64 = p.second;
    if (args.search_path.empty()) {
      if (is64)
        search_path.insert(search_path.end(),
            args.mingw64_search_path.begin(), args.mingw64_search_path.end());
      else
        search_path.insert(search_path.end(),
            args.mingw64_32_search_path.begin(),
            args.mingw64_32_search_path.end());
    } else {
      search_path = args.search_path;
    }
    for (auto &n : ns) {
      if (args.whitelist.count(boost::algorithm::to_lower_copy(n)))
        continue;
      if (args.resolve) {
        auto resolved = path_cache.resolve(search_path, n);
        result_set.insert(resolved);
        if (args.transitive && !known_files.count(n)) {
          auto p = make_pair(n, resolved);
          known_files.insert(p);
          files.push(std::move(p));
        }
      } else {
        result_set.insert(n);
      }
    }
  }
}
void Traverser::print_result()
{
  for (auto &r : result_set)
    cout << r << '\n';
}

int main(int argc, char **argv)
{
  try {
    Arguments args;
    args.parse(argc, argv);
    Traverser t(args);
  } catch (const exception &e) {
    cerr << "Error: " << e.what() << '\n';
    exit(1);
  }
}
