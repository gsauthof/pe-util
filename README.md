List shared object dependencies of a portable executable (PE).

It uses the [pe-parse library][2] to read the PE structure.

2016, Georg Sauthoff <mail@georg.so>

## Examples

Create a [portable executable (PE)][1] via cross-compiling
and displays it shared object dependencies:

    $ mkdir build
    $ cd build
    $ mingw64-cmake ..
    $ mingw64-make main
    $ peldd main.exe --no-wlist
    ADVAPI32.dll
    libboost_filesystem-mt.dll
    libboost_system-mt.dll
    libgcc_s_seh-1.dll
    KERNEL32.dll
    msvcrt.dll
    libstdc++-6.dll
    USER32.dll

Display the dependencies of a PE library:

    $ peldd /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libstdc++-6.dll --no-wlist
    libgcc_s_seh-1.dll
    KERNEL32.dll
    msvcrt.dll
    libwinpthread-1.dll
    USER32.dll

Display the dependencies of a PE binary by pointing to a custom path and excluding default path:
  
    Note: peldd uses /usr/x86_64-w64-mingw32/sys-root/mingw/bin/ as its default path.
 
    $ peldd main.exe -p /some/path/to/use/bin --disable-default-path -a

    /some/path/to/use/bin/libgcc_s_seh-1.dll
    /some/path/to/use/bin/libstdc++-6.dll
    /some/path/to/use/bin/libwinpthread-1.dll
     
Display the dependencies of a PE binary without any well-known
system libraries:

    $ peldd main.exe
    libgcc_s_seh-1.dll
    libstdc++-6.dll

Compute the transitive closure of a binary, using the default
search path:

    $ peldd main.exe --all
    main.exe
    /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libgcc_s_seh-1.dll
    /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libstdc++-6.dll
    /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libwinpthread-1.dll

Error because on non whitelisted dll:

    $ peldd ut.exe --all
    Error: Could not resolve: WS2_32.dll

The same binary after extending the whitelist:

    $ peldd ut.exe -a  -w WS2_32.dll 
    /usr/x86_64-w64-mingw32/sys-root/mingw/bin/iconv.dll
    /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libboost_filesystem-mt.dll
    /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libboost_regex-mt.dll
    /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libboost_system-mt.dll
    /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libgcc_s_seh-1.dll
    /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libstdc++-6.dll
    /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libwinpthread-1.dll
    /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libxml2-2.dll
    /usr/x86_64-w64-mingw32/sys-root/mingw/bin/zlib1.dll
    ut.exe

Deploy a cross compiled binary:

    $ peldd ut.exe -a | xargs cp -t /mnt/win/builds/

## License

Both the library and the program are licensed under the MIT license.

[1]: https://en.wikipedia.org/wiki/Portable_Executable
[2]: https://github.com/trailofbits/pe-parse
