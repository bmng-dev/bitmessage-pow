vcvarsall.bat x86
CL /I C:\OpenSSL-Win32\include /INCREMENTAL bmpow.c /MT /link /DLL /OUT:bmpow32.dll /LIBPATH:"C:\OpenSSL-Win32\lib" libeay32.lib ws2_32.lib
