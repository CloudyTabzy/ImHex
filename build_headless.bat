@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
set VCPKG_ROOT=C:\vcpkg
cmake --build build/vs2022 --target imhex_all
