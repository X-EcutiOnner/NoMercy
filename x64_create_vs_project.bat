@echo off

if [%1]==[] goto usage

rmdir /s /q .vs_proj_x64

mkdir .vs_proj_x64

pushd .vs_proj_x64

cmake .. -DCMAKE_BUILD_TYPE=%1

popd

@echo Project make done!
goto :eof

:usage
@echo Usage: %0 ^<build_type^>
PAUSE
exit /B 1