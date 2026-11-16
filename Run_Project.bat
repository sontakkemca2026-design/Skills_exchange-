
@echo off
cd /d C:\CampusSkillExchange

set PATH=C:\msys64\ucrt64\bin;%PATH%

g++ -std=c++17 main.cpp -o campus_web.exe -I"C:\msys64\ucrt64\include\mariadb" -L"C:\msys64\ucrt64\lib" -lws2_32 -lmariadb

if errorlevel 1 (
    echo Compilation failed!
    pause
    exit /b
)

campus_web.exe
pause
