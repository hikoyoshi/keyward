@echo off
rem Builds the Keyward portable zip: tests, both executables, README.txt -> dist\Keyward-portable-<date>.zip
setlocal
cd /d "%~dp0"

for /f %%d in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd"') do set STAMP=%%d

echo [1/3] go test
go test -short ./... || goto :fail

echo [2/3] go build
go build -tags desktop,production -ldflags "-H windowsgui -s -w" -o build\keyward.exe . || goto :fail
go build -ldflags "-s -w" -o build\keyward-mcp.exe .\cmd\keyward-mcp || goto :fail

echo [3/3] package
if exist dist\Keyward rmdir /s /q dist\Keyward
mkdir dist\Keyward || goto :fail
copy /y build\keyward.exe dist\Keyward\ >nul || goto :fail
copy /y build\keyward-mcp.exe dist\Keyward\ >nul || goto :fail
copy /y portable\README.txt dist\Keyward\ >nul || goto :fail
copy /y portable\README.zh-TW.txt dist\Keyward\ >nul || goto :fail
copy /y ..\LICENSE dist\Keyward\LICENSE.txt >nul || goto :fail
powershell -NoProfile -Command "Compress-Archive -Path 'dist\Keyward' -DestinationPath 'dist\Keyward-portable-%STAMP%.zip' -Force" || goto :fail

echo.
echo Done: dist\Keyward-portable-%STAMP%.zip
exit /b 0

:fail
echo.
echo Build failed.
exit /b 1
