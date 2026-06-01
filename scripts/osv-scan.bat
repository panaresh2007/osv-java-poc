@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  OSV Scanner - CVE Detection POC
::  Scan 1: Direct deps via pom.xml / lock files
::  Scan 2: Transitive deps via CycloneDX SBOM
::           - Uses committed bom.json if present in repo
::           - Generates via Maven if not present
::  Output: cve-direct.csv + cve-transitive.csv + cve-combined.csv
:: ============================================================

set OSV_EXE=C:\osv-poc\osv-scanner.exe
set PS_SCRIPT=C:\osv-poc\parse-osv.ps1
set MVN_EXE=C:\osv-poc\maven\apache-maven-3.9.6\bin\mvn
set WORK_DIR=C:\osv-poc\scan-temp
set RESULTS_DIR=C:\osv-poc\osv-results
set JAVA_HOME=C:\Program Files\Microsoft\jdk-17.0.19.10-hotspot
set PATH=%PATH%;%JAVA_HOME%\bin

cls
echo.
echo  ============================================================
echo   OSV Scanner - CVE Detection POC
echo   Direct + Transitive Dependency Scanning
echo  ============================================================
echo.

:: ── Check prerequisites ──────────────────────
if not exist "%OSV_EXE%"   ( echo  [ERROR] osv-scanner.exe not found & pause & exit /b 1 )
if not exist "%PS_SCRIPT%" ( echo  [ERROR] parse-osv.ps1 not found   & pause & exit /b 1 )

:: ── Ask for repo URL ─────────────────────────
echo  Enter your GitHub or ADO repository URL:
echo  Example: https://github.com/panaresh2007/osv-java-poc
echo.
set /p REPO_URL=  Repository URL: 
echo.
if "%REPO_URL%"=="" ( echo  [ERROR] No URL entered. & pause & exit /b 1 )

:: ── Kill Java and clean temp ──────────────────
taskkill /f /im java.exe >nul 2>&1
timeout /t 2 /nobreak >nul
cd /d C:\osv-poc
if exist "%WORK_DIR%" rmdir /s /q "%WORK_DIR%" 2>nul
if exist "%WORK_DIR%" (
    echo  [ERROR] Cannot delete temp folder. Close any open programs and retry.
    pause & exit /b 1
)

:: ── Clone repo ───────────────────────────────
echo  [1/6] Cloning repository...
git clone "%REPO_URL%" "%WORK_DIR%"
if errorlevel 1 ( echo  [ERROR] Clone failed. & pause & exit /b 1 )
echo  [OK]  Clone successful.
echo.

:: ── Create results folder ────────────────────
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set DT=%%I
set TIMESTAMP=%DT:~0,8%_%DT:~8,6%
set TIMESTAMP=%TIMESTAMP: =0%
for %%A in ("%REPO_URL%") do set REPO_NAME=%%~nA
set RUN_DIR=%RESULTS_DIR%\%REPO_NAME%_%TIMESTAMP%
mkdir "%RUN_DIR%" 2>nul

set JSON_DIRECT=%RUN_DIR%\scan-direct.json
set JSON_TRANSITIVE=%RUN_DIR%\scan-transitive.json
set CSV_DIRECT=%RUN_DIR%\cve-direct.csv
set CSV_TRANSITIVE=%RUN_DIR%\cve-transitive.csv
set CSV_COMBINED=%RUN_DIR%\cve-combined.csv

:: ── Detect lock files ────────────────────────
echo  [2/6] Detecting lock files...
set IS_MAVEN=0
set HAS_LOCK=0
if exist "%WORK_DIR%\pom.xml"           ( echo         pom.xml found           & set IS_MAVEN=1 & set HAS_LOCK=1 )
if exist "%WORK_DIR%\package-lock.json" ( echo         package-lock.json found & set HAS_LOCK=1 )
if exist "%WORK_DIR%\yarn.lock"         ( echo         yarn.lock found         & set HAS_LOCK=1 )
if exist "%WORK_DIR%\requirements.txt"  ( echo         requirements.txt found  & set HAS_LOCK=1 )
if exist "%WORK_DIR%\go.sum"            ( echo         go.sum found            & set HAS_LOCK=1 )
if exist "%WORK_DIR%\Cargo.lock"        ( echo         Cargo.lock found        & set HAS_LOCK=1 )
if exist "%WORK_DIR%\Gemfile.lock"      ( echo         Gemfile.lock found      & set HAS_LOCK=1 )
if %HAS_LOCK%==0 ( echo  [ERROR] No lock files found. & rmdir /s /q "%WORK_DIR%" & pause & exit /b 1 )
echo.

:: ── SCAN 1: Direct ───────────────────────────
echo  [3/6] SCAN 1 - Direct dependencies...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$osv='%OSV_EXE%'; $w='%WORK_DIR%'; $out='%JSON_DIRECT%';" ^
  "$lf=@();" ^
  "if(Test-Path \"$w\pom.xml\")           {$lf+='--lockfile';$lf+=\"$w\pom.xml\"};" ^
  "if(Test-Path \"$w\package-lock.json\") {$lf+='--lockfile';$lf+=\"$w\package-lock.json\"};" ^
  "if(Test-Path \"$w\yarn.lock\")         {$lf+='--lockfile';$lf+=\"$w\yarn.lock\"};" ^
  "if(Test-Path \"$w\requirements.txt\")  {$lf+='--lockfile';$lf+=\"$w\requirements.txt\"};" ^
  "if(Test-Path \"$w\go.sum\")            {$lf+='--lockfile';$lf+=\"$w\go.sum\"};" ^
  "if(Test-Path \"$w\Cargo.lock\")        {$lf+='--lockfile';$lf+=\"$w\Cargo.lock\"};" ^
  "if(Test-Path \"$w\Gemfile.lock\")      {$lf+='--lockfile';$lf+=\"$w\Gemfile.lock\"};" ^
  "$a=@('scan','source')+$lf+@('--format','json','--output-file',$out);" ^
  "& $osv @a 2>`$null;" ^
  "if(Test-Path $out){Write-Host '  [OK]  Direct scan complete.'}else{Write-Host '  [INFO] No direct CVEs found.'}"

echo.

:: ── SCAN 2: Transitive ───────────────────────
echo  [4/6] SCAN 2 - Transitive dependencies ^(SBOM^)...

if %IS_MAVEN%==0 (
    echo  [INFO] Transitive SBOM scan supported for Maven projects only. Skipping.
    goto :parse
)

:: ── Strategy 1: Use committed bom.json ───────
set BOM_FILE=
if exist "%WORK_DIR%\bom.json" (
    echo  [OK]  bom.json found in repo ^(committed^) - using directly.
    set BOM_FILE=%WORK_DIR%\bom.json
    goto :run_transitive
)

:: ── Strategy 2: Generate via Maven ───────────
echo  [INFO] No committed bom.json found - generating via Maven...
if not exist "%MVN_EXE%.cmd" (
    echo  [WARN] Maven not found at %MVN_EXE%. Skipping transitive scan.
    echo  [TIP]  Install Maven or commit bom.json to repo to enable transitive scanning.
    goto :parse
)

echo  Running Maven CycloneDX plugin...
echo  (Uses local cache - fast if plugin already downloaded)
echo.
:: Write Maven command to temp bat and call it
echo @echo off > "%TEMP%\run_mvn.bat"
echo cd /d "%WORK_DIR%" >> "%TEMP%\run_mvn.bat"
echo "%MVN_EXE%" org.cyclonedx:cyclonedx-maven-plugin:2.7.9:makeAggregateBom -DoutputFormat=json >> "%TEMP%\run_mvn.bat"
call "%TEMP%\run_mvn.bat"
set MVN_EXIT=%ERRORLEVEL%
del "%TEMP%\run_mvn.bat" 2>nul
echo  [DEBUG] Maven exit code: %MVN_EXIT%

if %MVN_EXIT% neq 0 (
    echo  [WARN] Maven SBOM generation failed. Skipping transitive scan.
    echo  [TIP]  Commit bom.json to repo to avoid this step.
    goto :parse
)

if not exist "%WORK_DIR%\target\bom.json" (
    echo  [WARN] bom.json not created. Skipping transitive scan.
    goto :parse
)

echo  [OK]  SBOM generated via Maven.
set BOM_FILE=%WORK_DIR%\target\bom.json

:: ── Run transitive scan ───────────────────────
:run_transitive
"%OSV_EXE%" scan source -L "%BOM_FILE%" --format json --output-file "%JSON_TRANSITIVE%" 2>nul
if exist "%JSON_TRANSITIVE%" (
    echo  [OK]  Transitive scan complete.
) else (
    echo  [WARN] Transitive scan produced no output.
)
echo.

:: ── Parse to CSV ─────────────────────────────
:parse
echo  [5/6] Generating CSV reports...

if exist "%JSON_DIRECT%"     powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -JsonFile "%JSON_DIRECT%"     -CsvFile "%CSV_DIRECT%"     -ScanType "Direct"
if exist "%JSON_TRANSITIVE%" powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -JsonFile "%JSON_TRANSITIVE%" -CsvFile "%CSV_TRANSITIVE%" -ScanType "Transitive"

if exist "%CSV_DIRECT%" (
    if exist "%CSV_TRANSITIVE%" (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=Import-Csv '%CSV_DIRECT%'; $t=Import-Csv '%CSV_TRANSITIVE%'; $all=$d+$t | Sort-Object @{E={switch($_.Severity){'CRITICAL'{0}'HIGH'{1}'MEDIUM'{2}'LOW'{3}default{4}}}}; $all | Export-Csv '%CSV_COMBINED%' -NoTypeInformation; Write-Host '  Combined:' $all.Count 'total CVEs'"
    ) else (
        copy "%CSV_DIRECT%" "%CSV_COMBINED%" >nul
        echo  [INFO] Only direct scan available - saved as combined.
    )
)
echo.

:: ── Summary ──────────────────────────────────
echo  [6/6] Summary...
echo.

set D_COUNT=0
set T_COUNT=0
set C_COUNT=0
if exist "%CSV_DIRECT%"     for /f %%A in ('powershell -NoProfile -Command "(Import-Csv '%CSV_DIRECT%').Count"')     do set D_COUNT=%%A
if exist "%CSV_TRANSITIVE%" for /f %%A in ('powershell -NoProfile -Command "(Import-Csv '%CSV_TRANSITIVE%').Count"') do set T_COUNT=%%A
if exist "%CSV_COMBINED%"   for /f %%A in ('powershell -NoProfile -Command "(Import-Csv '%CSV_COMBINED%').Count"')   do set C_COUNT=%%A

echo  ============================================================
echo   RESULTS SUMMARY
echo  ============================================================
echo.
echo   SCAN 1 - Direct deps     : %D_COUNT% CVEs  ^(pom.xml only^)
echo   SCAN 2 - Transitive deps : %T_COUNT% CVEs  ^(full dependency tree^)
echo   TOTAL COMBINED           : %C_COUNT% CVEs
echo.
echo   Results saved to: %RUN_DIR%
echo.

:: ── Cleanup ──────────────────────────────────
taskkill /f /im java.exe >nul 2>&1
timeout /t 2 /nobreak >nul
cd /d C:\osv-poc
rmdir /s /q "%WORK_DIR%" 2>nul

if exist "%CSV_COMBINED%" (
    echo  Opening combined CSV in Excel...
    start "" "%CSV_COMBINED%"
) else if exist "%CSV_DIRECT%" (
    start "" "%CSV_DIRECT%"
)
echo.
pause
