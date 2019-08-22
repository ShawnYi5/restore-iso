chcp 437
rem deal vmware tools
move /y %WINDIR%\system32\VMUpgradeAtShutdownWXP.dll_bak %WINDIR%\system32\VMUpgradeAtShutdownWXP.dll


setlocal EnableDelayedExpansion
set current_path=%~f0
set current_dir=%~dp0
echo %current_path%
echo %current_dir%

cd /d %current_dir%
cd ..
start WaitSysI.exe killinstdrv 300
cd restore_log

rem deal firewall
"%current_dir%\..\TaskWorker.exe" enable_firewall

rem deal sql server 2005 hang
set temp_file_path=%current_dir%sc.txt
echo %temp_file_path%

set /a check_count=0
set /a check_max_count=16

:CHECK_SERVICE_START

set /a check_count+=1

set /a check_pending_count=0
set /a check_pending_max_count=32

sc qc MSSQLSERVER > "%temp_file_path%"
set sql_server_auto=0
find "START_TYPE         : 2   AUTO_START" "%temp_file_path%" >nul 2>&1 && set sql_server_auto=1
if "%sql_server_auto%"=="0" (
  goto EXIT_SERVICE_NOT_AUTO
)

sc query MSSQLSERVER > "%temp_file_path%"

set has_sql_server=1
find "The specified service does not exist as an installed service." "%temp_file_path%" >nul 2>&1 && set has_sql_server=0
if "%has_sql_server%"=="0" (
  goto EXIT_NOT_EXIST_SERVICE
)

set is_running=0
find "STATE              : 4  RUNNING" "%temp_file_path%" >nul 2>&1 && set is_running=1
if "%is_running%"=="1" (
  goto EXIT_DO_OK
)

:CHECK_PENDING

set /a check_pending_count+=1

set is_start_pending=0
find "STATE              : 2  START_PENDING" "%temp_file_path%" >nul 2>&1 && set is_start_pending=1
if "%is_start_pending%"=="0" (
  goto RETRY_CHECK
)

ping -n 10 127.0>nul
sc query MSSQLSERVER > "%temp_file_path%"

set is_start_pending=0
find "STATE              : 2  START_PENDING" "%temp_file_path%" >nul 2>&1 && set is_start_pending=1
if "%is_start_pending%"=="0" (
  goto RETRY_CHECK
)

if %check_pending_count% lss %check_pending_max_count% (
  goto CHECK_PENDING
)

sc stop MSSQLSERVER
ping -n 30 127.0>nul
sc start MSSQLSERVER
goto EXIT_DO_OK

:RETRY_CHECK
if %check_count% gtr %check_max_count% (
  goto EXIT_TIMEOUT
)
ping -n 30 127.0>nul
goto CHECK_SERVICE_START

:EXIT_DO_OK
  echo start service ok
  goto EXIT_KILL_SELF

:EXIT_NOT_EXIST_SERVICE
  echo not exist service
  goto EXIT_KILL_SELF

:EXIT_SERVICE_NOT_AUTO
  echo not auto start service
  goto EXIT_KILL_SELF  
  
:EXIT_TIMEOUT
  echo timeout
  goto EXIT_KILL_SELF
  
:EXIT_KILL_SELF
  rem del /F /Q "%current_path%"
  exit 0


