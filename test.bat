@echo off



@rem chcp 65001 UTF-8的
@rem chcp 936 可以换回默认的GBK
@rem chcp 437 是美国英语
chcp 65001
@rem     命令1 & 命令2 & 命令3 ... (无论前面命令是否故障,照样执行后面)
@rem     命令1 && 命令2 && 命令3....(仅当前面命令成功时,才执行后面)
@rem     命令1 || 命令2 || 命令3.... (仅当前面命令失败时.才执行后面)

set str1=1.DevDebug
set str2=2.DevRelease
set str3=3.ProdDebug
set str4=4.ProdRelease


echo %tips%
echo %str1%
echo %str2%
echo %str3%
echo %str4%
@rem set tips= 请选择你的环境:
set /p a=请选择你的环境:

set tips_str=install
set splashactivity=

@rem choice /c 1234 /n /m "Please choice:"

if "%a%"=="1" (

call :execute %str1%

)
if "%a%"=="2" (


call :execute %str2%

)
if "%a%"=="3" (

call :execute %str3%

)
if "%a%"=="4" (

call :execute %str4%

)



:execute
    SET temp_str=%1
    echo The current environment: %temp_str%
    gradlew %tips_str%%temp_str:~2% && adb shell am start -n %splashactivity% & goto:move



:move

set copy_path=.\app\build\outputs\apk
echo %copt_path%
echo %~dp0
rd /s /q .\temp
md temp
xcopy /e /i %copy_path% %~dp0\temp && rd /s /q %copy_path%
echo OK & goto:ending



goto start
@rem 当前盘符：%~d0
@rem 当前路径：% cd %
@rem 当前执行命令行：%0
@rem 当前bat文件路径：%~dp0
@rem 当前bat文件短路径：%~sdp0
@rem 当前批处理全路径：%~f0


@rem for /f "delims=\" %%a in ('dir /b /a-d /o-d "%~dp0\*"') do (
@rem   echo %%a：文件完整信息
@rem  echo %%~da：保留文件所在驱动器信息
@rem  echo %%~pa：保留文件所在路径信息
@rem  echo %%~na：保留文件名信息
@rem  echo %%~xa：保留文件后缀信息
@rem echo %%~za：保留文件大小信息
@rem  echo %%~ta：保留文件修改时间信息
@rem  echo %%~dpa：保留文件所在驱动器和所在路径信息
@rem echo %%~nxa：保留文件名及后缀信息
@rem echo %%~pnxa：保留文件所在路径及文件名和后缀信息
@rem echo %%~dpna：保留文件驱动器、路径、文件名信息
@rem  echo %%~dpnxa：保留文件驱动器、路径、文件名、后缀信息
@rem )
:start



:ending
  echo end!!!



