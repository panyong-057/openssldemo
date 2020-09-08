@echo off



@rem chcp 65001 UTF-8的
@rem chcp 936 可以换回默认的GBK
@rem chcp 437 是美国英语
chcp 65001
@rem     命令1 & 命令2 & 命令3 ... (无论前面命令是否故障,照样执行后面)
@rem     命令1 && 命令2 && 命令3....(仅当前面命令成功时,才执行后面)
@rem     命令1 || 命令2 || 命令3.... (仅当前面命令失败时.才执行后面)

set str1=1.Debug
set str2=2.Release

echo %tips%
echo %str1%
echo %str2%
@rem set tips= 请选择你的环境:
set /p a=请选择你的环境:

set tips_str=install
set splashactivity=com.example.jin.ende_test/.MainActivity

@rem choice /c 1234 /n /m "Please choice:"

if "%a%"=="1" (

call :execute %str1%

)
if "%a%"=="2" (


call :execute %str2%

)




:execute
    SET temp_str=%1
    echo The current environment: %temp_str%
    gradlew %tips_str%%temp_str:~2% && adb shell am start -n %splashactivity% & goto:end

:end
  echo end!!!



