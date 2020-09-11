#!/bin/bash

#gradlew -p D:\\workspace\\xizileyuan\\kuaiwan_android -i assembleProDDebug
apk_path=./app/build/outputs/apk/prod/debug
con_gradle=./comlib/build.gradle
sdk_path="sdk.dir=/android/sdk/oo"
echo "请选择："
BUILD_TARGETS="dev uat prod"

for i in $BUILD_TARGETS
  do
  case $i in
  dev)
  
  ;;
  uat)

  ;;
  prod)

  ;;

  esac
  echo $i
done
read input
      if [[ $input == dev ]];then
      #sed 's/要被取代的字串/新的字串/g'
      sed  -i 's/sdk.dir/$sdk_path/g' local.properties
      #echo cat local.properties;
      awk '{print}' local.properties #打印文件
      #cat local.properties | while read line; do echo sdk  $line ; done #打印文件
      elif [[ $input == uat ]]; then
       rm -rf $apk_path
      elif [ $input == prod ]; then
         echo "$input do samething"

fi


