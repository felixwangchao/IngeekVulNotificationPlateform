#!/bin/sh

# 安装pip
sudo apt-get install python-pip python-dev build-essential 
sudo pip install --upgrade pip 
sudo pip install --upgrade virtualenv 

# 安装lxml模块以及相关依赖
sudo apt-get install libxml2 libxml2-dev  
sudo apt-get install libxlst libxslt-dev 
sudo apt-get install python-libxml2 python-libxslt
sudo apt-get install lxml

# 安装bs4模块
sudo apt-get install python-bs4 python-bs4-doc  




