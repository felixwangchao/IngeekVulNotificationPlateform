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

# 获取当前路径
cur_dir=$(pwd)

# 写入add_task.sh
echo "#!/bin/sh">add_task.sh
echo "export  PYTHONPATH=/usr/bin/python" >> add_task.sh
echo "python $cur_dir/notf.py" >> add_task.sh
chmod +x $cur_dir/add_task.sh

# 写入crontab,每天早晨11:30和下午5:30分别执行一次

echo "30 11 * * * $cur_dir/add_task.sh" > /tmp/vulnotiftask
echo "30 17 * * * $cur_dir/add_task.sh" >> /tmp/vulnotiftask
cat /tmp/vulnotiftask | crontab
rm /tmp/vulnotiftask






