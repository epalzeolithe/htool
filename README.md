# htool

Python3 tool to manipulate last Huawei 4G/LTE routeur

For example : 
python3 htool.py -v -ip 192.168.10.1 -u admin -p password -sb 4
> this force 1800Mhz mode


Here's the automatic help :

usage: htool.py [-h] [-ip IP] [-u U] [-p P] [-gb] [-sb SB] [-r] [-v] [-sms][-phone PHONE] [-msg MSG] [-s] [-sloop] [-stat] [-statloop]

> optional arguments:
  -h, --help    show this help message and exit
  
  -ip IP        router IP
  
  -u U          username
  
  -p P          password
  
  -gb           getband in XML format
  
  -sb SB        setband 700Mhz=8000000 800Mhz=80000 1800Mz=4 2100Mhz=1 2600Mhz=40 (you can add for aggregations)
                
  -r            reboot
  
  -v            verbose mode
  
  -sms          send sms
  
  -phone PHONE  phone number
  
  -msg MSG      message to send
  
  -s            signal infos
  
  -sloop        signal infos
  
  -stat         get traffic-statistics
  
  -statloop     get traffic-statistics in loop, download rate in bytes / s
  
