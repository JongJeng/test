#!/bin/sh
# 要启动的进程
process_name="./2.14.x/ThroughputTest subscriber --reliability=besteffort --domain 0 --shared_memory=on --data_sharing=on --data_loans"

# 启动10个进程
for i in 1 2 3 4 5 6 7 8 9 10
do
    # 启动进程并在后台运行
    $process_name & 
    
    echo "启动进程 $i"
done

echo "所有进程已启动"
 
