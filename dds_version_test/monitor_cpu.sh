#!/bin/bash

# 检查是否提供了进程名
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <process_name>"
    exit 1
fi

PROCESS_NAME=$1

ps -aux | grep "$PROCESS_NAME"

pidstat -C "ThroughputTest" -p ALL 1


# # 查找进程名对应的所有 PID
# PIDS=$(pgrep "$PROCESS_NAME")

# # 检查是否找到了进程
# if [ -z "$PIDS" ]; then
#     echo "No processes found for '$PROCESS_NAME'"
#     exit 1
# fi

# # 输出 PID 列表
# echo "Monitoring the following PIDs:"
# echo "$PIDS"

# # 构建 pidstat 的 -p 选项
# PID_ARGS=""
# for PID in $PIDS; do
#     PID_ARGS="$PID_ARGS -p $PID"
# done

# # 监控进程的 CPU 和内存使用情况
# eval pidstat -h -u -r $PID_ARGS 1


# 使用示例：
# bash monitor_cpu.sh LatencyTest > data.txt
# bash monitor_cpu.sh ThroughputTest > data.txt
