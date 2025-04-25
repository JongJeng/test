# SHM test
 ## 启动1个pub
 ./ThroughputTest publisher --reliability=besteffort --domain 0 --shared_memory=on --subscribers=10 --time=20 --file=payloads_demands.csv --recovery_time=50 
 ## 启动10个sub               
 ./ThroughputTest subscriber --reliability=besteffort --domain 0 --shared_memory=on


 # UDP test
 ## 启动1个pub
 ./ThroughputTest publisher --reliability=besteffort --domain 0 --shared_memory=off --subscribers=10 --time=20 --file=payloads_demands.csv --recovery_time=50
 
 ## 启动10个sub                 
 ./ThroughputTest subscriber --reliability=besteffort --domain 0 --shared_memory=off


 # ZeroCopy test
 ## 启动1个pub
 ./ThroughputTest publisher --reliability=besteffort --domain 0 --shared_memory=on --subscribers=10 --time=20 --file=payloads_demands.csv --recovery_time=10 --data_sharing=on --data_loans

 ./ThroughputTest publisher --reliability=besteffort --domain 0 --shared_memory=on --data_sharing=on --data_loans --subscribers=10 --time=20 --recovery_time=10 --demand=100 --msg_size=10485760

    
 ## 启动10个sub             
 ./ThroughputTest subscriber --reliability=besteffort --domain 0 --shared_memory=on --data_sharing=on --data_loans



4096;100
512000;100
2097152;100
10485760;100