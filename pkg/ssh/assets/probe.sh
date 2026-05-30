#!/bin/sh
export LC_ALL=C
while true; do
awk 'BEGIN {
    getline < "/proc/uptime"; split($0, up); close("/proc/uptime");
    printf "{\"type\":\"sys\",\"uptime\":%d}\n", up[1];
    getline < "/proc/loadavg"; split($0, la); close("/proc/loadavg");
    printf "{\"type\":\"load\",\"load\":\"%s %s %s\"}\n", la[1], la[2], la[3];
    cores=0;
    while ((getline < "/proc/stat") > 0) {
        if ($1 == "cpu") {
            split($0, st);
            printf "{\"type\":\"cpu\",\"user\":%d,\"nice\":%d,\"sys\":%d,\"idle\":%d,\"iowait\":%d,\"irq\":%d,\"softirq\":%d,\"steal\":%d}\n", st[2], st[3], st[4], st[5], st[6], st[7], st[8], st[9];
        } else if ($1 ~ /^cpu[0-9]+$/) {
            cores++;
        }
    }
    close("/proc/stat");
    if(cores==0) cores=1;
    printf "{\"type\":\"cores\",\"count\":%d}\n", cores;
    while ((getline < "/proc/meminfo") > 0) {
        if ($1 == "MemTotal:") mt=$2;
        else if ($1 == "MemFree:") mf=$2;
        else if ($1 == "Buffers:") mb=$2;
        else if ($1 == "Cached:") mc=$2;
        else if ($1 == "MemAvailable:") ma=$2;
    }
    close("/proc/meminfo");
    if (ma=="") ma=mf+mb+mc;
    printf "{\"type\":\"mem\",\"total\":%d,\"available\":%d}\n", mt, ma;
}'
df -P -k 2>/dev/null | awk 'NR>1 && $1 ~ /^\/dev\// && $1 !~ /loop/ {
    printf "{\"type\":\"disk\",\"mount\":\"%s\",\"total\":%d,\"used\":%d}\n", $6, $2, $3;
}'
cat /proc/[0-9]*/stat 2>/dev/null | awk '
{
    pid=$1;
    match($0, /\(.*?\)/);
    comm=substr($0, RSTART+1, RLENGTH-2);
    gsub(/\\/, "\\\\", comm);
    gsub(/"/, "\\\"", comm);
    rest=substr($0, RSTART+RLENGTH);
    split(rest, a, " ");
    printf "{\"type\":\"proc\",\"pid\":%d,\"name\":\"%s\",\"state\":\"%s\",\"utime\":%d,\"stime\":%d,\"rss_kb\":%d}\n", pid, comm, a[1], a[12], a[13], a[22]*4;
}'
echo '{"type":"eof"}'
sleep 2
done
