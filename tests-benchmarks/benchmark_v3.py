#!/usr/bin/env python3

#Version 2 of benchmark.py will measure the duration of running the target script and output the test query and durations.
#If the target script returns the query_info results, this version will display those results instead of the test query.
import argparse
import subprocess
import time
#TEST_QUERIES = ["hostname","hostname.local","1.domain.com","domain.com","1.domain.com","2.1.domain.com","3.2.1.domain.com","4.3.2.1.domain.com","5.4.3.2.1.domain.com","6.5.4.3.2.1.domain.com","7.6.5.4.3.2.1.domain.com"]
TEST_QUERIES = ["hostname","hostname.local","com.co","1.domain.com","domain.com","domain.us","domain.mo.us","domain.k12.mo.us","1.domain.us","1.domain.mo.us","1.domain.k12.mo.us","2.1.domain.us","2.1.domain.mo.us","2.1.domain.k12.mo.us","3.2.1.domain.us","3.2.1.domain.mo.us","3.2.1.domain.k12.mo.us","4.3.2.1.domain.us","4.3.2.1.domain.mo.us","4.3.2.1.domain.k12.mo.us","5.4.3.2.1.domain.us","5.4.3.2.1.domain.mo.us","5.4.3.2.1.domain.k12.mo.us","6.5.4.3.2.1.domain.us","6.5.4.3.2.1.domain.mo.us","6.5.4.3.2.1.domain.k12.mo.us","7.6.5.4.3.2.1.domain.us","7.6.5.4.3.2.1.domain.mo.us","7.6.5.4.3.2.1.domain.k12.mo.us"]
def main():
    parser = argparse.ArgumentParser(description='time zeek')
    parser.add_argument('script', metavar='script.zeek', type=str, help='script to run')
    parser.add_argument('--iterations', dest='iterations', type=int, help='Run for this many iterations')
    args = parser.parse_args()
    for q in TEST_QUERIES:
        results = []
        q_info = []
        q_time_results = []
        for _ in range(3):
            start = time.perf_counter()
            query_info = subprocess.run(["zeek", args.script, "icannTLD::iterations=" +str(args.iterations), "icannTLD::test_query=" +q], stdout=subprocess.PIPE)
            end = time.perf_counter()
            duration = end-start
            results.append(duration)
            q_info = query_info.stdout.decode('ascii').strip()
            title, (q_time), out_q, out_sd, out_d, out_tld, out_td = q_info.split()
            q_time_results.append(float(q_time))
        if query_info.stdout.decode('ascii') == '':
            print(q, "script time ".join("{:0.3f}".format(d) for d in results))
        else:
            avg_s = sum(results) / len(results)
            avg_q = sum(q_time_results) / len(q_time_results)
            qps = args.iterations / avg_q
            print(out_q, out_sd, out_d, out_tld, out_td, " avg_script_time:","{:0.3f}".format(avg_s)," avg_query_time:","{:0.3f}".format(avg_q), " qps:",f"{qps:,.1f}")
if __name__ == "__main__":
    main()