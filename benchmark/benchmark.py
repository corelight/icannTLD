#!/usr/bin/env python3

#Version 1 of benchmark.py will measure the duration of running the target script and output the test query and durations.
import argparse
import subprocess
import time
TEST_QUERIES = ["google.com","1.google.com","2.1.google.com","3.2.1.google.com","4.3.2.1.google.com","5.4.3.2.1.google.com","6.5.4.3.2.1.google.com","7.6.5.4.3.2.1.google.com"]
def main():
    parser = argparse.ArgumentParser(description='time zeek')
    parser.add_argument('script', metavar='script.zeek', type=str, help='script to run')
    parser.add_argument('--iterations', dest='iterations', type=int, help='Run for this many iterations')
    args = parser.parse_args()
    for q in TEST_QUERIES:
        results = []
        for _ in range(3):
            start = time.perf_counter()
            subprocess.call(["zeek", args.script, "icannTLD::iterations=" +str(args.iterations), "icannTLD::test_query=" +q])
            end = time.perf_counter()
            duration = end-start
            results.append(duration)
        print(q, " ".join("{:0.3f}".format(d) for d in results))
if __name__ == "__main__":
    main()