# icannTLD Benchmarking

The benchmark folder contains modified versions of the scripts for benchmark testing.  Because the finial scripts read streams of packets and the test environment is not a full Sensor, the scripts are modified to use a static list of DNS queries for testing.

Each script can have multiple versions to test and compare different functions within the script.  Add the suffix _benchmark to the name of the script and add comments to the beginning of the script with a description of the uniqueness that is being tested in that version.

Upload the results of the benchmark test with the name of the _benchmark script with the additional _results added to the name.
