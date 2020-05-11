# icannTLD
Zeek script using Input Framework to get ICANN TLD, effective domain, and effective subdomain of a DNS query.  The source of the Input Framework is https://publicsuffix.org/list/effective_tld_names.dat.

This list is updated several times a week and can be pulled daily.

The list cannot be pulled directly from Mozilla.org and put on a Corelight/Zeek Sensor.  It will have to be filtered and formatted correctly first.  The Ansible Playbook "mozilla_list_regex_import.yml" in this repository is an example of a playbook that will download the entire list, format it correctly, split it based on number of top level domain parts, then upload all of the lists it to a Corelight Sensor using Ansible and the Corelight Client.

Update sensor_vars.yml as appropriate.  It is not recommended to store your passwords in the var file, use a password vault.  With so many options for password vaults, this example is using the var file for simplicity.

The files in the temp folder will be replaced by "mozilla_list_regex_import.yml" playbook.  They are included here as examples.

This script does not currently use any list for 1st level domains, (i.e. ".com"). If the Top Level Domain (tld) does not match the 2, 3 or 4 part regex patterns, it's assumed it is a 1st level tld. The script can be modified to only list ICANN tld's but it does not currently.