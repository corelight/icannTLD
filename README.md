# icannTLD
Zeek script using Input Framework to get ICANN Top-Level Domain (TLD), effective domain, and effective subdomain of a DNS query.  The source of the Input Framework is https://publicsuffix.org/list/effective_tld_names.dat.

Today, anyone can buy any TLD. This list is updated several times a day and can be pulled daily.

TLDs are generally split into two categories:
	- ccTLDs are Country Code TLDs, such as .us, .jp and .uk
	- gTLDs are Generic TLDs and include the traditional names .com, .net, and .org.  Generic TLDs also include the new TLDs such as .info, .city, .microsoft, etc.

The list cannot be pulled directly from Mozilla.org and put on a Corelight/Zeek Sensor.  It will have to be filtered and formatted correctly first.  The included Ansible Playbook "mozilla_list_regex_import.yml" is an example of a playbook that will download the entire list, format it correctly, split it based on number of top level domain parts, then upload all of the lists it to a Corelight Sensor using Ansible and the Corelight Client.

Update sensor_vars.yml as appropriate.  It is not recommended to store your passwords in the var file, use a password vault.  With so many options for password vaults, this example is using the var file for simplicity.

The files in the temp folder will be replaced by "mozilla_list_regex_import.yml" playbook.  The *icann.dat files in the source_files folder will also be replaced by the "mozilla_list_regex_import.yml" playbook.  They are included here as examples and are accurate as of the date of this commit.  

The files in the source_files folder SHOULD BE LOADED INTO THE SENSOR PRIOR TO LOADING THIS SCRIPT PACKAGE.  They can be loaded directly into the sensor via the GUI or via the Corelight Client if desired.

This script does not currently use any list for 1st level domains, (i.e. ".com"). If the Top Level Domain (tld) does not match the 2, 3 or 4 part regex patterns, it's assumed it is a 1st level tld. The script can be modified to only list ICANN tld's but it does not currently.

This script also identifies trusted domains with a true or false (trusted_domain: T or F).
