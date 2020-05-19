# icannTLD

## Script Description
Zeek script using the official ICANN Top-Level Domain (TLD) list with the Input Framework to extract the relevant information from a DNS query and mark whether it's trusted or not.  The source of the ICANN TLD's can be found here: https://publicsuffix.org/list/effective_tld_names.dat.  The Trusted Domains list is a custom list, created by the user, to filter domains during searches.

## Script Functions
icannTLD parses every DNS query and adds the following fields to the DNS Log.

| Field | Value | Description |
| ------ | ------ |------ |
| icann_tld | | This is the Top-Level Domain based on the official list of TLD's from ICANN. |
| icann_domain | | This is the Domain based on the official list of TLD's from ICANN. |
| icann_host_subdomain | | This is the remaining nodes of the query after the domain has been removed.  In some cases this is the subdomain, in other cases it's the host name, and in others it's host name and subdomain. |
| is_trusted_domain | true/false | Each query is marked true or false based on the icann_domain and a custom *trusted_domains.dat* file. |

### Note:
This script does not currently use any list for 1st level domains, (i.e. ".com"). If the Top Level Domain (tld) does not match the 2, 3 or 4 part regex patterns, it's assumed it is a 1st level tld.


## Installation/Setup
The files in the source_files folder **should be loaded into the sensor prior to loading this script package**.  They can be loaded directly into the sensor via the GUI or via the Corelight Client if desired.

Instructions for Open Source Zeek may vary.

	corelight-client -b <sensor_address> bro input upload --name 1st_level_public_icann.dat --file ./source_files/1st_level_public_icann.dat
	corelight-client -b <sensor_address> bro input upload --name 2nd_level_public_icann.dat --file ./source_files/2nd_level_public_icann.dat
	corelight-client -b <sensor_address> bro input upload --name 3rd_level_public_icann.dat --file ./source_files/3rd_level_public_icann.dat
	corelight-client -b <sensor_address> bro input upload --name 4th_level_public_icann.dat --file ./source_files/4th_level_public_icann.dat
	corelight-client -b <sensor_address> bro input upload --name trusted_domains.dat --file ./source_files/trusted_domains.dat
	zkg install https://gitlab.lagermann.net/james/icanntld

## Top-Level Domain Background
Today, anyone can buy a TLD so this list can change frequently.  ICANN updates the list several times a day, as changes are made, and it can be pulled daily.

TLDs are generally split into two categories:
	- ccTLDs are Country Code TLDs, such as .us, .jp and .uk
	- gTLDs are Generic TLDs and include the traditional names .com, .net, and .org.  Generic TLDs also include the new TLDs such as .info, .city, .microsoft, etc.

## Updating the ICANN TLD list on a Sensor
The list cannot be pulled directly from Mozilla.org and put on a Corelight/Zeek Sensor.  It will have to be filtered and formatted correctly first.  The included Ansible Playbook "mozilla_list_regex_import.yml" is an example of an Ansible playbook that will download the entire list, format it correctly, split it based on the number of top level domain parts, then upload all of the lists it to a Corelight Sensor using Ansible and the Corelight Client.

Update sensor_vars.yml as appropriate.  It is not recommended to store your passwords in the var file, use some type of password vault.  With so many options for password vaults, this example is using the var file for simplicity.

## Supporting files
The files in the temp folder will be replaced by "mozilla_list_regex_import.yml" playbook.  The *icann.dat files in the source_files folder will also be replaced by the "mozilla_list_regex_import.yml" playbook.  They are included here as examples and are accurate as of the date of this commit.  

The test-benchmarks folder contains a benchmark script that runs a test version of the script through a series of tests and measures the results.  The test script also has comments through out it with more details.  Comments have been removed from the production script.