##! This module contains some convenience mechanisms for extracting TLDs
##! and domains from fully qualified domain names using data available
##! from Mozilla which can be found here:
##!   https://publicsuffix.org/list/effective_tld_names.dat
##!
##! Author: Seth Hall <seth@icir.org>

module icannTLD;

redef record DNS::Info += {
	effective_subdomain: string &log &optional;
	effective_domain: string &log &optional;
	effective_tld: string &log &optional;
};

const effective_tlds_1st_level: pattern = /DEFINED_IN_SEPARATE_FILE/ &redef;
const effective_tlds_2nd_level: pattern = /DEFINED_IN_SEPARATE_FILE/ &redef;
const effective_tlds_3rd_level: pattern = /DEFINED_IN_SEPARATE_FILE/ &redef;
const effective_tlds_4th_level: pattern = /DEFINED_IN_SEPARATE_FILE/ &redef;

const effective_tld_local: pattern = /(.*(\.local))|(^[^\.]+)$/;
const effective_tld_pattern: pattern    = /DEFINED_IN_SEPARATE_FILE/ &redef;
const effective_domain_pattern: pattern = /DEFINED_IN_SEPARATE_FILE/ &redef;
@load ./tld-data
# These are used to match the depth of domain components desired since
# patterns can't (and probably shouldn't be) compiled dynamically).
const tld_extraction_suffixes: table[count] of pattern = {
	[1] = /\.[^\.]+$/,
	[2] = /\.[^\.]+\.[^\.]+$/,
	[3] = /\.[^\.]+\.[^\.]+\.[^\.]+$/,
	[4] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+$/,
	[5] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+$/,
	[6] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]\.[^\.]+$/,
};

function effective_tld(c: connection)
	{
	local query = "."+c$dns$query;
	if ( effective_tld_local in c$dns$query ) {
		c$dns$effective_tld = "local";
		c$dns$effective_domain = "local";
		c$dns$effective_subdomain = "";
		break;
	}
	local depth=1;
	if ( effective_tlds_4th_level in query )
		depth=4;
	else if ( effective_tlds_3rd_level in query )
		depth=3;
	else if ( effective_tlds_2nd_level in query )
		depth=2;
	# set dns log vaules
	local q_tld = find_last(query, tld_extraction_suffixes[depth]);
	c$dns$effective_tld = lstrip(q_tld, "\.");
	local q_domain = find_last(query, tld_extraction_suffixes[depth +1]);
	c$dns$effective_domain = lstrip(q_domain, "\.");
	c$dns$effective_subdomain = sub(c$dns$query, tld_extraction_suffixes[depth +1], "");
	if ( c$dns$effective_domain == "" )
		c$dns$effective_domain = c$dns$query;
	if ( c$dns$effective_subdomain == c$dns$query)
		c$dns$effective_subdomain = "";
	}

#event bro_init()
#	{
#	local domains = vector("blah.www.google.com", "www.google.co.uk", "www.easa.eu.int");
#	for ( i in domains )
#		{
#		print fmt("Original: %s", domains[i]);
#		print fmt("    Effective TLD: %s", DomainTLD::effective_tld(domains[i]));
#		print fmt("    Effective domain: %s", DomainTLD::effective_domain(domains[i]));
#		}
#	}

#added for benchmark testing
export {
	option iterations: int = 2;
	option test_query: string = "com.co";
}
redef exit_only_after_terminate=T;
event zeek_init() {
	#for benchmark testing only (to replace pcap)
	local c: connection;
	local dns_info: DNS::Info;
	c$dns = dns_info;
	c$dns$query=test_query;
	c$dns$effective_tld = "";
	c$dns$effective_subdomain = "";
    local x = 0;
	local start_time = current_time();
    while ( ++x < iterations ) {
        effective_tld(c);
    }
	local end_time = current_time();
	print fmt("Time: %.6f", end_time - start_time) +" " +c$dns$query, c$dns$effective_tld, c$dns$effective_domain, c$dns$effective_subdomain, "";
	terminate();
	exit(0);
}