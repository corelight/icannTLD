module icannTLD;

redef record DNS::Info += {
	is_trusted_domain: string &log &optional;
	icann_host_subdomain: string &log &optional;
	icann_domain: string &log &optional;
	icann_tld: string &log &optional;
};

## define regex pattern place holders to find TLDs
global effective_tlds_1st_level: pattern = /./ &redef;
global effective_tlds_2nd_level: pattern = /./ &redef;
global effective_tlds_3rd_level: pattern = /./ &redef;
global effective_tlds_4th_level: pattern = /./ &redef;
const effective_tld_local: pattern = /(.*(\.local))|(^[^\.]+)$/;

## define regex patterns for domain and top level domains
const extraction_regex: table[count] of pattern = {
	[1] = /\.[^\.]+$/,
	[2] = /\.[^\.]+\.[^\.]+$/,
	[3] = /\.[^\.]+\.[^\.]+\.[^\.]+$/,
	[4] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+$/,
	[5] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+$/,
	[6] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]\.[^\.]+$/,
};

########################################################
## begin Input Framework
# Use Input Framework to maintain list of ICANN TLD's
type Idx: record {
	tld: string;
};
type Idx_td: record {
	trusted_domain: string;
};
global first_icannTLD_set: set[string] = set();
global second_icannTLD_set: set[string] = set();
global third_icannTLD_set: set[string] = set();
global fourth_icannTLD_set: set[string] = set();
global trusted_domains_set: set[string] = set();

event zeek_init() &priority=10 {
	Input::add_table([$source="1st_level_public_icann.dat", $name="first_icannTLD_set",
					$idx=Idx, $destination=first_icannTLD_set,
					$mode=Input::REREAD]);
	Input::add_table([$source="2nd_level_public_icann.dat", $name="second_icannTLD_set",
					$idx=Idx, $destination=second_icannTLD_set,
					$mode=Input::REREAD]);
	Input::add_table([$source="3rd_level_public_icann.dat", $name="third_icannTLD_set",
					$idx=Idx, $destination=third_icannTLD_set,
					$mode=Input::REREAD]);
	Input::add_table([$source="4th_level_public_icann.dat", $name="fourth_icannTLD_set",
					$idx=Idx, $destination=fourth_icannTLD_set,
					$mode=Input::REREAD]);
	Input::add_table([$source="trusted_domains.dat", $name="trusted_domains_set",
					$idx=Idx_td, $destination=trusted_domains_set,
					$mode=Input::REREAD]);
	effective_tlds_1st_level = set_to_regex(first_icannTLD_set, "\\.(~~)$");
	effective_tlds_2nd_level = set_to_regex(second_icannTLD_set, "\\.(~~)$");
	effective_tlds_3rd_level = set_to_regex(third_icannTLD_set, "\\.(~~)$");
	effective_tlds_4th_level = set_to_regex(fourth_icannTLD_set, "\\.(~~)$");
}
## end Input Framework
########################################################

# The ICANN TLD list is split by number of parts in the TLD then converted to regex.
# Using those regex patterns, look for a match to determine how many TLD parts in the query.
# Then use the appropriate regex pattern to extract the desired value.
event dns_end(c: connection, msg: dns_msg) {
	if ( c?$dns && c$dns?$query ) {
		c$dns$is_trusted_domain = "false";
		
		# Is the query for a hostname or does it end in .local?
		if ( effective_tld_local in c$dns$query ) {
			c$dns$icann_tld = "local";
			c$dns$icann_domain = "local";
			c$dns$icann_host_subdomain = "";
			c$dns$is_trusted_domain = "true";
			break;
		}

		local tld_parts=1;
		local dot_query = "." + c$dns$query;
		# Find how many parts are in the tld.
		if ( effective_tlds_4th_level in dot_query )
			tld_parts=4;
		else if ( effective_tlds_3rd_level in dot_query )
			tld_parts=3;
		else if ( effective_tlds_2nd_level in dot_query )
			tld_parts=2;


		# Use regex patterns to extract the desired values based on how many parts are in the tld.
		local icann_tld_raw = find_last(dot_query, extraction_regex[tld_parts]);
		c$dns$icann_tld = lstrip(icann_tld_raw, "\.");
		if (c$dns$icann_tld == "in-addr.arpa") {
			c$dns$icann_domain = "in-addr.arpa";
			c$dns$icann_host_subdomain = "";
			c$dns$is_trusted_domain = "true";
			break;
		}
		
		if (c$dns$icann_tld == c$dns$query) {
			c$dns$icann_domain = c$dns$query;
			c$dns$icann_host_subdomain = "";
		}
		else {
			local icann_domain_raw = find_last(dot_query, extraction_regex[tld_parts +1]);
			c$dns$icann_domain = lstrip(icann_domain_raw, "\.");
			if (c$dns$icann_domain == c$dns$query){
				c$dns$icann_host_subdomain = "";
			}
			else {
				c$dns$icann_host_subdomain = sub(c$dns$query, extraction_regex[tld_parts +1], "");
			}
		}

		if (c$dns$icann_domain in trusted_domains_set) {
			c$dns$is_trusted_domain = "true";
		}
	}
}

########################################################
## begin set_to_regex
# convert ICANN TLD set to regex as it's updated
event Input::end_of_data(name: string, source: string) {
    if (name == "first_icannTLD_set")
		effective_tlds_1st_level = set_to_regex(first_icannTLD_set, "\\.(~~)$");
	if (name == "second_icannTLD_set")
		effective_tlds_2nd_level = set_to_regex(second_icannTLD_set, "\\.(~~)$");
	if (name == "third_icannTLD_set")
		effective_tlds_3rd_level = set_to_regex(third_icannTLD_set, "\\.(~~)$");
	if (name == "fourth_icannTLD_set")
		effective_tlds_4th_level = set_to_regex(fourth_icannTLD_set, "\\.(~~)$");
}
## end set_to_regex
########################################################
