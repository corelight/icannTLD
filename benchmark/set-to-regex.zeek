module icannTLD;

redef record DNS::Info += {
	effective_subdomain: string &log &optional;
	effective_domain: string &log &optional;
	icann_tld: string &log &optional;
};

########################################################
## begin Input Framework
# Use Input Framework to maintain list of ICANN TLD's
type Idx: record {
        tld: string;
};
global first_icannTLD_set: set[string] = set();
global second_icannTLD_set: set[string] = set();
global third_icannTLD_set: set[string] = set();
global fourth_icannTLD_set: set[string] = set();

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
}
## end Input Framework
########################################################

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

function FindTLD(c: connection)
	{
	# The ICANN TLD list is split by number of parts in the TLD then converted to regex.
	# Using those regex patterns, look for a match to determine how many TLD parts in the query.
	local tld_parts=1;
	local dot_query = "." + c$dns$query;
	if ( effective_tld_local in c$dns$query ) {
		c$dns$icann_tld = "local";
		c$dns$effective_domain = "local";
		c$dns$effective_subdomain = "";
		break;
	}
	if ( effective_tlds_4th_level in dot_query )
		tld_parts=4;
	else if ( effective_tlds_3rd_level in dot_query )
		tld_parts=3;
	else if ( effective_tlds_2nd_level in dot_query )
		tld_parts=2;
	# else if ( effective_tlds_1st_level in dot_query )
	# 	tld_parts=1;
	local icann_tld_raw = find_last(dot_query, extraction_regex[tld_parts]);
	c$dns$icann_tld = lstrip(icann_tld_raw, "\.");
	if (c$dns$icann_tld == c$dns$query) {
		c$dns$effective_domain = c$dns$query;
		c$dns$effective_subdomain = "";
	}
	else {
		local effective_domain_raw = find_last(dot_query, extraction_regex[tld_parts +1]);
		c$dns$effective_domain = lstrip(effective_domain_raw, "\.");
		if (c$dns$effective_domain == c$dns$query){
			c$dns$effective_subdomain = "";
		}
		else {
			c$dns$effective_subdomain = sub(c$dns$query, extraction_regex[tld_parts +1], "");
		}
	}	
}

########################################################
## begin added for testing only (remove for production)
export {
	option iterations: int = 2;
	option test_query: string = "domain.com.co";
}
redef exit_only_after_terminate=T;
global end_of_data_count: count = 0;
## end added for testing only (remove for production)
########################################################

event Input::end_of_data(name: string, source: string) {
    if (name == "first_icannTLD_set")
		effective_tlds_1st_level = set_to_regex(first_icannTLD_set, "\\.(~~)$");
	if (name == "second_icannTLD_set")
		effective_tlds_2nd_level = set_to_regex(second_icannTLD_set, "\\.(~~)$");
	if (name == "third_icannTLD_set")
		effective_tlds_3rd_level = set_to_regex(third_icannTLD_set, "\\.(~~)$");
	if (name == "fourth_icannTLD_set")
		effective_tlds_4th_level = set_to_regex(fourth_icannTLD_set, "\\.(~~)$");
########################################################
## begin added for testing only (remove for production)
	++end_of_data_count;
	if ( end_of_data_count == 4 ) {
		local c: connection;
		local dns_info: DNS::Info;
		c$dns = dns_info;
		c$dns$query=test_query;
		c$dns$icann_tld = "";
		c$dns$effective_domain = "";
		c$dns$effective_subdomain = "";
		local x = 0;
		local start_time = current_time();
		while ( ++x < iterations ) {
			FindTLD(c);
		}
		local end_time = current_time();
		print fmt("Time: %.6f", end_time - start_time) +" " +c$dns$query, c$dns$icann_tld, c$dns$effective_domain, c$dns$effective_subdomain, "";
		# print effective_tlds_4th_level;
		terminate();
		exit(0);
	}
## end added for testing only (remove for production)
########################################################
}

########################################################
## begin removed for testing (uncomment for production)
# event dns_end(c: connection, msg: dns_msg) {
#
# }
## end removed for testing (uncomment for production)
########################################################