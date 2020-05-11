module icannTLD;

redef record DNS::Info += {
	effective_subdomain: string &log &optional;
	effective_domain: string &log &optional;
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

# The ICANN TLD list is split by number of parts in the TLD then converted to regex.
# Using those regex patterns, look for a match to determine how many TLD parts in the query.
# Then use the appropriate regex pattern to extract the desired value.
event dns_end(c: connection, msg: dns_msg) {
	local tld_parts=1;
	local dot_query = "." + c$dns$query;
	
	# Is the query for a hostname or does it end in .local?
	if ( effective_tld_local in c$dns$query ) {
		c$dns$icann_tld = "local";
		c$dns$effective_domain = "local";
		c$dns$effective_subdomain = "";
		break;
	}

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
