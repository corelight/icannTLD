#main1_while_benchmark is the same as main1 except it replaces the tail loop with a while loop .  It uses split_string1 to break the DNS query into two parts 
#seperated by the first match of a period from the left.  It looks from LEFT TO RIGHT to
#find a match in the ICANN TLD list.
#
#Each time it loops through the function, it removes the far left section of the query.


module icannTLD;
#use input framework to add a set with ICANN Domains
type Idx: record {
        tld: string;
};
global icannTLD_set: set[string] = set();
event zeek_init() &priority=10 {
    Input::add_table([$source="public_suffix_list.dat", $name="icannTLD_set",
                      $idx=Idx, $destination=icannTLD_set,
                      $mode=Input::REREAD]);
}

type query_info: record {
    query: string;
    icann_tld: string &optional;
    eff_domain: string &optional;
    eff_subdomain: string &optional;
};
global query: query_info;
global icann_tld: query_info;
global eff_domain: query_info;
global eff_subdomain: query_info;

export {
	global FindTLD: function(query: string): query_info;
}

function step_two(query: string, dns_query: string, offset: count &default = 1): query_info {
	local test_tld = split_string1(query, /(\.)/);
	if (|test_tld| > 1) {
		if (test_tld[1] in icannTLD_set) {
			query_info$icann_tld = test_tld[1];
			if (offset == 1) {
				query_info$eff_domain = query;
			}
			else {
				query_info$eff_subdomain = subst_string(dns_query, "." +query_info$eff_domain, "");
			}
		}
		else {
			query_info$eff_domain = test_tld[1];
			query_info$eff_subdomain = test_tld[0];
			step_two(test_tld[1], dns_query, ++offset);
		}
	}
	return query_info;
}
#renamed from 'event dns_end(c: connection, msg: dns_msg)' for testing
function FindTLD(query: string): query_info {
	local info: query_info;
	info$query = query;
	if ( /.*(\.local)$/ in query ) {
		info$eff_domain = "local";
	}
	else if ( /^[^\.]+$/ in info$query ) {
		info$eff_domain = "local";
	}
	else if ( query in icannTLD_set ) {
		info$icann_tld = query;
		info$eff_domain = query;
	}
	else {
		#info$eff_subdomain = "";
		info = step_two(query, query);
	}
	return info;
}
#added for testing
export {
	option iterations: int = 500000;
	option test_query: string = "google.com";
}
redef exit_only_after_terminate=T;
event Input::end_of_data(name: string, source: string) {
	#for benchmark testing only (to replace pcap)
    local info: query_info;
    local x = 0;
    # while ( ++x < iterations ) {
        info = FindTLD(test_query);
    # }
	print info$query, info$icann_tld, info$eff_domain, info$eff_subdomain;
	terminate();
	exit(0);
}