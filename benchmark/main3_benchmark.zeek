#main3_benchmark is a library that returns icann_tld, eff_domain and eff_subdomain.
#It uses split_string to break the DNS query into all of the parts 
#seperated by a period.  Then it looks from RIGHT TO LEFT to find a match in the 
#ICANN TLD list.
#
#It also uses a while loop within the FindTLD function.

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

export {
	global FindTLD: function(query: string): query_info;
}

function step_two(query: string): query_info {
    local info: query_info;
    info$query = query;
	local query_parts = split_string(query, /\./);
	local query_size = |query_parts|;
	local idx: int = query_size-1;
	local test_tld = query_parts[idx];
	while (idx > 0  ) {;
		if (test_tld !in icannTLD_set)
			break;
		info$icann_tld = test_tld;
		info$eff_domain = fmt("%s.%s", query_parts[idx-1], test_tld);
		test_tld = fmt("%s.%s", query_parts[idx-1], test_tld);
		--idx;
	}
	if(idx > 0) {
		 info$eff_subdomain = join_string_vec(query_parts[0:idx],".");
	}
    return info;
}

function FindTLD(query: string): query_info {
    local info: query_info;
    info$query = query;
    if ( /.*(\.local)$/ in query ) {
        info$eff_domain = "local";
    }
    else if ( /^[^\.]+$/ in query ) {
        info$eff_domain = "local";
    }
    else if ( query in icannTLD_set ) {
        info$icann_tld = query;
        info$eff_domain = query;
    }
    else {
        info = step_two(query);
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
    while ( ++x < iterations ) {
        info = FindTLD(test_query);
    }
    print info;
	terminate();
	exit(0);
}