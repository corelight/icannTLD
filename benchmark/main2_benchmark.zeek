#main2_benchmark uses split_string to break the DNS query into all of the parts 
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
redef record DNS::Info += {
	eff_subdomain: string &log &optional;
	eff_domain: string &log &optional;
	icann_tld: string &log &optional;
};

function FindTLD(c: connection, query: string, dns_query: string, offset: count &default = 1) {
	local query_parts = split_string(query, /\./);
	local query_size = |query_parts|;
	local idx: int = query_size-1;
	local test_tld = query_parts[idx];
	while (idx > 0  ) {;
		if (test_tld !in icannTLD_set)
			break;
		c$dns$icann_tld = test_tld;
		c$dns$eff_domain = fmt("%s.%s", query_parts[idx-1], test_tld);
		test_tld = fmt("%s.%s", query_parts[idx-1], test_tld);
		--idx;
	}
	if(idx >= 0) {
		 c$dns$eff_subdomain = join_string_vec(query_parts[0:idx],".");
	}
}

function test_one(c: connection) {
    if ( c?$dns && c$dns?$query ) {
        if ( /.*(\.local)$/ in c$dns$query ) {
            info$eff_domain = "local";
        }
        else if ( /^[^\.]+$/ in c$dns$query ) {
            info$eff_domain = "local";
        }
        else if ( c$dns$query in icannTLD_set ) {
            c$dns$icann_tld = c$dns$query;
            c$dns$eff_domain = c$dns$query;
        }
        else {
            FindTLD(c, c$dns$query, c$dns$query);
        }
    }
}
#added for testing
export {
	option iterations: int = 500000;
	option test_query: string = "google.com";
}
redef exit_only_after_terminate=T;
event Input::end_of_data(name: string, source: string) {
	#for benchmark testing only (to replace pcap)
	local c: connection;
	local dns_info: DNS::Info;
	c$dns = dns_info;
	c$dns$query=test_query;
    local x = 0;
    while ( ++x < iterations ) {
        test_one(c);
    }
	print c$dns$query, c$dns$icann_tld, c$dns$eff_domain, c$dns$eff_subdomain;
	terminate();
	exit(0);
}