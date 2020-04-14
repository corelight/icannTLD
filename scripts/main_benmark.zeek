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
	local test_tld = split_string1(query, /(\.)/);
	if (|test_tld| > 1) {
		if (test_tld[1] in icannTLD_set) {
			c$dns$icann_tld = test_tld[1];
			if (offset == 1) {
				c$dns$eff_domain = query;
			}
			else {
				c$dns$eff_subdomain = subst_string(dns_query, "." +c$dns$eff_domain, "");
			}
		}
		else {
			c$dns$eff_domain = test_tld[1];
			c$dns$eff_subdomain = test_tld[0];
			FindTLD(c, test_tld[1], dns_query, ++offset);
		}
	}
}
#renamed from 'event dns_end(c: connection, msg: dns_msg)' for testing
function test_one(c: connection) {
    if ( c?$dns && c$dns?$query ) {
        if ( /.*(\.local)$/ in c$dns$query ) {
            ;
        }
        else if ( /^[^\.]+$/ in c$dns$query ) {
            ;
        }
        else if ( c$dns$query in icannTLD_set ) {
            c$dns$icann_tld = c$dns$query;
            c$dns$eff_domain = c$dns$query;
        }
        else {
            c$dns$eff_subdomain = "";
            FindTLD(c, c$dns$query, c$dns$query);
        }
    }
}
#added for testing
redef exit_only_after_terminate=T;
event Input::end_of_data(name: string, source: string) {
	#for benchmark testing only (to replace pcap)
	local c: connection;
	local dns_info: DNS::Info;
	c$dns = dns_info;
	c$dns$query="7.6.5.4.3.2.1.google.com";
    local x = 0;
    while ( ++x < {{ N }} ) {
        test_one(c);
    }
	terminate();
}