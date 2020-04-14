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

function FindTLD(query: string, dns_query: string, offset: count &default = 1) {
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
			FindTLD(test_tld[1], dns_query, ++offset);
		}
	}
}

event dns_end(c: connection, msg: dns_msg) {
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
			eff_subdomain = "";
			FindTLD(c$dns$query, c$dns$query);
   		}
   	}
}
