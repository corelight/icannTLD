#main1_benchmark uses split_string1 to break the DNS query into two parts 
#seperated by the first match of a period from the left.  It looks from LEFT TO RIGHT to
#find a match in the ICANN TLD list.
#
#It also uses a tail loop within the FindTLD function to call itself.  Each time
#it loops through the function, it removes the far left section of the query.


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
function FindTLD(c: connection, query: string, idx: count &default = 2) {
	local dns_query = query;
	local pass: int = 1;
	# print "FindTLD query: " +query;
	# print "FindTLD idx:", idx;
	# print "FindTLD pass:", pass;
	while (idx > 1 ) {
		local test_tld = split_string1(query, /(\.)/);
		# print "while test_tld", test_tld;
		# print "while test_tld size", |test_tld|;
		idx = |test_tld|;
		# print "while idx", idx;
		if (|test_tld| > 1) {
			# print "if test_tld size", |test_tld|;
			if (test_tld[1] in icannTLD_set) {
				# print "if if test_tld[1]: " +test_tld[1];
				c$dns$icann_tld = test_tld[1];
				# print "if if c$dns$icann_tld: " +c$dns$icann_tld;
				if (pass == 1) {
					# print "if if if pass", pass;
					c$dns$eff_domain = query;
					# print "if if if c$dns$eff_domain: " +c$dns$eff_domain;
					return;
				}
				else {
					c$dns$eff_subdomain = subst_string(dns_query, "." +c$dns$eff_domain, "");
					# print "if if else c$dns$eff_subdomain: " +c$dns$eff_subdomain;
					return;
				}
			}
			else {
				c$dns$eff_domain = test_tld[1];
				# print "if else c$dns$eff_domain: " +c$dns$eff_domain;
				c$dns$eff_subdomain = test_tld[0];
				# print "if else c$dns$eff_subdomain: " +c$dns$eff_subdomain;
				query = test_tld[1];
				# print "if else query: " +query;
				++pass;
			}
		}
	}
	return;
}
#renamed from 'event dns_end(c: connection, msg: dns_msg)' for testing
function test_one(c: connection) {
    if ( c?$dns && c$dns?$query ) {
		# print "function c$dns$query: " +c$dns$query;
        if ( /.*(\.local)$/ in c$dns$query ) {
            c$dns$eff_domain = "local";
        }
        else if ( /^[^\.]+$/ in c$dns$query ) {
            c$dns$eff_domain = "local";
        }
        else if ( c$dns$query in icannTLD_set ) {
            c$dns$icann_tld = c$dns$query;
            c$dns$eff_domain = c$dns$query;
        }
        else {
            c$dns$eff_subdomain = "";
            FindTLD(c, c$dns$query);
        }
    }
}
#added for testing
export {
	option iterations: int = 500000;
	option test_query: string = "www.google.com";
}
redef exit_only_after_terminate=T;
event Input::end_of_data(name: string, source: string) {
	#for benchmark testing only (to replace pcap)
	local c: connection;
	local dns_info: DNS::Info;
	c$dns = dns_info;
	c$dns$query=test_query;
	# print "even test_query: " +test_query;
    local x = 0;
    while ( ++x < iterations ) {
        test_one(c);
    }
	print c$dns$query, c$dns$icann_tld, c$dns$eff_domain, c$dns$eff_subdomain;
	terminate();
	exit(0);
}