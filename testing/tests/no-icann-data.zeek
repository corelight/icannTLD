# @TEST-DOC: Test dns.log enrichment without icannTLD data.
#
# @TEST-EXEC: zeek -Cr $TRACES/tld-examples.pcap $PACKAGE %INPUT
# @TEST-EXEC: btest-diff dns.log

@TEST-START-FILE 1st_level_public_icann.dat
#fields	tld
@TEST-END-FILE

@TEST-START-FILE 2nd_level_public_icann.dat
#fields	tld
@TEST-END-FILE

@TEST-START-FILE 3rd_level_public_icann.dat
#fields	tld
@TEST-END-FILE

@TEST-START-FILE 4th_level_public_icann.dat
#fields	tld
@TEST-END-FILE

@TEST-START-FILE trusted_domains.dat
#fields	trusted_domain
@TEST-END-FILE

event zeek_init()
	{
	suspend_processing();
	}

global num_input_files = 5;

event Input::end_of_data(name: string, source: string) {
	if ( name[-4:] == "_set" )
		{
		if ( --num_input_files == 0 )
			continue_processing();
		}
}
