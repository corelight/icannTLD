# @TEST-DOC: Test dns.log enrichment with icannTLD data.
#
# @TEST-EXEC: zeek -Cr $TRACES/tld-examples.pcap $PACKAGE %INPUT
# @TEST-EXEC: btest-diff dns.log

@TEST-START-FILE 1st_level_public_icann.dat
#fields	tld
net
@TEST-END-FILE

@TEST-START-FILE 2nd_level_public_icann.dat
#fields	tld
research.aero
@TEST-END-FILE

@TEST-START-FILE 3rd_level_public_icann.dat
#fields	tld
picard.replit.dev
@TEST-END-FILE

@TEST-START-FILE 4th_level_public_icann.dat
#fields	tld
auth.af-south-1.amazoncognito.com
@TEST-END-FILE

@TEST-START-FILE trusted_domains.dat
#fields	trusted_domain
example.de
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
