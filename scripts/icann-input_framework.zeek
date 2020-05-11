module icannTLD;

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

########################################################
## begin set_to_regex
# convert ICANN TLD set to regex as it's updated
event Input::end_of_data(name: string, source: string) {
    if (name == "first_icannTLD_set")
		effective_tlds_1st_level = set_to_regex(first_icannTLD_set, "\\.(~~)$");
	if (name == "second_icannTLD_set")
		effective_tlds_2nd_level = set_to_regex(second_icannTLD_set, "\\.(~~)$");
	if (name == "third_icannTLD_set")
		effective_tlds_3rd_level = set_to_regex(third_icannTLD_set, "\\.(~~)$");
	if (name == "fourth_icannTLD_set")
		effective_tlds_4th_level = set_to_regex(fourth_icannTLD_set, "\\.(~~)$");
}
## end set_to_regex
########################################################
