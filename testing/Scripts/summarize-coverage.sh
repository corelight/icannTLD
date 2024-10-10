#! /bin/sh
#
# Helper script that collects individual BTest coverage information and
# summarizes lines that have no coverage.
#
# Needs to be run from the main BTest directory.
#
# Assumes that the scripts directory has been regularized to be "../scripts".

# Look for only this package's scripts, skipping over Zeek's base scripts.
grep -h '\.\./scripts' .tmp/script-coverage/* |

    # Make the names relative to the scripts/ directory.
    sed 's,\t.*/\.\./scripts/,\t,;s,\./,,g' |

    # For each line, sum up its total coverage, outputting those with none.
    awk '
	{
	c = $1	# hold onto the count
	$1 = "#"	# nil out the first argument so $0 no longer includes it
	n[$0] += c	# use the entire script name + line number as key
	}

END	{
	# Look for reports that cover entire function bodies.
	for ( i in n )
		{
		if ( n[i] > 0 )
			# There is coverage for this instance, no need to
			# consider further.
			continue

		nfields = split(i, fields)
		if ( fields[nfields] != "BODY" )
			# This is not a function body.
			continue

		# This is a function body that has no usage count.
		# Extract its location so we can remember to skip any
		# entries that lie within it.
		body_file = fields[2]
		nlines = split(fields[4], lines, /-/)

		if ( nlines == 1 )
			start_line = end_line = lines[0]
		else
			{
			start_line = lines[1]
			end_line = lines[2]
			}

		# Mark every line as one to skip.
		for ( j = start_line; j <= end_line; ++j )
			++skip[body_file, j]
		}

	for ( i in n )
		{
		if ( n[i] > 0 )
			# It has coverage, no need to consider further.
			continue

		nfields = split(i, fields)
		if ( fields[nfields] != "BODY" )
			{
			# Extract location to see whether it has been suppressed.
			body_file = fields[2]
			nlines = split(fields[4], lines, /-/)

			if ( skip[body_file, lines[1]] > 0 )
				continue

			if ( nlines == 2 && skip[body_file, lines[2]] > 0 )
				continue
			}

		print i, n[i]
		}
	}
' |

    # Remove the artificial "# " we added to "nil out" argument counts above.
    sed 's,# ,,' |

    # Sort the output so that all of the uncovered lines in a given script are
    # grouped together.  Within a script, sort based on increasing line number.
    sort -k1,1 -k3,3n
