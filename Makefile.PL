#!/usr/bin/perl

use strict;
use ExtUtils::MakeMaker;
WriteMakefile(
	'NAME'	    => 'DCE::RPC',
	'VERSION_FROM'  => 'lib/DCE/RPC.pm',
	'PREREQ_PM'	=> {
			Authen::Perl::NTLM => 0.10
			}
	)
;
