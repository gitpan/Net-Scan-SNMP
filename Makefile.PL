use 5.008006;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Net::Scan::SNMP',
    VERSION_FROM      => 'lib/Net/Scan/SNMP.pm',
    PREREQ_PM         => {
				Net::SNMP => 5.2.0,
				Class::Accessor::Fast => 0.22,
			},

    ($] >= 5.005 ?
      (ABSTRACT       => 'A simple way to scan devices to verify SNMP community.',
       AUTHOR         => 'Matteo Cantoni <mcantoni@cpan.org>') : ()),
);
