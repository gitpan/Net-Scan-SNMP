use Test::More tests => 1;
BEGIN { use_ok('Net::Scan::SNMP') };

my $host = "127.0.0.1";

my $scan = Net::Scan::SNMP->new({
	host    => $host,
	timeout => 1,
});

my $results = $scan->scan;

print "$host $results\n";

exit(0);
