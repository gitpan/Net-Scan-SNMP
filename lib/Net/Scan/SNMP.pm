package Net::Scan::SNMP;

use 5.008006;
use strict;
use warnings;
use base qw(Class::Accessor::Fast);
use Carp;
use Net::SNMP;

our $VERSION = '0.01';
$VERSION = eval $VERSION;

__PACKAGE__->mk_accessors( qw(host port protocol snmp_version community timeout retries) );

$| = 1;

sub scan {

	my $self         = shift;
	my $host         = $self->host;
	my $port         = $self->port         || 161;
	my $protocol     = $self->protocol     || 'udp';
	my $snmp_version = $self->snmp_version || 1;
	my $community    = $self->community    || 'public';
	my $timeout      = $self->timeout      || 8;
	my $retries      = $self->retries      || 2;

	my $mibDescr     = '1.3.6.1.2.1.1.1.0';
	
	$|=1;

        if ($timeout > 60){
                die "Error: max timeout value is 60 seconds!";
                return;
        }
	
	$SIG{ALRM}=sub{exit(0);};
	alarm $timeout;

        my ($session, $error) = Net::SNMP->session(
                Hostname  => $host,
                Port      => $port,
                Domain    => $protocol,
                Version   => $snmp_version,
                Community => $community,
                Timeout   => $timeout,
                Retries   => $retries
        );

	my $description = $session->get_request( -varbindlist => [$mibDescr] );

	if ($description){ 
		return $description->{$mibDescr}; 
	}

	return;
	
	$session->close;
}

1;
__END__

=head1 NAME

Net::Scan::SNMP - scan devices to verify SNMP community

=head1 SYNOPSIS

  use Net::Scan::SNMP;

  my $host = $ARGV[0];

  my $scan = Net::Scan::SNMP->new({
    host    => $host,
    timeout => 5
  });

  my $results = $scan->scan;

  print "$host $results\n";

=head1 DESCRIPTION

This module permit to scan devices to verify SNMP community.

=head1 METHODS

=head2 new

The constructor. Given a host returns a L<Net::Scan::SNMP> object:

  my $scan = Net::Scan::SNMP->new({
    host         => '127.0.0.1',
    port         => 80,
    protocol     => udp,
    snmp_version => 1,
    community    => 'public,
    timeout      => 5,
    retries      => 2 
  });

Optionally, you can also specify :

=over 2

=item B<port>

Remote port. Default is 80;

=item B<protocol>

Set the default Transport Domain. Default is 8 seconds;

=item B<snmp_version>

Set the SNMP version. Default is 1.

=item B<community>

Set the SNMP community. Defaults is 'public'.

=item B<timeout>

Default is 8 seconds;

=item B<retries>

Set or get the current retry count for the object. Default is 2.

=back

=head2 scan 

Scan the target.

  $scan->scan;

=head1 SEE ALSO

L<Net::SNMP>

=head1 AUTHOR

Matteo Cantoni, E<lt>mcantoni@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

Copyright (c) 2006, Matteo Cantoni

=cut
