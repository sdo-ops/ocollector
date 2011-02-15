package Ocollector::Tcpbasic::Windows;

use strict;
use warnings;
use Net::Address::IP::Local;

my @accessors = qw( tag_partial interval errormsg);

use base qw(Class::Accessor Ocollector::Common);
Ocollector::Tcpbasic::Windows->mk_accessors(@accessors);


our $VERSION = '1.0';

sub new {
    my $class = shift;
    my $opts  = ref($_[0]) ? shift : {@_};

    my $self;
    foreach my $opt (keys %{$opts}) {
        $self->{$opt} = $opts->{$opt};
    }

    $self->{errormsg}  = '';

    my @tags;
    push @tags, 'host=' . Net::Address::IP::Local->public_ipv4;

    if (exists $self->{type}) {
        push @tags, 'type=' . $self->{type};
    } else {
        push @tags, 'type=rachel';
    }

    $self->{tag_partial} = join(' ', @tags);


    return bless $self, $class;
}

sub show_results {
    my $self = shift;

    my $output = `netstat -s`;
    my @lines = split /\n/, $output;

    my $results;

    # Active Opens                        = 7268
    # Passive Opens                       = 940
    # Failed Connection Attempts          = 184
    # Reset Connections                   = 470
    # Current Connections                 = 22
    # Segments Received                   = 397427
    # Segments Sent                       = 341375
    # Segments Retransmitted              = 1168

    foreach my $line (@lines) {
        next unless $line =~ /(Active\sOpens|Passive\sOpens|Failed\sConnection\sAttempts|Reset\sConnections|Current\sConnections|Segments\sReceived|Segments\sSent|Segments\sRetransmitted) \s+ = \s+ (\d+)/ixsm;

        my ($counter, $value) = ($1, $2);
        $counter =~ s/\s/_/g;
        $results .= sprintf("put windows.netstat.tcp %d %.0f counter=%s %s\n", time, $value, $counter, $self->tag_partial);
    }

    return $results;
}
