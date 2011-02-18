package Ocollector::CloudStat::Cpu;

use strict;
use warnings;
use Net::Address::IP::Local;
use Sys::Hostname;

my @accessors = qw( tag_partial interval errormsg metric );

use base qw(Class::Accessor Ocollector::Common);
Ocollector::CloudStat::Disk->mk_accessors(@accessors);


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
    if ($self->{prefer} && $self->{prefer} =~ /hostname/ixsm) {
        push @tags, 'host=' . hostname;
    } else {
        push @tags, 'host=' . Net::Address::IP::Local->public_ipv4;
    }

    $self->{tag_partial} = join(' ', @tags);
    $self->{metric} = 'Cloud.HostStat.Dis';

    my $nr_cpus = `/usr/sbin/xm info | grep 'nr_cpus'`;
    ($self->{ncpus}) = ($nr_cpus =~ /(\d+)/);

    return bless $self, $class;
}

sub show_results {
    my $self = shift;

    # except domain 0
    my $xentop = `/usr/sbin/xentop -i 2 -d 1 -b`;
    my ($total, $used, $usage, $free);

    # let's see if we should integrate further

    my $results;
    if (defined $total && defined $free) {
        $used = $total - $free;
        $usage = ($used/$total)*100;

        my $metric = $self->metric;
        my $tag_partial = $self->tag_partial;
    }

    return $results;
}
