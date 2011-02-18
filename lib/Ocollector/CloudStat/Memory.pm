package Ocollector::CloudStat::Memory;

use strict;
use warnings;
use Net::Address::IP::Local;

my @accessors = qw( tag_partial interval errormsg);

use base qw(Class::Accessor Ocollector::Common);
Ocollector::CloudStat::Memory->mk_accessors(@accessors);


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
    $self->{metric} = 'Cloud.HostStat.Memory';


    return bless $self, $class;
}

sub get_xminfo {
    my $rc;
    my $pmem = `xm info`;

    foreach (split /\n/, $pmem) {
        next unless /(total|free)_memory/ixsm;
        my $k = $1;
        my ($v) = ($_ =~ /\w+ .* (\d+)/);
        $rc->{$k} = $v;
    }

    my $used_percent = (1 - ($rc->{free} / $rc->{total}))*100;
    $rc->{used} = $rc->{total} - $rc->{free};
    $rc->{usage} = $rc->{used}/$rc->{total}*100;
    delete $rc->{free};

    return $rc;
}

sub get_free {
    my $rc;
    my $d0mem = `free -m`;

    foreach (split /\n/, $d0mem) {
        next unless /^Mem/ixsm;
        my ($total, $used) = ($_ =~ /(\d+) .*? (\d+)/);
        $rc->{total} = $total;
        $rc->{used} = $used;
    }

    my $used_percent = ($rc->{used} / $rc->{total})*100;
    $rc->{usage} = $used_percent;

    return $rc;
}

sub show_results {
    my $self = shift;

    my $pmem = get_xminfo();
    my $dom0 = get_free();

    my $pmem_total_nod0 = $pmem->{total} - $dom0->{total};
    my $pmem_used_nod0  = $pmem->{used}  - $dom0->{used};
    my $pmem_usage_nod0 = ($pmem_used_nod0/$pmem_total_nod0)*100;

    my $results;
    my $metric = $self->metric;
    my $tag_partial = $self->tag_partial;

    $results .= sprintf("put %s %d %d %s meminfo=used vname=all v=0\n", $metric, time, $pmem->{used}, $tag_partial);
    $results .= sprintf("put %s %d %d %s meminfo=total vname=all v=0\n", $metric, time, $pmem->{total}, $tag_partial);
    $results .= sprintf("put %s %d %d %s meminfo=usage vname=all v=0\n", $metric, time, $pmem->{usage}, $tag_partial);

    $results .= sprintf("put %s %d %d %s meminfo=used vname=allv v=0\n", $metric, time, $pmem_used_nod0, $tag_partial);
    $results .= sprintf("put %s %d %d %s meminfo=total vname=allv v=0\n", $metric, time, $pmem_total_nod0, $tag_partial);
    $results .= sprintf("put %s %d %d %s meminfo=usage vname=allv v=0\n", $metric, time, $pmem_usage_nod0, $tag_partial);

    return $results;
}
