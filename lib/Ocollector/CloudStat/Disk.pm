package Ocollector::CloudStat::Disk;

use strict;
use warnings;
use Net::Address::IP::Local;
use Sys::Hostname;

my @accessors = qw( tag_partial interval errormsg);

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
    $self->{metric} = 'Cloud.HostStat.Memory';


    return bless $self, $class;
}


# pdis_nod0=(`$VGS_CMD | tr -d 'G' | awk '/xenvg/{print $6,$7}'`)
# pdis_total_nod0=${pdis_nod0[0]}
# pdis_free_nod0=${pdis_nod0[1]}
# pdis_used_nod0=`echo $pdis_total_nod0 $pdis_free_nod0 | awk '{printf "%s",$1-$2}'`
# pdis_usage_nod0=`echo $pdis_used_nod0 $pdis_total_nod0 | awk '{printf "%.2f",$1/$2*100}'`
# echo "$METRICNAME_DIS $ts $pdis_used_nod0 disinfo=used vname=allv v=0"
# echo "$METRICNAME_DIS $ts $pdis_total_nod0 disinfo=total vname=allv v=0"
# echo "$METRICNAME_DIS $ts $pdis_usage_nod0 disinfo=usage vname=allv v=0"


# VG    #PV #LV #SN Attr   VSize   VFree
#   xenvg   1   6   0 wz--n- 689.61G 526.94G
sub show_results {
    my $self = shift;

    # except domain 0
    my $vgs = `/usr/sbin/vgs --units G`;
    my ($total, $used, $usage, $free);

    foreach (split /\n/, $vgs) {
        next unless /\s* xenvg/ixsm;
        ($total, $free) = ($_ =~ /([0-9.]+)G \s ([0-9.]+)G$/ixsm);
    }


    my $results;

    if (defined $total && defined $free) {
        $used = $total - $free;
        $usage = ($used/$total)*100;

        my $metric = $self->metric;
        my $tag_partial = $self->tag_partial;
        $results .= sprintf("put %s %d %d %s disinfo=used vname=allv v=0\n", $metric, time, $used, $tag_partial);
        $results .= sprintf("put %s %d %d %s disinfo=total vname=allv v=0\n", $metric, time, $total, $tag_partial);
        $results .= sprintf("put %s %d %d %s disinfo=usage vname=allv v=0\n", $metric, time, $usage, $tag_partial);
    }

    return $results;
}
