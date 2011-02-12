package Ocollector::AccountServer::Cache;

use strict;
use warnings;
use Date::Parse;
use Data::Dumper;
use Net::Address::IP::Local;

my @accessors = qw( metric logdir logname tag_partial interval errormsg);

use base qw(Class::Accessor Ocollector::Common);
Ocollector::AccountServer::Cache->mk_accessors(@accessors);

our $VERSION = '1.0';

sub new {
    my $class = shift;
    my $opts  = ref($_[0]) ? shift : {@_};

    my $self;
    foreach my $opt (keys %{$opts}) {
        $self->{$opt} = $opts->{$opt};
    }

    $self->{metric}    = 'AccsvrStats';
    $self->{errormsg}  = '';

    my @tags;
    push @tags, 'host=' . Net::Address::IP::Local->public_ipv4;

    if (exists $self->{svcgrp}) {
        push @tags, 'svcgrp=' . $self->{svcgrp};
    } else {
        push @tags, 'svcgrp=rachel';
    }

    $self->{tag_partial} = join(' ', @tags);
    

    return bless $self, $class;
}

sub show_results {
    my ($self) = @_;

    my $rc;

    my $logfile = $self->determine_log($self->logdir, $self->logname);
    my $bw = File::ReadBackwards->new($logfile);

    my $results;
    if ($bw) {
        my $stop = time - $self->interval;

        BACKWARD_READ:
        while (defined (my $line = $bw->readline)) {
            chomp $line;

            # 00:23:26.582    [CacheInfo] [TotalCount: 8415] [TrustCache: 7574] [CacheSucc: 5103]

            my ($time) = ($line =~ /^(\d{2}:\d{2}:\d{2})/);
            $time = sprintf("%s %s", Date::Tiny->now->ymd, $time);

            # each line
            my $sec = str2time($time);
            if ($sec >= $stop) {
                # 过滤掉非CacheInfo的
                if ($line =~ /\[TotalCount:\s*(\d+)\] \s* \[TrustCache:\s*(\d+)\] \s* \[CacheSucc:\s*(\d+)\]/ixsm) {
                    my ($totalcount, $trustcache, $cachesucc) = ($1, $2, $3);
                    $results .= sprintf("put AccsvrStats.Cache.TotalCount %d %d %s\n", time, $totalcount, $self->{tag_partial});
                    $results .= sprintf("put AccsvrStats.Cache.TrustCache %d %d %s\n", time, $trustcache, $self->{tag_partial});
                    $results .= sprintf("put AccsvrStats.Cache.CacheSucc %d %d %s\n", time, $cachesucc, $self->{tag_partial});
                }

                next BACKWARD_READ;
            }
            else {
                # 停止parse，时间到
                last BACKWARD_READ;
            }
        }
    } else {
        $self->errormsg("open logfile: $logfile failed");
    }

    return $results;;
}
