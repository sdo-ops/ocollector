package Ocollector::ServiceMonitor::Memcached;

use strict;
use warnings;
use Date::Parse;
use Data::Dumper;

my @accessors = qw( metric logdir logfile interval pattern lastpos errormsg);

use base qw(Class::Accessor Ocollector::Common);
Ocollector::ServiceMonitor::Memcached->mk_accessors(@accessors);

our $VERSION = '1.0';

sub new {
    my $class = shift;
    my $opts  = ref($_[0]) ? shift : {@_};

    my $self;
    foreach my $opt (keys %{$opts}) {
        $self->{$opt} = $opts->{$opt};
    }

    $self->{metric}    = 'servicemonitor.memcached';
    $self->{lastpos}   = '';
    $self->{logfile}   = '';
    $self->{errormsg}  = '';

    return bless $self, $class;
}

sub do_parse {
    my ($self) = @_;

    $self->logfile($self->determine_latest($self->logdir, $self->pattern));

    my $rc;

    my $logfile = $self->logfile;
    my $bw = File::ReadBackwards->new($logfile);

    if ($bw) {
        my $re_ipv4 = $Ocollector::Common::re_ipv4;
        my $stop = time - $self->interval;

        BACKWARD_READ:
        while (defined (my $line = $bw->readline)) {
            chomp $line;

            # 如果和最近一次读取的md5一样，说明根本没变过。  
            # 那就没必要做任何事情。
            last BACKWARD_READ if $self->give_md5($line) eq $self->lastpos;

            # 1. 防止异常日志
            # 2. 保证时间能被正常parse
            next BACKWARD_READ unless $line =~ /^time:(\d{4}-\d{2}-\d{2} \s+ \d{2}:\d{2}:\d{2}) \s+/ixsm;

            my $sec = str2time($1);

            if ($sec >= $stop) {
                if ($line !~ /($re_ipv4) : (\d+) .*? cost_time:(\d+) .*? [:=]+(\w+)/ixsm) {
                    next BACKWARD_READ;
                } else {
                    my ($ip, $port, $cost, $result) = ($1, $2, $3, $4);

                    if ($result eq 'SUCCESS') {
                        $rc->{$ip}->{$port}->{succeed_cost} += $cost;
                        $rc->{$ip}->{$port}->{succeed}++;
                    } else {
                        $rc->{$ip}->{$port}->{failed_cost} += $cost;
                        $rc->{$ip}->{$port}->{failed}++;
                    }

                    $rc->{$ip}->{$port}->{total}++;


                    # 记录最近一次的数据
                    $self->lastpos($self->give_md5($line));
                }
            }
            else {
                # 停止parse，时间到
                last BACKWARD_READ;
            }
        }
    } else {
        $self->errormsg("open logfile: $logfile failed");
    }

    return $rc;
}

sub format_result {
    my ($self, $rc) = @_;

    my $results;
    if ($rc) {
        foreach my $ip (keys %{$rc}) {
            foreach my $port (keys %{$rc->{$ip}}) {
                foreach my $item (keys %{$rc->{$ip}->{$port}}) {
                    # 因为succeed和failed都可能不存在，所以用total
                    next unless $item eq 'total';

                    # 保证succeed和failed有值
                    unless (exists $rc->{$ip}->{$port}->{succeed}) {
                        $rc->{$ip}->{$port}->{succeed} = 0;
                        $rc->{$ip}->{$port}->{succeed_cost} = 1;
                    }

                    unless (exists $rc->{$ip}->{$port}->{failed}) {
                        $rc->{$ip}->{$port}->{failed} = 0;
                        $rc->{$ip}->{$port}->{failed_cost} = 1;
                    }

                    my $total = $rc->{$ip}->{$port}->{$item};

                    # 计算: error rate
                    $results .= sprintf("put %s.error %d %.2f host=%s port=%s\n",
                            $self->metric, time, $rc->{$ip}->{$port}->{failed}/$total*100, $ip, $port);

                    # 计算: throughput and latency
                    for (qw/succeed failed/) {
                        $results .= sprintf("put %s.throughput %d %d host=%s port=%s type=%s\n",
                                $self->metric, time, $rc->{$ip}->{$port}->{$_}, $ip, $port, $_);

                        if ($rc->{$ip}->{$port}->{$_} == 0) {
                            $results .= sprintf("put %s.latency %d 0 host=%s port=%s type=%s\n",
                                    $self->metric, time, $ip, $port, $_);
                        } else {
                            $results .= sprintf("put %s.latency %d %d host=%s port=%s type=%s\n",
                                    $self->metric, time, $rc->{$ip}->{$port}->{$_ . '_cost'}/$rc->{$ip}->{$port}->{$_}, $ip, $port, $_);
                        }
                    }
                }
            }
        }
    } else {
        $self->errormsg($self->metric . " empty parse");
    }

    return $results;
}

sub show_results {
    my $self = shift;
    
    my $rc = $self->do_parse;

    if ($rc) {
        return $self->format_result($rc);
    }

    return;
}

1;
