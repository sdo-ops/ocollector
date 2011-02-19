package Ocollector::Nginx::ErrorLog;

use strict;
use warnings;
use Date::Parse;
use Data::Dumper;
use Sys::Statistics::Linux::DiskUsage;

my @accessors = qw(metric logfile interval errormsg);

use base qw(Class::Accessor Ocollector::Common);
Ocollector::Nginx::ErrorLog->mk_accessors(@accessors);

our $VERSION = '1.0';

my $re_ipv4 = qr/(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))/ixsm;
my $re_static = qr/\.(?:gif|png|jpg|jpeg|js|css|swf)/ixsm;

sub new {
    my $class = shift;
    my $opts  = ref($_[0]) ? shift : {@_};

    # 允许用户指定
    my $self;
    $self->{logfile}    = '/dev/shm/nginx_metrics/errors.log';
    $self->{metric}     = 'nginx.error2';
    $self->{errormsg}   = '';

    foreach my $opt (keys %{$opts}) {
        $self->{$opt} = $opts->{$opt};
    }

    my @tags;
    push @tags, 'host=' . Net::Address::IP::Local->public_ipv4;

    $self->{tag_partial} = join(' ', @tags);

    return bless $self, $class;
}

sub do_parse {
    my $self = shift;

    my $timefrm = $self->interval;
    my $logfile = $self->logfile;

    my $stop = time() - $timefrm;

    my ($rc_dynamic, $rc_static);
    my $bw = File::ReadBackwards->new($logfile);
    if ($bw) {
        BACKWARD_READ:
        while (defined (my $line = $bw->readline)) {
            chomp $line;

            if ($line =~ /(\d{4}\/\d{2}\/\d{2} \s \d{2}:\d{2}:\d{2}) \s \[error\]/ixsm) {
                my $msec = str2time($1);

                if ($msec < $stop) {
                    last BACKWARD_READ;
                } else {
                    # 1. upstream timed out (slow upstream)
                    # 2. connect() failed (upstream went away)
                    # 3. no live upstream (all upstreams failed)
                    if ($line =~ /(upstream \s timed \s out|connect[()]{2} \s failed) .* request: \s+ "(?:GET|POST|PUT) \s ([^ ?]+) .* upstream: \s+ "http:\/\/($re_ipv4):\d+ .* host: \s+ "([\w.]+)"/ixsm) {
                        my ($uri, $upstream, $domain) = ($2, $3, $4);

                        my $reason = '';
                        if ($1 eq 'upstream timed out') {
                            $reason = 'upstream_timed_out';
                        } else {
                            $reason = 'connect_failed';
                        }

                        if ($uri !~ $re_static) {
                            $rc_dynamic->{$domain}->{$upstream}->{$reason}++;
                        } else {
                            $rc_static->{$domain}->{$upstream}->{$reason}++;
                        }
                    } elsif ($line =~ /no \s live \s upstream .* request: \s+ "(?:GET|POST|PUT) \s ([^ ?]+) .*  host: \s+ "([\w.]+)"/ixsm) {
                        my ($uri, $domain) = ($1, $2);

                        my $upstream = '25.255.255.255';
                        my $reason = 'no_live_upstreams';
                        if ($uri !~ $re_static) {
                            $rc_dynamic->{$domain}->{$upstream}->{$reason}++;
                        } else {
                            $rc_static->{$domain}->{$upstream}->{$reason}++;
                        }
                    } else {
                        1;
                    }

                }
            }
        }
    } else {
        $self->errormsg("failed to open $logfile");
        return undef;
    }

    unless (defined $rc_dynamic && defined $rc_static) {
        $self->errormsg('no error produced, great');
    }

    return ($rc_dynamic, $rc_static);
}


sub show_results {
    my $self = shift;
    
    # 如果不知道是不是在tmpfs上，我们也可以flush一下。
    # tmpfs少了，说不定就是我们引起的。
    if (flush_tmpfs()) {
        system '>' . $self->logfile;

        # flush后日志为空，本次prepare_metrics失败。 
        $self->errormsg('tmpfs flushed.');
        return 0;
    }

    my ($rc_dynamic, $rc_static) = $self->do_parse;

    my $results;
    if (defined $rc_dynamic) {
        # 开始计算动态
        foreach my $domain (keys %{$rc_dynamic}) {
            foreach my $upstream (keys %{$rc_dynamic->{$domain}}) {
                # 如果某种类型的error没有，我们这里补个0上去
                unless (exists $rc_dynamic->{$domain}->{$upstream}->{no_live_upstreams}) {
                    $rc_dynamic->{$domain}->{$upstream}->{no_live_upstreams} = 0;
                }

                unless (exists $rc_dynamic->{$domain}->{$upstream}->{connect_failed}) {
                    $rc_dynamic->{$domain}->{$upstream}->{connect_failed} = 0;
                }

                unless (exists $rc_dynamic->{$domain}->{$upstream}->{upstream_timed_out}) {
                    $rc_dynamic->{$domain}->{$upstream}->{upstream_timed_out} = 0;
                }

                foreach my $reason (keys %{$rc_dynamic->{$domain}->{$upstream}}) {
                    $results .= sprintf("put %s %d %d domain=%s upstream=%s reason=%s %s type=dynamic\n",
                        $self->metric, time(), $rc_dynamic->{$domain}->{$upstream}->{$reason},
                        $domain, $upstream, $reason, $self->{tag_partial});
                }
            }
        }
        
    }

    if (defined $rc_static) {
        foreach my $domain (keys %{$rc_static}) {
            foreach my $upstream (keys %{$rc_static->{$domain}}) {
                # 如果某种类型的error没有，我们这里补个0上去
                unless (exists $rc_static->{$domain}->{$upstream}->{no_live_upstreams}) {
                    $rc_static->{$domain}->{$upstream}->{no_live_upstreams} = 0;
                }

                unless (exists $rc_static->{$domain}->{$upstream}->{connect_failed}) {
                    $rc_static->{$domain}->{$upstream}->{connect_failed} = 0;
                }

                unless (exists $rc_static->{$domain}->{$upstream}->{upstream_timed_out}) {
                    $rc_static->{$domain}->{$upstream}->{upstream_timed_out} = 0;
                }

                foreach my $reason (keys %{$rc_static->{$domain}->{$upstream}}) {
                    $results .= sprintf("put %s %d %d domain=%s upstream=%s reason=%s %s type=static\n",
                        $self->metric, time(), $rc_static->{$domain}->{$upstream}->{$reason},
                        $domain, $upstream, $reason, $self->{tag_partial});
                }
            }
        }
    }

    return $results;
}

sub flush_tmpfs {
    my $lxs = Sys::Statistics::Linux::DiskUsage->new;
    my $stat = $lxs->get;
    my $threshold = 90;

    if (exists $stat->{tmpfs}) {
        my ($free, $total) = ($stat->{tmpfs}->{free}, $stat->{tmpfs}->{total});

        # 大小为0的tmpfs可能存在么？
        if ($total >= 0) {
            my $used = sprintf("%.2f", ($total - $free)/$total*100);
            # 低于这点时开始flush 
            if ($used >= $threshold) {
                return 1;
            }
        }
    }

    return 0;
}

1;
