#!/usr/bin/env perl
# author:        yanglei@snda.com
# last modified: 2011-02-05
# description:   this script collects interesting data then send to some place for scrunity.

use strict;
use warnings;
use File::Path;
use POSIX qw( strftime );
use Getopt::Long;
use IO::Socket;
use File::ReadBackwards;
#use Data::Dumper;

# Hacked oneline to remove dependency on version module, which requires a XS file that we can't pack.
use Net::Address::IP::Local;

# GLOBALS
my $O_ERROR = '';

# Those regular expressions are stoled from Regex::Common
# but zero-dependency is more important for us.
my $re_ipv4 = qr/(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))/ixsm;
my $re_domain = qr/(?:[0-9A-Za-z](?:(?:[-A-Za-z0-9]){0,61}[A-Za-z0-9])?(?:\.[A-Za-z](?:(?:[-A-Za-z0-9]){0,61}[A-Za-z0-9])?)*)/ixsm;
my $re_uri = qr/[^ ]+/ixsm;
my $re_msec = qr/\d{10}\.\d{3}/ixsm;
my $re_status = qr/\d{3}|-/ixsm;
my $re_cost = qr/(?:\d+\.\d+|-)/ixsm;
my $re_error = qr/(?:5\d{2})/ixsm; # 目前仅认为5xx是错误，400不算
my $re_static = qr/\.(?:gif|png|jpg|jpeg|js|css|swf)/ixsm;

sub parse_http_nginx_v2 {
    my ($timefrm, $logfile) = @_;

    my $stop = time - $timefrm;

    my ($rc_dynamic, $rc_total);

    my $bw = File::ReadBackwards->new($logfile);
    if ($bw) {
        BACKWARD_READ:
        while (defined (my $line = $bw->readline)) {
            chomp $line;

            if ($line =~ /^($re_msec) \s+ ($re_domain|$re_ipv4) \s+ ($re_uri) \s+ ($re_status) \s+ ($re_ipv4:\d+|-) \s+ ($re_cost|-)/ixsm) {
                my ($msec, $domain, $uri, $status, $upstream, $cost) = ($1, $2, $3, $4, $5, $6);

                if ($msec < $stop) {
                    last BACKWARD_READ;
                } else {
                    $upstream =~ s/:\d+//g; # remove port
                    if ($domain =~ $re_ipv4) {
                        next BACKWARD_READ; # 当Host头为IP时，认为是无效的请求。
                    } else {
                        if ($upstream eq '-') {
                            next BACKWARD_READ; # 如果upstream为空，表示已经被nginx缓存，相信nginx不会有错，所以不再计算。
                        } else {
                            # 如果是动态，先填充动态的结构。将动态与总计分开方便一点
                            if ($uri !~ $re_static) {
                                if ($status =~ /$re_error/) {
                                    $rc_dynamic->{$domain}->{$upstream}->{error}++ ;
                                } else {
                                    unless (exists $rc_dynamic->{$domain}->{$upstream}->{error}) {
                                        $rc_dynamic->{$domain}->{$upstream}->{error} = 0;
                                    }
                                }
                                $rc_dynamic->{$domain}->{$upstream}->{latency} += $cost if $cost ne '-';
                                $rc_dynamic->{$domain}->{$upstream}->{throughput}++;
                            }

                            if ($status =~ /$re_error/) {
                                $rc_dynamic->{$domain}->{$upstream}->{error}++ ;
                            } else {
                                unless (exists $rc_dynamic->{$domain}->{$upstream}->{error}) {
                                    $rc_dynamic->{$domain}->{$upstream}->{error} = 0;
                                }
                            }
                            $rc_total->{$domain}->{$upstream}->{throughput} += $cost if $cost ne '-';
                            $rc_total->{$domain}->{$upstream}->{total}++;
                        }
                    }
                }
            }
        }
    } else {
        return undef;
    }

    return ($rc_dynamic, $rc_total);
}

# 读取Nginx最后N行的日志，根据5xx的返回码，建立每个URL的情况，以及处理耗时。
sub parse_http_nginx_v1 {
    my ($last_n, $logfile) = @_;

    # my $output = `tail -$last_n $logfile`;
    my $output = `wc -l $logfile`;

    chomp $output;

    my ($count) = ($output =~ /^(\d+)\s/);

    if ($count && $count>0) {
        return $count;
    } else {
        return undef;
    }
}

sub get_tcpbasic {
    my $output = `netstat -st`;
    my $want_re = qr/((?:active\sconnections\sopenings)|(?:passive\sconnection\sopenings)|(?:failed\sconnection\sattempts)|(?:connection\sresets\sreceived))/ixsm;

    #  Tcp:
    #      759262422 active connections openings
    #      118115924 passive connection openings
    #      2406493 failed connection attempts
    #      2227918 connection resets received
    my $rc;
    foreach (split /\n/, $output) {
        next unless $_ =~ $want_re;
        chomp;

        my $line = $_;

        my @metric_segment = split/\s/, $1;
        my ($count) = ($line =~ /\s+(\d+)\s+/ixsm);
        my $metric = join(q{_}, map { lc($_) } @metric_segment);

        $rc->{$metric} = $count;

        # early break
        if ($line =~ /connection\sresets\sreceived/ixsm) {
            last;
        }
    }

    return $rc;
}

sub get_diskstats {
    my $output = `cat /proc/diskstats | grep -P '(?:sd[a-z]\\d*|dm-(?:\\d+))'`;

    # explanation of /proc/diskstats
    # Field 1 -- # of reads issued
    # Field 2 -- # of reads merged, field 6 -- # of writes merged
    # Field 3 -- # of sectors read
    # Field 4 -- # of milliseconds spent reading
    # Field 5 -- # of writes completed
    # Field 7 -- # of sectors written
    # Field 8 -- # of milliseconds spent writing
    # Field 9 -- # of I/Os currently in progress
    # Field 10 -- # of milliseconds spent doing I/Os
    # Field 11 -- weighted # of milliseconds spent doing I/Os

    my $rc;
    foreach (split /\n/, $output) {
        chomp;

        my @results = split /\s+/;

        next if @results != 15;
        my $disk = $results[3];

        $rc->{$disk}->{reads_issued}        = $results[4];
        $rc->{$disk}->{reads_merged}        = $results[5];
        $rc->{$disk}->{sectors_read}        = $results[6];
        $rc->{$disk}->{spent_reading}       = $results[7];
        $rc->{$disk}->{writes_completed}    = $results[8];
        $rc->{$disk}->{writes_merged}       = $results[9];
        $rc->{$disk}->{sectors_write}       = $results[10];
        $rc->{$disk}->{spent_writing}       = $results[11];
        $rc->{$disk}->{io_currently}        = $results[12];
        $rc->{$disk}->{spent_io}            = $results[13];
        $rc->{$disk}->{spent_io_weighted}   = $results[14];
    }

    return $rc;
}

sub prepare_metrics {
    my ($target, $type, $params) = @_;

    my $results = q{};
    if ($type eq 'diskstats') {
        my $rc= get_diskstats();

        foreach my $d (sort keys %{$rc}) {
            foreach my $item (sort keys %{$rc->{$d}}) {
                $results .= sprintf("put diskstats.%s %d %d host=%s disk=%s\n",
                    $item, time(), $rc->{$d}->{$item}, $target, $d);
            }
        }
    }
    elsif ($type eq 'tcpbasics') {
        my $rc= get_tcpbasic();

        foreach my $item (sort keys %{$rc}) {
            $results .= sprintf("put tcpbasic.%s %d %d host=%s\n", $item, time(), $rc->{$item}, $target);
        }
    }
    elsif ($type eq 'log-nginx-v1') {
        my $rc = parse_http_nginx_v1($params->{last_n}, $params->{nginx_log});

        if (defined $rc) {
            $results .= sprintf("put http.nginx.v1.error.%d %d %d host=%s\n",
                504, time(), $rc, $target);
        } else {
            return 0;
        }
    }
    elsif ($type eq 'log-nginx-v2') {
        my ($rc_dynamic, $rc_total)  = parse_http_nginx_v2($params->{last_n}, $params->{nginx_log});

        my $interval = $params->{last_n};
        my $metric_name;
        if ($interval == 60) {
            $metric_name = '1min';
        } elsif ($interval == 300) {
            $metric_name = '5min';
        } else {
            $metric_name = "${interval}sec";
        }

        my $virtualized = 'no';
        $virtualized = 'yes' if $params->{virtual};

        if (defined $rc_dynamic && defined $rc_total) {
            # 开始计算动态
            foreach my $domain (keys %{$rc_dynamic}) {
                foreach my $upstream (keys %{$rc_dynamic->{$domain}}) {
                    foreach my $item (keys %{$rc_dynamic->{$domain}->{$upstream}}) {
                        if ($item ne 'latency') { # 耗时的算法和其他不同
                            $results .= sprintf("put nginx.%s.dynamic.%s %d %d host=%s domain=%s upstream=%s virtualized=%s\n",
                                $item, $metric_name, time(), $rc_dynamic->{$domain}->{$upstream}->{$item},
                                $target, $domain, $upstream, $virtualized); # 这是开始是tag
                        } else {
                            # latency返回毫秒数
                            # 总耗时除以总请求数
                            $results .= sprintf("put nginx.%s.dynamic.%s %d %d host=%s domain=%s upstream=%s virtualized=%s\n",
                                $item, $metric_name, time(),
                                ($rc_dynamic->{$domain}->{$upstream}->{$item}/$rc_dynamic->{$domain}->{$upstream}->{throughput})*1000,
                                $target, $domain, $upstream, $virtualized); # 这是开始是tag
                        }
                    }
                }
            }
        } else {
            return 0;
        }
    }
    else {
        return 0;
    }

    return $results;
}

sub usage {
    print "At minmum, you must provide the collector type, ";
    print "e.,g ./ocollector --type=diskstats\n";

    print "example1: ./ocollector --target=192.168.2.1 --type=diskstats\n";
    print "example2: ./ocollector --interval=5 --type=tcpbasics\n";
    print "example3: ./ocollector --type=log-nginx-v1 --nginx-log=access.log --log-lines=300\n";
}

sub send_metrics {
    my ($results, $ocollector_daemon, $ocollector_port, $ocollector_proto) = @_;

    my $rc = 0;

    # send directly through IO::Socket
    my $sock = IO::Socket::INET->new(
        PeerAddr => $ocollector_daemon,
        PeerPort => $ocollector_port,
        Proto    => $ocollector_proto,
    );

    unless ($sock) {
        $O_ERROR = "create ${ocollector_daemon}:$ocollector_port failed";
        return 0;
    }

    print {$sock} $results;
    close $sock;

    return 1;
}

sub log_succeed {
    my $msg = shift;
    printf("%s\t%s\n", strftime("%Y-%m-%d %H:%M:%S", localtime), "$msg");
}

sub log_exception {
    my $function = shift;
    printf("%s\t%s\n", strftime("%Y-%m-%d %H:%M:%S", localtime), "$function() failed: $O_ERROR\n");
}

sub main {
    my $ocollector_daemon       = 'op.sdo.com';
    my $ocollector_port         = 4242;
    my $ocollector_proto        = 'tcp';
    my $ocollector_interval     = 15;
    my $ocollector_target       = q{};
    my $ocollector_type         = q{};
    my $ocollector_nginx_log    = q{};
    my $ocollector_log_lines    = 500;
    my $ocollector_verbose      = 0;
    my $ocollector_virtual      = 0;
    my $help;

    GetOptions("to=s" => \$ocollector_daemon,
               "interval=i" => \$ocollector_interval,
               "port=i" => \$ocollector_port,
               "target=s" => \$ocollector_target,
               "type=s" => \$ocollector_type,
               "nginx-log=s" => \$ocollector_nginx_log,
               "log-lines=s" => \$ocollector_log_lines,
               "virtual" => \$ocollector_virtual,
               "verbose" => \$ocollector_verbose,
               "help" => \$help
               );

    if ($help) {
        usage;
        exit 0;
    }
    my $supported = 'diskstats|tcpbasics|log-nginx-v1|log-nginx-v2';

    if (!$ocollector_type) {
        usage();
        exit 1;
    } elsif ($ocollector_type !~ /^(?:$supported)/ixsm) {
        print "[$ocollector_type] is not a supported collecting type, the following type is $supported supported.\n";
        exit 1;
    } else {
        1;
    }

    # 如果不给出host，则自动获取IP
    if (!$ocollector_target) {
        $ocollector_target = Net::Address::IP::Local->public_ipv4();
    }

    # 如果某种类型的collector需要参数，通过统一的params扔进去。
    my $params;
    $params->{last_n}    = $ocollector_log_lines;
    $params->{nginx_log} = $ocollector_nginx_log;
    $params->{virtual}   = $ocollector_virtual;

    for (;;) {
        # 只有metrics生成成功才发送，保证tsd那端不会受到乱七八糟的东西。
        if (my $results = prepare_metrics($ocollector_target, $ocollector_type, $params)) {
            #print $results; exit;
            if (send_metrics($results, $ocollector_daemon, $ocollector_port)) {
                if ($ocollector_verbose) {
                    log_succeed("send_metrics() succeed:\n$results");
                } else {
                    log_succeed("send_metrics() succeed.") ;
                }
            } else {
                log_exception('send_metrics');
            }
        }
        else {
            log_exception('prepare_metrics');
        }

        # 取前N秒的时候，多sleep一会。
        # 处理500多请求/秒 1min的数据需要5秒，也就是1/12。
        # 因此sleep时间为 间隔 + 间隔*1/24 + 随机值
        if ($ocollector_type eq 'log-nginx-v2') {
            sleep($ocollector_log_lines + $ocollector_log_lines/12 + 5);
        } else {
            sleep($ocollector_interval);
        }
    }
}

main();
