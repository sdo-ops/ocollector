#!/usr/bin/env perl
# author:        yanglei@snda.com
# last modified: 2011-02-10
# description:   this script collects interesting data then send to some place for scrunity.

use strict;
use warnings;
use File::Path;
use POSIX qw( strftime );
use Getopt::Long;
use IO::Socket;
use File::ReadBackwards;
use Sys::Statistics::Linux::DiskUsage;
use Date::Parse;
use File::Spec;
use Data::Dumper;
use Try::Tiny;
use Ocollector::ServiceMonitor::Memcached;
use Ocollector::AccountServer::StatisticDetails;
use Ocollector::AccountServer::Cache;

# Hacked oneline to remove dependency on version module, which requires a XS file that we can't pack.
use Net::Address::IP::Local;

use constant WIN32 => $^O eq 'MSWin32';
use constant SUNOS => $^O eq 'solaris';

our $VERSION = "1.06";
$VERSION = eval $VERSION;


# GLOBALS
my $O_ERROR     = '';

# Those regular expressions are stoled from Regex::Common
# but zero-dependency is more important for us.
my $re_ipv4 = qr/(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))/ixsm;
my $re_domain = qr/(?:[0-9A-Za-z](?:(?:[-A-Za-z0-9]){0,61}[A-Za-z0-9])?(?:\.[A-Za-z](?:(?:[-A-Za-z0-9]){0,61}[A-Za-z0-9])?)*)/ixsm;
my $re_uri = qr/[^ ]+/ixsm;
my $re_qstring = qr/(?:[^ ]+|-)/ixsm;
my $re_msec = qr/\d{10}\.\d{3}/ixsm;
my $re_iis_time = qr/\d{4}-\d{2}-\d{2} \s \d{2}:\d{2}:\d{2}/ixsm;
my $re_status = qr/\d{3}|-/ixsm;
my $re_cost = qr/(?:\d+\.\d+|-|\d+)/ixsm;
my $re_static_err = qr/(?:5\d{2}|404)/ixsm;
my $re_dynamic_err = qr/(?:5\d{2})/ixsm;
my $re_static = qr/\.(?:gif|png|jpg|jpeg|js|css|swf)/ixsm;
my $re_iis_logfile = qr/^ex\d{6}\.log$/ixsm;

# damn it, the position is not same between iis5 and iis6
my $re_iis6 = qr/^($re_iis_time) \s ($re_ipv4) \s (?:\w+) \s ($re_uri) \s (?:$re_qstring) \s ($re_ipv4) \s ($re_status) \s ($re_cost)/ixsm;
my $re_iis5 = qr/^($re_iis_time) \s ($re_ipv4) \s ($re_ipv4) \s (?:\w+) \s ($re_uri) \s (?:$re_qstring) \s ($re_status) \s ($re_cost)/ixsm;


# START OF HELPER FUNCTIONS
sub determin_iislog {
    my $iis_directory = shift;

    my $dir_fh;

    opendir $dir_fh, $iis_directory;

    unless ($dir_fh) {
        $O_ERROR = "failed to open dir: $iis_directory";
        return undef;
    }

    my $rc;
    while ((my $filename = readdir($dir_fh))) {
        # 跳过不符合IIS日志(ex110206.log)
        next unless $filename =~ $re_iis_logfile;

        # 然后取mtime最大的
        my $full_filename = File::Spec->catfile($iis_directory, $filename);
        my $mtime = (stat($full_filename))[9];
        $rc->{$mtime} = $full_filename;
    }

    my @sorted = sort { $b <=> $a } keys %{$rc};
    my $this_file = $rc->{$sorted[0]};

    unless ($this_file) {
        $O_ERROR = "failed to obtain iis logfile, no max mtime";
    }

    return $this_file;
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

# END OF HELPER FUNCTIONS

sub parse_http_iis_v1 {
    my ($timefrm, $logfile, $user_given_domain, $iis_version) = @_;

    my $stop = time() - $timefrm;

    my ($rc_dynamic, $rc_static);

    my $bw = File::ReadBackwards->new($logfile);
    if ($bw) {
        BACKWARD_READ:
        while (defined (my $line = $bw->readline)) {
            chomp $line;
            next BACKWARD_READ if $line =~ /^#/; # 略过header

            my ($msec, $host, $uri, $client, $status, $cost);
            if ($iis_version == 6) {
                if ($line =~ $re_iis6) {
                    ($msec, $host, $uri, $client, $status, $cost) = ($1, $2, $3, $4, $5, $6);
                } else {
                    next BACKWARD_READ;
                }
            } else {
                if ($line =~ $re_iis5) {
                    ($msec, $client, $host, $uri, $status, $cost) = ($1, $2, $3, $4, $5, $6);
                } else {
                    next BACKWARD_READ;
                }
            }

            $msec = str2time($msec) + 3600*8; # 调整到东8区，IIS永远记录的是UTC时间
            if ($msec < $stop) {
                last BACKWARD_READ;
            } else {
                if ($uri !~ $re_static) {
                    if ($status =~ /$re_dynamic_err/) {
                        $rc_dynamic->{$user_given_domain}->{$host}->{error}++;
                    }

                    if ($cost > 0) { # 为0的time taken不计算，不可靠
                        $rc_dynamic->{$user_given_domain}->{$host}->{latency} += $cost;
                        $rc_dynamic->{$user_given_domain}->{$host}->{latency_throughput}++;
                    }

                    $rc_dynamic->{$user_given_domain}->{$host}->{throughput}++;
                } else {
                    if ($status =~ /$re_static_err/) {
                        $rc_static->{$user_given_domain}->{$host}->{error} = 0;
                    }

                    if ($cost > 0) { # 为0的time taken不计算，不可靠
                        $rc_static->{$user_given_domain}->{$host}->{latency} += $cost;
                        $rc_static->{$user_given_domain}->{$host}->{latency_throughput}++;
                    }

                    $rc_static->{$user_given_domain}->{$host}->{throughput}++;
                }
            }
        }
    } else {
        $O_ERROR = "failed to open $logfile";
        return undef;
    }

    return ($rc_dynamic, $rc_static);
}

sub parse_http_nginx_v2 {
    my ($timefrm, $logfile) = @_;

    my $stop = time() - $timefrm;

    my ($rc_dynamic, $rc_static);

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
                        if ($uri !~ $re_static) {
                            if ($upstream eq '-') {
                                next BACKWARD_READ; # 如果upstream为空，表示已经被nginx缓存，相信nginx不会有错，所以不再计算。
                            } else {
                                if ($status =~ /$re_dynamic_err/) {
                                    $rc_dynamic->{$domain}->{$upstream}->{error}++;
                                }
                                $rc_dynamic->{$domain}->{$upstream}->{latency} += $cost if $cost ne '-';
                                $rc_dynamic->{$domain}->{$upstream}->{throughput}++;
                            }
                        } else {
                            # nginx自己处理了请求
                            if ($upstream eq '-') {
                                $upstream = '0.0.0.0';
                            }

                            if ($status =~ /$re_static_err/) {
                                $rc_static->{$domain}->{$upstream}->{error} = 0;
                            }

                            if ($cost eq '-') {
                                $rc_static->{$domain}->{$upstream}->{latency} += 0;
                            } else {
                                $rc_static->{$domain}->{$upstream}->{latency} += $cost;
                            }
                            $rc_static->{$domain}->{$upstream}->{throughput}++;
                        }
                    }
                }
            }
        }
    } else {
        return undef;
    }

    return ($rc_dynamic, $rc_static);
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
    my $want_re = qr/((?:active\sconnections\sopenings)|(?:passive\sconnection\sopenings)|(?:failed\sconnection\sattempts)|(?:connection\sresets\sreceived)|(?:connections\sestablished)|(?:resets\ssent))/ixsm;

    #  Tcp:
    #      759262422 active connections openings
    #      118115924 passive connection openings
    #      2406493 failed connection attempts
    #      2227918 connection resets received
    #      47 connections established
    #      35 resets sent 
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
        if ($line =~ /resets\ssent/ixsm) {
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
                $results .= sprintf("put linux.diskstats %d %d host=%s disk=%s item=%s virtualized=%s\n",
                    time(), $rc->{$d}->{$item}, $target, $d, $item, $params->{virtual});
            }
        }
    }
    elsif ($type eq 'tcpbasics') {
        my $rc= get_tcpbasic();

        foreach my $item (sort keys %{$rc}) {
            $results .= sprintf("put linux.netstat.tcp %d %d host=%s item=%s virtualized=%s\n",
                    time(), $rc->{$item}, $target, $item, $params->{virtual});
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
    elsif ($type eq 'log-iis-v1') {
        # 从IIS文件夹从挑出mtime最大的作为本次扫描对象
        my $iis_logfile = determin_iislog($params->{iis_dir});
        return '' unless $iis_logfile;

        my ($rc_dynamic, $rc_static)  = parse_http_iis_v1($params->{last_n}, $iis_logfile, $params->{user_given_domain}, $params->{iis_version});

        my $interval = $params->{last_n};
        my $metric_name;
        if ($interval == 60) {
            $metric_name = '1min';
        } elsif ($interval == 300) {
            $metric_name = '5min';
        } else {
            $metric_name = "${interval}sec";
        }

        if (defined $rc_dynamic) {
            # 开始计算动态
            foreach my $domain (keys %{$rc_dynamic}) {
                foreach my $host (keys %{$rc_dynamic->{$domain}}) {
                    # 如果error没有，我们这里补个0上去
                    unless (exists $rc_dynamic->{$domain}->{$host}->{error}) {
                        $rc_dynamic->{$domain}->{$host}->{error} = 0;
                    }

                    # 如果latency_throughput不存在，latency也必然不存在。为防止除0，设置latency_throughput = 1
                    unless (exists $rc_dynamic->{$domain}->{$host}->{latency_throughput}) {
                        $rc_dynamic->{$domain}->{$host}->{latency} = 0;
                        $rc_dynamic->{$domain}->{$host}->{latency_throughput} = 1;
                    }

                    foreach my $item (keys %{$rc_dynamic->{$domain}->{$host}}) {
                        next if $item eq 'latency_throughput';

                        if ($item ne 'latency') { # 耗时的算法和其他不同
                            $results .= sprintf("put iis.%s %d %d interval=%s host=%s domain=%s virtualized=%s type=dynamic\n",
                                $item, time(), $rc_dynamic->{$domain}->{$host}->{$item},
                                $metric_name, $target, $domain, $params->{virtual});
                        } else {
                            $results .= sprintf("put iis.%s %d %d interval=%s host=%s domain=%s virtualized=%s type=dynamic\n",
                                $item, time(),
                                ($rc_dynamic->{$domain}->{$host}->{$item}/$rc_dynamic->{$domain}->{$host}->{latency_throughput}),
                                $metric_name, $target, $domain, $params->{virtual});
                        }
                    }
                }
            }
        }

        if (defined $rc_static) {
            # 开始计算静态
            foreach my $domain (keys %{$rc_static}) {
                foreach my $host (keys %{$rc_static->{$domain}}) {
                    unless (exists $rc_static->{$domain}->{$host}->{error}) {
                        $rc_static->{$domain}->{$host}->{error} = 0;
                    }

                    unless (exists $rc_static->{$domain}->{$host}->{latency_throughput}) {
                        $rc_static->{$domain}->{$host}->{latency} = 0;
                        $rc_static->{$domain}->{$host}->{latency_throughput} = 1;
                    }

                    foreach my $item (keys %{$rc_static->{$domain}->{$host}}) {
                        next if $item eq 'latency_throughput';

                        if ($item ne 'latency') { # 耗时的算法和其他不同
                            $results .= sprintf("put iis.%s %d %d interval=%s host=%s domain=%s virtualized=%s type=static\n",
                                $item, time(), $rc_static->{$domain}->{$host}->{$item},
                                $metric_name, $target, $domain, $params->{virtual});
                        } else {
                            $results .= sprintf("put iis.%s %d %d interval=%s host=%s domain=%s virtualized=%s type=static\n",
                                $item, time(),
                                ($rc_static->{$domain}->{$host}->{$item}/$rc_static->{$domain}->{$host}->{latency_throughput}),
                                $metric_name, $target, $domain, $params->{virtual});
                        }
                    }
                }
            }
        }
    } elsif ($type eq 'log-nginx-v2') {
        # 如果不知道是不是在tmpfs上，我们也可以flush一下。
        # tmpfs少了，说不定就是我们引起的。
        if (flush_tmpfs()) {
            system '>' . $params->{nginx_log};

            # flush后日志为空，本次prepare_metrics失败。 
            $O_ERROR = 'tmpfs flushed.';
            return 0;
        }

        my ($rc_dynamic, $rc_static)  = parse_http_nginx_v2($params->{last_n}, $params->{nginx_log});

        my $interval = $params->{last_n};
        my $metric_name;
        if ($interval == 60) {
            $metric_name = '1min';
        } elsif ($interval == 300) {
            $metric_name = '5min';
        } else {
            $metric_name = "${interval}sec";
        }

        if (defined $rc_dynamic) {
            # 开始计算动态
            foreach my $domain (keys %{$rc_dynamic}) {
                foreach my $upstream (keys %{$rc_dynamic->{$domain}}) {
                    # 如果error没有，我们这里补个0上去
                    unless (exists $rc_dynamic->{$domain}->{$upstream}->{error}) {
                        $rc_dynamic->{$domain}->{$upstream}->{error} = 0;
                    }

                    foreach my $item (keys %{$rc_dynamic->{$domain}->{$upstream}}) {
                        if ($item ne 'latency') { # 耗时的算法和其他不同
                            $results .= sprintf("put nginx.%s %d %d interval=%s host=%s domain=%s upstream=%s virtualized=%s type=dynamic\n",
                                $item, time(), $rc_dynamic->{$domain}->{$upstream}->{$item},
                                $metric_name, $target, $domain, $upstream, $params->{virtual});
                        } else {
                            # latency返回毫秒数
                            # 总耗时除以总请求数
                            $results .= sprintf("put nginx.%s %d %d interval=%s host=%s domain=%s upstream=%s virtualized=%s type=dynamic\n",
                                $item, time(),
                                ($rc_dynamic->{$domain}->{$upstream}->{$item}/$rc_dynamic->{$domain}->{$upstream}->{throughput})*1000,
                                $metric_name, $target, $domain, $upstream, $params->{virtual});
                        }
                    }
                }
            }
            
            # 对于接口类型网站，没有static
            if (defined $rc_static) {
                # 开始计算静态
                foreach my $domain (keys %{$rc_static}) {
                    foreach my $upstream (keys %{$rc_static->{$domain}}) {
                        unless (exists $rc_static->{$domain}->{$upstream}->{error}) {
                            $rc_static->{$domain}->{$upstream}->{error} = 0;
                        }

                        foreach my $item (keys %{$rc_static->{$domain}->{$upstream}}) {
                            if ($item ne 'latency') { # 耗时的算法和其他不同
                                $results .= sprintf("put nginx.%s %d %d interval=%s host=%s domain=%s upstream=%s virtualized=%s type=static\n",
                                    $item, time(), $rc_static->{$domain}->{$upstream}->{$item},
                                    $metric_name, $target, $domain, $upstream, $params->{virtual});
                            } else {
                                # latency返回毫秒数
                                # 总耗时除以总请求数
                                $results .= sprintf("put nginx.%s %d %d interval=%s host=%s domain=%s upstream=%s virtualized=%s type=static\n",
                                    $item, time(),
                                    ($rc_static->{$domain}->{$upstream}->{$item}/$rc_static->{$domain}->{$upstream}->{throughput})*1000,
                                    $metric_name, $target, $domain, $upstream, $params->{virtual});
                            }
                        }
                    }
                }
            }
        } else {
            $O_ERROR = 'empty parse_http_nginx_v2()';
            return 0;
        }
    }
    else {
        $O_ERROR = 'impossible';
        return 0;
    }

    return $results;
}

sub usage {
    my $type = shift;

    if ($type == 1) {
        die <<USAGE;
Usage: ocollector [options] -t type

Try `ocollector --help` or `ocollector -h` for more options.
USAGE
    }

    die <<HELP;
Usage: ocollector [options] -t type

Options:
    -v,--verbose                          Print the full collecting results
    -q,--quiet                            Suppress all output even error messages
    -h,--help                             Print this help
    -o,--to                               Specify the address where metrics send to, default: op.sdo.com
    -p,--port                             Specify the port where metrics got sent to, default: 4242
    -i,--interval                         Number of seconds to wait before next send, default: 15
    -a,--amount                           Read this amount of logs, only lines and seconds are recognized, default: 60
    -l,--log                              The absolute path of the logfile to read from, default: /dev/shm/nginx_metrics/metrics.log
    -e,--iisdir                           The absolute folder name of iislog
    -r,--target                           An arbitrary string used to identify this host, default to one's ip
    -u,--virtual                          Set this if the machine is a virtualized one, default: no
    -t,--type                             Specify the collecting type, default: tcpbasics

    --domain                              The domain for iislog
    --iis                                 Specify the version of IIS
    --apparg                              application specific arguments, you can list them like: --apparg ostype=windows --apparg arch=x86_64

Types:
    tcpbasics                             Basic tcp connection info from netstat -st
    diskstats                             Disk devices stats from /proc/diskstats
    log-iis-v1                            Analyze customized IIS log, see iis log format in Notes.2
    log-nginx-v2                          Analyze customized nginx log, see nginx log format in Notes.3
    ServiceMonitor::Memcached             Parse server.check.sdo.com:5237's memcached log

Examples:
    ocollector -v                                                    # send tcpbasic stats to op.sdo.com every 15 seconds and print full results
    ocollector -o metrics.sdo.com -p 3333                            # send to metric.sdo.com:3333
    ocollector -r mysql_master -t diskstats                          # collect diskstats and identify the host by mysql_master 
    ocollector -t diskstats -i 5                                     # send diskstats to op.sdo.com every 5 seconds
    ocollector -t tcpbasics --virtual                                # tag the host as a virtualized one
    ocollector -t log-nginx-v2 -a 30                                 # analyze nginx's metric log every 30 seconds
    ocollector -t log-iis-v1 --domain "a.com" -e "e:\\\\W3SVC123"      # analyze iis website log whose domain is a.com
    nohup ocollector --type log-nginx-v2 &                           # damonize ocollector

Notes:
    1. Use `curl -LO http://op.sdo.com/download/ocollector` to grab the latest stable version.
    2. IIS log format: date time c-ip s-ip cs-method cs-uri-stem cs-uri-query sc-status time-take
    3. Nginx log format: \$msec \$host \$uri \$status \$upstream_addr \$upstream_response_time

HELP

    return 1;
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
    # options

    my $ocollector_daemon       = 'op.sdo.com';
    my $ocollector_port         = 4242;
    my $ocollector_proto        = 'tcp';
    my $ocollector_interval     = 15;
    my $ocollector_target       = q{};
    my $ocollector_version      = q{};
    my $ocollector_type         = q{};
    my $ocollector_nginx_log    = q{};
    my $ocollector_log_lines    = q{};
    my $ocollector_verbose      = q{};
    my $ocollector_virtual      = q{};
    my $ocollector_quiet        = q{};
    my $ocollector_iis_domain   = q{};
    my $ocollector_iis_dir      = q{};
    my $ocollector_iis_version  = q{};
    my $ocollector_apparg       = q{};
    my $help                    = q{};

    usage(1) if (@ARGV < 1);

    Getopt::Long::Configure("bundling");

    usage(2) unless GetOptions(
               "o|to=s" => \$ocollector_daemon,
               "i|interval=i" => \$ocollector_interval,
               "p|port=i" => \$ocollector_port,
               "r|target=s" => \$ocollector_target,
               "t|type=s" => \$ocollector_type,
               "l|log=s" => \$ocollector_nginx_log,
               "e|iisdir=s" => \$ocollector_iis_dir,
               "a|amount=i" => \$ocollector_log_lines,
               "q|quiet" => \$ocollector_quiet,
               "u|virtual" => \$ocollector_virtual,
               "v|verbose" => \$ocollector_verbose,
               "V|version" => \$ocollector_version,
               "h|help" => \$help,
               "domain=s" => \$ocollector_iis_domain,
               "iis=i" => \$ocollector_iis_version,
               "apparg=s%" => \$ocollector_apparg,
   );

    if ($ocollector_version) {
        print "ocollector version: $VERSION\n";
        exit 0;
    }

    usage(2) if $help;

    my $supported = 'diskstats|tcpbasics|log-nginx-v1|log-nginx-v2|log-iis-v1|(?:\w+::\w+)';

    if (!$ocollector_type) {
        $ocollector_type = 'tcpbasics';
    } elsif ($ocollector_type !~ /^(?:$supported)/ixsm) {
        die "[$ocollector_type] is not a supported collecting type, the following type is $supported supported.\n";
    } else {
        1;
    }

    # 如果某种类型的collector需要参数，通过统一的params扔进去。
    my $params;

    # 如果不给出host，则自动获取IP
    if (!$ocollector_target) {
        $ocollector_target = Net::Address::IP::Local->public_ipv4();
    }

    # 每个collector自己的特殊配置
    if ($ocollector_type eq 'log-nginx-v2') {
        # 如果没有指定，默认取前1分钟以及/dev/shm下的日志

        $ocollector_log_lines = 60 unless $ocollector_log_lines;
        $ocollector_nginx_log = '/dev/shm/nginx_metrics/metrics.log' unless $ocollector_nginx_log;
        $ocollector_interval = 60 if $ocollector_interval == 15;
    }
    elsif ($ocollector_type eq 'log-iis-v1') {
        $ocollector_log_lines = 60 unless $ocollector_log_lines;
        $ocollector_interval = 60 if $ocollector_interval == 15;

        unless ($ocollector_iis_version) {
            $ocollector_iis_version = 6;
        }

        if (!-d $ocollector_iis_dir) {
            die "IIS log directory does not exist: [$ocollector_iis_dir]\n";
        }

        unless ($ocollector_iis_domain) { # 其实是iis，懒得改了
            die "IIS domain name is missing\n";
        }
    }
    elsif ($ocollector_type =~ /(?:\w+::\w+)/) {
        foreach my $arg (keys %{$ocollector_apparg}) {
            $params->{$arg} = $ocollector_apparg->{$arg};
        }
     }
    else {
        1;
    }


    $params->{last_n}            = $ocollector_log_lines;
    $params->{nginx_log}         = $ocollector_nginx_log;
    $params->{iis_dir}           = $ocollector_iis_dir;
    $params->{user_given_domain} = $ocollector_iis_domain;
    $params->{iis_version}       = $ocollector_iis_version;

    if ($ocollector_virtual) {
        $params->{virtual} = 'yes';
    } else {
        $params->{virtual} = 'no';
    }

    if ($ocollector_type =~ /(?:\w+::\w+)/) {
        # 应用类型
        my $module = "Ocollector::$ocollector_type";
        my $ot = $module->new($params);

        for (;;) {
            # 只有metrics生成成功才发送，保证tsd那端不会受到乱七八糟的东西。
            if (my $results = $ot->show_results) {
                if (send_metrics($results, $ocollector_daemon, $ocollector_port)) {
                    if ($ocollector_verbose) {
                        log_succeed("send_metrics() succeed:\n$results") unless $ocollector_quiet;
                    } else {
                        log_succeed("send_metrics() succeed.") unless $ocollector_quiet;
                    }
                } else {
                    log_exception('send_metrics') unless $ocollector_quiet;
                }
            } else {
                $O_ERROR = $ot->errormsg;
                log_exception('prepare_metrics') unless $ocollector_quiet;
                $ot->errormsg(q{});
            }

            sleep($ot->interval);
        }
    } else {
        # 内置类型
        for (;;) {
            if (my $results = prepare_metrics($ocollector_target, $ocollector_type, $params)) {
                if (send_metrics($results, $ocollector_daemon, $ocollector_port)) {
                    if ($ocollector_verbose) {
                        log_succeed("send_metrics() succeed:\n$results") unless $ocollector_quiet;
                    } else {
                        log_succeed("send_metrics() succeed.") unless $ocollector_quiet;
                    }
                } else {
                    log_exception('send_metrics') unless $ocollector_quiet;
                }
            }
            else {
                log_exception('prepare_metrics') unless $ocollector_quiet;
            }

            sleep($ocollector_interval);
        }
    }
}

main();
