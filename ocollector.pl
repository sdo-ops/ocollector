#!/usr/bin/env perl
# author:        yanglei@snda.com
# last modified: 2011-02-03
# description:   this script collects interesting data then send to some place for scrunity.

use strict;
use warnings;
use File::Path;
use POSIX qw( strftime );
use Getopt::Long;
use IO::Socket;
use File::ReadBackwards;
use Net::Address::IP::Local;

my $O_ERROR = '';
my $SENDER = 'native';

sub parse_http_nginx_v2 {
    my ($timefrm, $logfile) = @_;

    open my $fh, '<', $logfile;

    if ($fh) {

    } else {
        return undef;
    }
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

    if ($SENDER eq 'nc') {
        my $cmd = "echo $results | nc -w 10 $ocollector_daemon $ocollector_port";
        printf("%s\t%s\n", strftime("%Y-%m-%d %H:%M:%S", localtime), $cmd);
        system $cmd;
    }
    else {
        # send directly through IO::Socket, low dependency thus the default way
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
    }

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
    my $help;

    GetOptions("to=s" => \$ocollector_daemon,
               "interval=i" => \$ocollector_interval,
               "port=i" => \$ocollector_port,
               "target=s" => \$ocollector_target,
               "type=s" => \$ocollector_type,
               "nginx-log=s" => \$ocollector_nginx_log,
               "log-lines=s" => \$ocollector_log_lines,
               "verbose" => \$ocollector_verbose,
               "help" => \$help
               );

    if ($help) {
        usage;
        exit 0;
    }
    my $supported = 'diskstats|tcpbasics|log-nginx-v1';

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

    for (;;) {
        # 只有metrics生成成功才发送，保证tsd那端不会受到乱七八糟的东西。
        if (my $results = prepare_metrics($ocollector_target, $ocollector_type, $params)) {
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

        sleep($ocollector_interval);
    }
}

main();
