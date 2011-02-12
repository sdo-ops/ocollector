package Ocollector::AccountServer::StatisticDetails;

use strict;
use warnings;
use Date::Parse;
use Data::Dumper;
use Net::Address::IP::Local;

my @accessors = qw( metric logdir logname tag_partial interval errormsg);

use base qw(Class::Accessor Ocollector::Common);
Ocollector::AccountServer::StatisticDetails->mk_accessors(@accessors);

our $VERSION = '1.1';

my $rex_zero      = qr{ , \s 0$}ixsm;
my $rex_game      = qr{ \[ (\d+):(-?\d+) \] }ixsm;
my $rex_all       = qr{ [(] (\d+) [)] .+? [(] (\d+):(\d+) [)] .+? [(] (\d+):(\d+) [)] .+? [(] (\d+):(\d+) [)] }ixsm;

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
        my $re_ipv4 = $Ocollector::Common::re_ipv4;
        my $stop = time - $self->interval;

        BACKWARD_READ:
        while (defined (my $line = $bw->readline)) {
            chomp $line;

            my ($time, $stats) = split /\s+/, $line;

            # anti garbled log here
            unless (defined $time && defined $stats) {
                next BACKWARD_READ;
            }

            # convert 19:47 to 2011-02-10 19:47:00
            $time = sprintf("%s %s:59", Date::Tiny->now->ymd, $time);

            # each line
            my $sec = str2time($time);
            if ($sec >= $stop) {
                my ($gameid, $gamearea) = ($stats =~ $rex_game);

                # metrics are:
                # accountserver.statisticdetails.total
                # accountserver.statisticdetails.staticauthen
                # accountserver.statisticdetails.ekeyauthen
                # accountserver.statisticdetails.ecardauthen

                # tags are: failed, succeed, gameid, gamearea, host, lb

                if ($stats !~ $rex_all) {
                    next BACKWARD_READ;
                } else {
                    my ($total, $static_all, $static_success, $ekey_all, $ekey_success, $ecard_all, $ecard_success)
                        = ($1, $2, $3, $4, $5, $6, $7);
                
                    my $static_fail = $static_all - $static_success;
                    my $ekey_fail   = $ekey_all   - $ekey_success;
                    my $ecard_fail  = $ecard_all  - $ecard_success;

                    $results .= sprintf("put %s %d %d gameid=%d gamearea=%d %s\n",
                        $self->metric . '.total', $sec, $total, $gameid, $gamearea, $self->tag_partial);
                
                    $results .= sprintf("put %s %d %d gameid=%d gamearea=%d type=succeed %s\n",
                        $self->metric . '.static', $sec, $static_success, $gameid, $gamearea, $self->tag_partial);

                    $results .= sprintf("put %s %d %d gameid=%d gamearea=%d type=failed %s\n",
                        $self->metric . '.static', $sec, $static_fail, $gameid, $gamearea, $self->tag_partial);

                    $results .= sprintf("put %s %d %d gameid=%d gamearea=%d type=succeed %s\n",
                        $self->metric . '.ekey', $sec, $ekey_success, $gameid, $gamearea, $self->tag_partial);

                    $results .= sprintf("put %s %d %d gameid=%d gamearea=%d type=failed %s\n",
                        $self->metric . '.ekey', $sec, $ekey_fail, $gameid, $gamearea, $self->tag_partial);

                    $results .= sprintf("put %s %d %d gameid=%d gamearea=%d type=succeed %s\n",
                        $self->metric . '.ecard', $sec, $ecard_success, $gameid, $gamearea, $self->tag_partial);

                    $results .= sprintf("put %s %d %d gameid=%d gamearea=%d type=failed %s\n",
                        $self->metric . '.ecard', $sec, $ecard_fail, $gameid, $gamearea, $self->tag_partial);
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

    return $results;;
}
