#!/usr/bin/env perl

use strict;
use warnings;
use File::Spec;
use Data::Dumper;
use File::Slurp qw/slurp/;


sub gen_lib {
    my @want = qw{Common ServiceMonitor/Memcached AccountServer/Cache AccountServer/StatisticDetails Tcpbasic/Windows};
    my $base = '/usr/lib/perl5/site_perl/5.8.8';
    my $namespace = 'Ocollector';
    my $namespace_full = File::Spec->catfile($base, $namespace);

    my $rc;
    map { $rc->{$_} = File::Spec->catfile($namespace_full, "$_.pm") } @want;

    return $rc;
}

sub gen_auto {
    my $base = '/usr/lib/perl5/site_perl/5.8.8/i386-linux-thread-multi/auto';
    my $namespace = 'Ocollector';

    my @gen_files;

    my $rc = gen_lib();
    foreach my $lib (keys %{$rc}) {
        my ($lib_path, $packlist);

        if ($lib !~ /\//) {
            $packlist = File::Spec->catfile($base, $namespace, '.packlist');
            $lib_path = $rc->{$lib};
            my $content = slurp($packlist);
            unless ($content =~ /$lib_path/) {
                system "echo \"$lib_path\" >> $packlist";
            }
        } else {
            my ($node) = ($lib =~ /(.*)\/.*$/ixsm);
            my $dir = File::Spec->catdir($base, $namespace, $node);
            system "mkdir -p $dir";

            $lib_path = $rc->{$lib};
            $packlist = File::Spec->catfile($dir, '.packlist');

            my $content = slurp($packlist);
            unless ($content =~ /$lib_path/) {
                system "echo \"$lib_path\" >> $packlist";
            }
        }

        system "touch $lib_path";
        push @gen_files, $lib_path;
        push @gen_files, $packlist;
    }

    return @gen_files;
}

sub copy_from_lib {
    my @gen_files = @_;

    my $base_auto = '/usr/lib/perl5/site_perl/5.8.8/i386-linux-thread-multi/auto';
    my $base_lib  = '/usr/lib/perl5/site_perl/5.8.8';
    my $lib = './lib';
    foreach my $file (@gen_files) {
        if ($file =~ /\.pm$/ixsm) {
            my $re = qr/$base_lib\/(.*)/ixsm;
            if ($file =~ $re) {
                my $create = File::Spec->catfile($lib, $1);
                my ($dir) = ($create =~ /(.*)\/.*$/);
                system "mkdir -p $dir";
                system "cp $file $create";
            }
        } else {
            my $re = qr/$base_auto\/(.*)/ixsm;
            if ($file =~ $re) {
                my $create = File::Spec->catfile($lib, $1);
                my ($dir) = ($create =~ /(.*)\/.*$/);
                system "mkdir -p $dir";
                system "cp $file $create";
            }
        }
    }
}

my @gen_files = gen_auto();
copy_from_lib(@gen_files);
