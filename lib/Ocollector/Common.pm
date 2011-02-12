package Ocollector::Common;

use strict;
use warnings;
use Digest::MD5;
use File::ReadBackwards;
use File::Spec;
use Date::Tiny;
use Exporter 'import';
our @EXPORT_OK = qw($re_ipv4);

my @accessors;

use base 'Class::Accessor';
Ocollector::Common->mk_accessors(@accessors);

our $VERSION = '1.0';
our $re_ipv4 = qr/(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))/ixsm;

sub new {
    my $class = shift;
    my $opts  = ref($_[0]) ? shift : {@_};

    my $self = {};
    return bless $self, $class;
}

sub determine_log {
    my ($self, $logdir, $logname) = @_;

    my $dt = Date::Tiny->now;
    return File::Spec->catfile($logdir, $dt->ymd, $logname);
}

sub give_md5 {
    my ($self, $content) = @_;

    my $ctx = Digest::MD5->new;
    $ctx->add($content);
    return $ctx->hexdigest;
}

sub determine_latest {
    my ($self, $logdir, $pattern) = @_;

    my $dir_fh;
    if (-d $logdir) {
        opendir $dir_fh, $logdir;

        unless ($dir_fh) {
            return;
        } else {
            my $rc;
            while ((my $filename = readdir($dir_fh))) {
                next unless $filename =~ qr/$pattern/ixsm;

                my $full_filename = File::Spec->catfile($logdir, $filename);
                my $mtime = (stat($full_filename))[9];
                $rc->{$mtime} = $full_filename;
            }

            my @sorted = sort { $b <=> $a } keys %{$rc};
            my $this_file = $rc->{$sorted[0]};

            return $this_file;
        }
    }

    return;
}

1;
