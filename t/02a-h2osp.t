#!/usr/bin/perl
use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";
use Crypt::RSA::DataFormat qw(i2osp os2ip h2osp);
use Math::BigInt try => 'GMP, Pari';

print "1..1\n";
my $i = 0;

my $hex = "0x 30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40";
my $expect = Math::BigInt->new("1077508215554862611321527363636310207916672064");
my $n = os2ip(h2osp($hex));
print $n == $expect ? "ok" : "not ok"; print " ", ++$i, "\n";
