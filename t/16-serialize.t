#!/usr/bin/perl

use FindBin qw($Bin);
use lib "$Bin/../lib";
use Crypt::RSA::Key;
use Data::Dumper;

my $i = 0;
print "1..2\n";
my $keychain = new Crypt::RSA::Key; 
my ($pub, $pri) = $keychain->generate(Password => "correct horse battery staple", Size=>256);
die $keychain->errstr if $keychain->errstr();

{
  #$pub->check || die $pub->errstr();
  my $s = $pub->serialize;
  $pub->deserialize(String=>[$s]);
  #$pub->check || die $pub->errstr();
  print $pub->check  ? "ok" : "not ok"; print " ", ++$i, "\n";
}

{
  #$pri->check || die $pri->errstr();
  my $s = $pri->serialize;
  $pri->deserialize(String=>[$s]);
  #$pri->check || die $pri->errstr();
  # Crypt::RSA 1.99 will choke on this
  print $pri->check  ? "ok" : "not ok"; print " ", ++$i, "\n";
}
