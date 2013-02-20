#!/usr/bin/env perl
use strict;
use warnings;

use Test::More;
use Crypt::RSA::Key;
use Data::Dumper;
use Bytes::Random::Secure;
my $randobj = Bytes::Random::Secure->new(NonBlocking=>1);

plan tests => 3;

# Danaj: This is definitely not the interface I would have chosen.  It would
# seem like you'd like to be able to hand the string to generate.
# Why do I have to make a full new object to deserialize?

my $obj = new Crypt::RSA::Key;

my ($pub, $pri) = $obj->generate(
   Identity => 'Some User <someuser@example.com>',
   Password => 'guess',
   Size => 512,
   KF => 'SSH',
   RandomSub => sub{ $randobj->irand() },
 );
die $obj->errstr if $obj->errstr();
my $n1 = $pub->n;
my $s = $pub->serialize();

my ($newpub, $newpri) = $obj->generate( Size => 128, KF => 'SSH', RandomSub => sub{ $randobj->irand() }, );
my $n2 = $newpub->n;

# Make sure we're not bonkers
isnt($n2, $n1, "Small new object has different n");


$newpub->deserialize( String => $s );

is($newpub->n, $n1, "Correct n after deserialize");
is_deeply( $newpub, $pub, "public key fully deserialized");
