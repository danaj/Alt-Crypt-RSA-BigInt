#!/usr/bin/perl
use warnings; use strict; use Crypt::RSA::Key; use Crypt::RSA::Key::Private::SSH; my $obj = new Crypt::RSA::Key;
# Create an unencrypted key
my ($pub, $pri) = $obj->generate( Identity => 'Some User <someuser@example.com>', Size => 1024, KF => 'SSH' );
# Now try to encrypt this key
my $crypted = $pri->serialize( Cipher => "Blowfish", Password => "Hunter2" ); 
