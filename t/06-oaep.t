#!/usr/bin/env perl
use strict;
use warnings;

## 06-oaep.t
##
## Copyright (c) 2000, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.

use Test::More;
use Crypt::RSA::ES::OAEP;
use Crypt::RSA::Key;

plan tests => 5;

my $oaep = new Crypt::RSA::ES::OAEP;
my $message = "My plenteous joys, Wanton in fullness, seek to hide themselves.";
my $keychain = new Crypt::RSA::Key;

my ($pub, $priv) = $keychain->generate ( Size => 1024, Password => 'xx', Identity => 'xx', Verbosity => 1 );
ok( ! $keychain->errstr, "No error from generate" );

is( $oaep->encryptblock(Key => $pub), 86, "encryptblock" );

my $ct = $oaep->encrypt (Key => $pub, Message => $message);
ok( ! $oaep->errstr, "No error from oaep encrypt" );
my $pt = $oaep->decrypt (Key => $priv, Cyphertext => $ct);
ok( ! $oaep->errstr, "No error from oaep decrypt" );

is( $pt, $message, "round trip message->encrypt->decrypt = message" );
diag("pt: $pt") if $pt ne $message;
