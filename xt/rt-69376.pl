#!/usr/bin/perl
use warnings;
use strict;
use Crypt::RSA::Key;
use Crypt::RSA::Key::Private::SSH;
use Data::Dumper;
use Data::Compare;

my $obj = new Crypt::RSA::Key;

# Create an unencrypted key
my ($pub, $pri) = $obj->generate( Identity => 'Some User <someuser@example.com>', Size => 1024, KF => 'SSH' );

foreach my $cipher (qw/Blowfish IDEA DES DES3 Twofish2 CAST5 Rijndael RC6 Camellia/) {
  # Now try to encrypt this key
  my $crypted = $pri->serialize( Cipher => $cipher, Password => "Hunter2" );
  # Now decrypt
  my $new_pri = $pri->deserialize( String=> [$crypted], Password => "Hunter2" );

  if (Compare($pri, $new_pri)) {
    print "SUCCESS : $cipher\n";
  } else {
    print Dumper($pri);
    print Dumper($new_pri);
    die "FAILURE: $cipher\n";
  }
}
