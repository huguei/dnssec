#!/usr/bin/perl
#
# DNSSEC RSA key size "length in bits"
#
# Use: dig cl dnskey | grep 257 | xargs -0 perl rsa-key-size.pl 
#
# Author: Hugo Salgado <hsalgado@nic.cl>
#
use strict;
use warnings;

use Net::DNS::RR;

my $key = shift;
my $rr = Net::DNS::RR->new($key);
my $total = length(unpack("B*",$rr->keybin));
my $b = unpack("B8", $rr->keybin);
my $l = unpack("N", pack("B32", substr("0" x 32 . $b, -32)));
my $lengthkey = $total - ($l+1)*8;
print $lengthkey, "\n";

