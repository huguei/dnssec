#!/usr/bin/perl
#
# Convert an RSA DNSKEY public key in presentation format (like
# from a dig output) to a RSA PEM encoded public key format.
#
# Use:
#     dnskey-to-pem.pl [-] <DNSKEY_RR>
#
# Examples:
#     dnskey-to-pem.pl "cl. 3584  IN  DNSKEY  257 3 8 AwEAAaeKm..."
#     dig cl dnskey | grep 257 | dnskey-to-pem.pl -
#
# Author: Hugo Salgado <hsalgado@nic.cl>
#         NIC Chile
#
use strict;
use warnings;

use bigint;
use Net::DNS::RR;
use Crypt::OpenSSL::Bignum;
use Crypt::OpenSSL::RSA;

my %RSA_ALGOS = (
    1  => 'RSAMD5',
    5  => 'RSASHA1',
    7  => 'RSASHA1-NSEC3-SHA1',
    8  => 'RSASHA256',
    10 => 'RSASHA512',
);

my ($exponent, $modulus);

my $llave = shift;
$llave = <> if $llave eq '-';

# Net::DNS::RR doesn't like TTL and class
$llave =~ s/^([\S]*)\s*\d+\s*IN\s*/$1 /;

my $rr = Net::DNS::RR->new($llave);

die '"This works only for RSA keys (algo 1, 5, 7, 8 and 10)'
    unless $RSA_ALGOS{$rr->algorithm};

# We should unpack exponent and modulus, RFC3110
my ($b, $r) = unpack("B8B*", $rr->keybin);
if ($b) {
    my $largo_expo = oct("0b" . $b);
    $exponent = substr($r, 0, $largo_expo*8);

    my $largo_modulo = $rr->keylength * -1;
    $modulus = substr($r, $largo_modulo);
}
else {
    my $largo_expo = oct("0b" . substr($r, 0, 16));
    $exponent = substr($r, 16, $largo_expo*8);

    my $largo_modulo = $rr->keylength * -1;
    $modulus = substr($r, $largo_modulo);
}

my $bn_e = Crypt::OpenSSL::Bignum->new_from_decimal(oct("0b" . $exponent));
my $bn_m = Crypt::OpenSSL::Bignum->new_from_decimal(oct("0b" . $modulus));

my $rsa_pubkey = Crypt::OpenSSL::RSA->new_key_from_parameters($bn_m, $bn_e);
print $rsa_pubkey->get_public_key_string();

