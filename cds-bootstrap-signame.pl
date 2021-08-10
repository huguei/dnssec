#!/usr/bin/perl
#
# Calculates the "signaling name" for a fully qualified domain name
# to be used as a bootstrap technique for DNSSEC setup of an unsigned
# zone.
#
# Based on a draft specification (published 21 July 2021)
#    https://desec-io.github.io/draft-thomassen-dnsop-dnssec-bootstrapping/#section-2.2-5
#
# Use:
#      $ cds-bootstrap-signame.pl example.com
#      i0n9ohifkgvslc89q6jbinevgcpol35s799b9uvu3aeobsh4dk7g
#
# Author: Hugo Salgado <hsalgado@nic.cl>
#         NIC Chile
#
use strict;
use warnings;

use Net::DNS::DomainName;
use Digest::SHA;
use MIME::Base32;

my $name = shift;
die "You must provide a domain name" unless $name;

my $rr     = Net::DNS::DomainName->new($name);
my $digest = Digest::SHA::sha256($rr->encode);
my $base32 = MIME::Base32::encode_base32hex($digest);

print lc $base32, "\n";

