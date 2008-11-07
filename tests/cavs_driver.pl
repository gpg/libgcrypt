#!/usr/bin/env perl
#
# $Id: cavs_driver.pl 1383 2008-10-30 11:45:31Z smueller $
#
# CAVS test driver (based on the OpenSSL driver)
# Written by: Stephan Müller <sm@atsec.com>
# Copyright (c) atsec information security corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions: 
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
#                            NO WARRANTY
#
#    BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
#    FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
#    OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
#    PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
#    OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#    MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
#    TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
#    PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
#    REPAIR OR CORRECTION.
#
#    IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
#    WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
#    REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
#    INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
#    OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
#    TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
#    YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
#    PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
#    POSSIBILITY OF SUCH DAMAGES.
#
#
# test execution instruction:
# 1. get the request files from the lab
# 2. call each request file from 1. with this program:
#	$0 <FILE>.rep
# 3. send the resulting file <FILE>.rsp to the lab
#
#
# Test should be easily adoptable to other implementations
# See the first functions for this task
#
# Following tests are covered (others may also be covered
# but have not been tested)
#
# AES
#	[CBC|CFB128|ECB|OFB]GFSbox[128|192|256]
#	[CBC|CFB128|ECB|OFB]MCT[128|192|256]
#	[CBC|CFB128|ECB|OFB]VarKey[128|192|256]
#	[CBC|CFB128|ECB|OFB]KeySbox[128|192|256]
#	[CBC|CFB128|ECB|OFB]MMT[128|192|256]
#	[CBC|CFB128|ECB|OFB]VarTxt[128|192|256]
#
# RSA
#	SigGen[15|RSA]
#	SigVer15
#	(SigVerRSA is not applicable for OpenSSL as X9.31 padding
#		is not done through openssl dgst)
#
# SHA
#	SHA[1|224|256|384|512]ShortMsg
#	SHA[1|224|256|384|512]LongMsg
#	SHA[1|224|256|384|512]Monte
#
# HMAC (SHA - caveat: we only support hash output equal to the block size of
# 	of the hash - we do not support truncation of the hash; to support
# 	that, we first need to decipher the HMAC.req file - see hmac_kat() )
# 	HMAC
#
# TDES
#	T[CBC|CFB??|ECB|OFB]Monte[1|2|3]
#	T[CBC|CFB??|ECB|OFB]permop
#	T[CBC|CFB??|ECB|OFB]MMT[1|2|3]
#	T[CBC|CFB??|ECB|OFB]subtab
#	T[CBC|CFB??|ECB|OFB]varkey
#	T[CBC|CFB??|ECB|OFB]invperm
#	T[CBC|CFB??|ECB|OFB]vartext
#
# ANSI X9.31 RNG
# 	ANSI931_AES128MCT
# 	ANSI931_AES128VST
#
# RC4 (atsec developed tests)
# 	RC4KeyBD
# 	RC4MCT
# 	RC4PltBD
# 	RC4REGT
#

use strict;
use warnings;
use IPC::Open2;
use Getopt::Std;
use MIME::Base64;

# Contains the command line options
my %opt;


#################################################################
##### Central interface functions to the external ciphers #######
#################################################################
# Only these interface routines should be changed in case of
# porting to a new cipher library
#
# For porting to a new library, create implementation of these functions
# and then add pointers to the respective implementation of each
# function to the given variables.

# common encryption/decryption routine
# $1 key in hex form (please note for 3DES: even when ede3 for three
#    independent ciphers is given with the cipher specification, we hand in
#    either one key for k1 = k2 = k3, two keys which are concatinated for
#    k1 = k3, k2 independent, or three keys which are concatinated for
#    k1, k2, k3 independent)
# $2 iv in hex form
# $3 cipher - the cipher string is defined as specified in the openssl
#    enc(1ssl) specification for the option "-ciphername"
#    (e.g. aes-128-cbc or des-ede3-cbc)
# $4 encrypt=1/decrypt=0
# $5 de/encrypted data in hex form
# return en/decrypted data in hex form
my $encdec;

# Sign a message with RSA
# $1: data to be signed in hex form
# $2: Hash algo
# $3: Key file in PEM format with the private key
# return: digest in hex format
my $rsa_sign;

# Verify a message with RSA
# $1: data to be verified in hex form
# $2: hash algo
# $3: file holding the public RSA key in PEM format
# $4: file holding the signature in binary form
# return: 1 == verfied / 0 == not verified
my $rsa_verify;

# generate a new private RSA key with the following properties:
# 	exponent is 65537
#	PEM format
# $1 key size in bit
# $2 keyfile name
# return: nothing, but file created
my $gen_rsakey;

# Creating a hash
# $1: Plaintext in hex form
# $2: hash type in the form documented in openssl's dgst(1ssl) - e.g.
#     sha1, sha224, sha256, sha384, sha512
# return: hash in hex form
my $hash;

# supplying the call to the external cipher implementation
# that is being used to keep STDIN and STDOUT open
# to maintain the state of the block chaining
# $1: cipher
# $2: 1=encryption, 0=decryption
# $3: buffersize needed for openssl
# $4: encryption key in binary form
# $5: IV in binary form
# return: command line to execute the application
my $state_cipher;

# supplying the call to the external cipher implementation
# that is being used to keep STDIN and STDOUT open
# to maintain the state of the RNG with its seed
#
# input holds seed values
# $1: cipher key in hex format
# $2: DT value in hex format
# $3: V value in hex format
#
# return: command line to execute the application
#
# the application is expected to deliver random values on STDOUT - the script
# reads 128 bits repeatedly where the state of the RNG must be retained
# between the reads. The output of the RNG on STDOUT is assumed to be binary.
my $state_rng;

# Generate an HMAC based on SHAx
# $1: Key to be used for the HMAC in hex format
# $2: length of the hash to be calculated in bits
# $3: Message for which the HMAC shall be calculated in hex format
# $4: hash type (1 - SHA1, 224 - SHA224, and so on)
# return: calculated HMAC in hex format
my $hmac;

################################################################
##### OpenSSL interface functions
################################################################
sub openssl_encdec($$$$$) {
	my $key=shift;
	my $iv=shift;
	my $cipher=shift;
	my $enc = (shift) ? "-e" : "-d";
	my $data=shift;

	# We only invoke the driver with the IV parameter, if we have
	# an IV, otherwise, we skip it
	$iv = "-iv $iv" if ($iv);

	$data=hex2bin($data);
	my $program="openssl enc -$cipher -nopad -nosalt -K $key $enc $iv";
	$program = "rc4 -k $key" if $opt{'R'}; #for ARCFOUR, no IV must be given
	$data=pipe_through_program($data,$program);
	return bin2hex($data);
}

sub openssl_rsa_sign($$$) {
	my $data = shift;
	my $cipher = shift;
	my $keyfile = shift;

	$data=hex2bin($data);
	die "ARCFOUR not available for RSA" if $opt{'R'};
	$data=pipe_through_program($data,
		"openssl dgst -$cipher -binary -sign $keyfile");
	return bin2hex($data);
}

sub openssl_rsa_verify($$$$) {
	my $data = shift;
	my $cipher = shift;
	my $keyfile = shift;
	my $sigfile = shift;

	$data = hex2bin($data);
	die "ARCFOUR not available for RSA" if $opt{'R'};
	$data = pipe_through_program($data,
		"openssl dgst -$cipher -binary -verify $keyfile -signature $sigfile");

	# Parse through the OpenSSL output information
	return ($data =~ /OK/);
}

sub openssl_gen_rsakey($$) {
	my $keylen = shift;
	my $file = shift;

	die "ARCFOUR not available for RSA" if $opt{'R'};
	# generating of a key with exponent 0x10001
	my @args = ("openssl", "genrsa", "-F4", "-out", "$file", "$keylen");
        system(@args) == 0
		or die "system @args failed: $?";
	die "system @args failed: file $file not created" if (! -f $file);
}

sub openssl_hash($$) {
	my $pt = shift;
	my $cipher = shift;

	die "ARCFOUR not available for hashes" if $opt{'R'};
	my $hash = hex2bin($pt);
	#bin2hex not needed as the '-hex' already converts it
	return pipe_through_program($hash, "openssl dgst -$cipher -hex");
}

sub openssl_state_cipher($$$$$) {
	my $cipher = shift;
	my $encdec = shift;
	my $bufsize = shift;
	my $key = shift;
	my $iv = shift;

        #FIXME: Implement the inner loop right here.

	my $enc = $encdec ? "-e": "-d";

	# We only invoke the driver with the IV parameter, if we have
	# an IV, otherwise, we skip it
	$iv = "-iv ".bin2hex($iv) if ($iv);

	my $out = "openssl enc -'$cipher' $enc -nopad -nosalt -bufsize $bufsize -K ".bin2hex($key)." $iv";
	#for ARCFOUR, no IV must be given
	$out = "rc4 -k " . bin2hex($key) if $opt{'R'};
	return $out;
}

###### End of OpenSSL interface implementation ############

###########################################################
###### libgcrypt implementation
###########################################################
sub libgcrypt_encdec($$$$$) {
	my $key=shift;
	my $iv=shift;
	my $cipher=shift;
	my $enc = (shift) ? "encrypt" : "decrypt";
	my $data=shift;

	# We only invoke the driver with the IV parameter, if we have
	# an IV, otherwise, we skip it
	$iv = "--iv $iv" if ($iv);

	my $program="fipsdrv --key $key $iv --algo $cipher $enc";

	return pipe_through_program($data,$program);

}

sub libgcrypt_rsa_sign($$$) {
	my $data = shift;
	my $hashalgo = shift;
	my $keyfile = shift;

	die "ARCFOUR not available for RSA" if $opt{'R'};

	return pipe_through_program($data,
		"fipsdrv --pkcs1 --algo $hashalgo --key $keyfile rsa-sign");
}

sub libgcrypt_rsa_verify($$$$) {
	my $data = shift;
	my $hashalgo = shift;
	my $keyfile = shift;
	my $sigfile = shift;

	die "ARCFOUR not available for RSA" if $opt{'R'};
	$data = pipe_through_program($data,
		"fipsdrv --pkcs1 --algo $hashalgo --key $keyfile --signature $sigfile rsa-verify");

	# Parse through the output information
	return ($data =~ /GOOD signature/);
}

sub libgcrypt_gen_rsakey($$) {
	my $keylen = shift;
	my $file = shift;

	die "ARCFOUR not available for RSA" if $opt{'R'};
	my @args = ("fipsdrv --keysize $keylen rsa-gen > $file");
	system(@args) == 0
		or die "system @args failed: $?";
	die "system @args failed: file $file not created" if (! -f $file);
}

sub libgcrypt_hash($$) {
	my $pt = shift;
	my $hashalgo = shift;

	my $program = "fipsdrv --algo $hashalgo digest";
	die "ARCFOUR not available for hashes" if $opt{'R'};

	return pipe_through_program($pt, $program);
}

sub libgcrypt_state_cipher($$$$$) {
	my $cipher = shift;
	my $enc = (shift) ? "encrypt": "decrypt";
	my $bufsize = shift;
	my $key = shift;
	my $iv = shift;

	my $program="fipsdrv --algo '$cipher' --mct-server $enc";
	return $program;
}

sub libgcrypt_state_rng($$$) {
	my $key = shift;
	my $dt = shift;
	my $v = shift;

	return "fipsdrv --binary --loop --key $key --iv $v --dt $dt random";
}

sub libgcrypt_hmac($$$$) {
	my $key = shift;
	my $maclen = shift;
	my $msg = shift;
	my $hashtype = shift;

	my $program = "fipsdrv --key $key --algo $hashtype hmac-sha";
	return pipe_through_program($msg, $program);	
}

######### End of libgcrypt implementation ################

################################################################
###### Vendor1 interface functions
################################################################

sub vendor1_encdec($$$$$) {
	my $key=shift;
	my $iv=shift;
	my $cipher=shift;
	my $enc = (shift) ? "encrypt" : "decrypt";
	my $data=shift;

	$data=hex2bin($data);
	my $program = "./aes $enc $key";
	$data=pipe_through_program($data,$program);
	return bin2hex($data);
}

sub vendor1_state_cipher($$$$$) {
	my $cipher = shift;
	my $encdec = shift;
	my $bufsize = shift;
	my $key = shift;
	my $iv = shift;

	$key = bin2hex($key);
	my $enc = $encdec ? "encrypt": "decrypt";
	my $out = "./aes $enc $key $bufsize";
	return $out;
}

##### No other interface functions below this point ######
##########################################################

##########################################################
# General helper routines

# Executing a program by feeding STDIN and retrieving
# STDOUT
# $1: data string to be piped to the app on STDIN
# rest: program and args
# returns: STDOUT of program as string
sub pipe_through_program($@) {
	my $in = shift;
	my @args = @_;

	my ($CO, $CI);
	my $pid = open2($CO, $CI, @args);
	
	my $out = "";
	my $len = length($in);
	my $first = 1;
	while (1) {
		my $rin = "";
		my $win = "";
		# Output of prog is FD that we read
		vec($rin,fileno($CO),1) = 1;
		# Input of prog is FD that we write
		# check for $first is needed because we can have NULL input
		# that is to be written to the app
		if ( $len > 0 || $first) {
			(vec($win,fileno($CI),1) = 1);
			$first=0;
		}
		# Let us wait for 100ms
		my $nfound = select(my $rout=$rin, my $wout=$win, undef, 0.1);
		if ( $wout ) {
			my $written = syswrite($CI, $in, $len);
			die "broken pipe" if !defined $written;
			$len -= $written;
			substr($in, 0, $written) = "";
			if ($len <= 0) {
				close $CI or die "broken pipe: $!";
			}
		}
		if ( $rout ) {
			my $tmp_out = "";
			my $bytes_read = sysread($CO, $tmp_out, 4096);
			$out .= $tmp_out;
			last if ($bytes_read == 0);
		}
	}
	close $CO or die "broken pipe: $!";
	waitpid $pid, 0;
	
	return $out;
}

#
# convert ASCII hex to binary input
# $1 ASCII hex
# return binary representation
sub hex2bin($) {
	my $in = shift;
	my $len = length($in);
	$len = 0 if ($in eq "00");
	return pack("H$len", "$in");
}

#
# convert binary input to ASCII hex
# $1 binary value
# return ASCII hex representation
sub bin2hex($) {
	my $in = shift;
	my $len = length($in)*2;
	return unpack("H$len", "$in");
}

# $1: binary byte (character)
# returns: binary byte with odd parity using low bit as parity bit
sub odd_par($) {
	my $in = ord(shift);
	my $odd_count=0;
	for(my $i=1; $i<8; $i++) {
		$odd_count++ if ($in & (1<<$i));
	}

	my $out = $in;
	if ($odd_count & 1) { # check if parity is already odd
		$out &= ~1; # clear the low bit
	} else {
		$out |= 1; # set the low bit
	}

	return chr($out);
}

# DES keys uses only the 7 high bits of a byte, the 8th low bit
# is the parity bit
# as the new key is calculated from oldkey XOR cipher in the MCT test,
# the parity is not really checked and needs to be set to match
# expectation (OpenSSL does not really care, but the FIPS
# test result is expected that the key has the appropriate parity)
# $1: arbitrary binary string
# returns: string with odd parity set in low bit of each byte
sub fix_key_parity($) {
	my $in = shift;
	my $out = "";
	for (my $i = 0; $i < length($in); $i++) {
		$out .= odd_par(substr($in, $i, 1));
	}

	return $out;
}

####################################################
# Encrypt/Decrypt routines

# encryption
# $1 key in hex form
# $2 iv in hex form
# $3 cipher
# $4 data in hex form
# return encrypted data
sub encrypt($$$$) {
	my $key=shift;
	my $iv=shift;
	my $cipher=shift;
	my $data=shift;

	return &$encdec($key, $iv, $cipher, 1, $data);
}

# decryption
# $1 key in hex form
# $2 iv in hex form
# $3 cipher
# $4 data in hex form
# return encrypted data
sub decrypt($$$$) {
	my $key=shift;
	my $iv=shift;
	my $cipher=shift;
	my $data=shift;

	return &$encdec($key, $iv, $cipher, 0, $data);
}

####################################################
# DER/PEM utility functions
# Cf. http://www.columbia.edu/~ariel/ssleay/layman.html

# Convert unsigned integer to base256 bigint bytes
# $1 integer
# returns base256 octet string
sub int_base256_unsigned($) {
	my $n = shift;

	my $out = chr($n & 255);
	while ($n>>=8) {
		$out = chr($n & 255) . $out;
	}

	return $out;
}

# Convert signed integer to base256 bigint bytes
# $1 integer
# returns base256 octet string
sub int_base256_signed($) {
	my $n = shift;
	my $negative = ($n < 0);

	if ($negative) {
		$n = -$n-1;
	}

	my $out = int_base256_unsigned($n);

	if (ord(substr($out, 0, 1)) & 128) {
		# it's supposed to be positive but has sign bit set,
		# add a leading zero
		$out = chr(0) . $out;
	}

	if ($negative) {
		my $neg = chr(255) x length($out);
		$out ^= $neg;
	}

	return $out;
}

# Length header for specified DER object length
# $1 length as integer
# return octet encoding for length
sub der_len($) {
	my $len = shift;

	if ($len <= 127) {
		return chr($len);
	} else {
		my $blen = int_base256_unsigned($len);

		return chr(128 | length($blen)) . $blen;
	}
}

# Prepend length header to object
# $1 object as octet sequence
# return length header for object followed by object as octets
sub der_len_obj($) {
	my $x = shift;

	return der_len(length($x)) . $x;
}

# DER sequence
# $* objects
# returns DER sequence consisting of the objects passed as arguments
sub der_seq {
	my $seq = join("", @_);
	return chr(0x30) . der_len_obj($seq);
}

# DER bitstring
# $1 input octets (must be full octets, fractional octets not supported)
# returns input encapsulated as bitstring
sub der_bitstring($) {
	my $x = shift;

	$x = chr(0) . $x;

	return chr(0x03) . der_len_obj($x);
}

# base-128-encoded integer, used for object numbers.
# $1 integer
# returns octet sequence
sub der_base128($) {
	my $n = shift;

	my $out = chr($n & 127);

	while ($n>>=7) {
		$out = chr(128 | ($n & 127)) . $out;
	}

	return $out;
}

# Generating the PEM certificate string
# (base-64-encoded DER string)
# $1 DER string
# returns octet sequence
sub pem_cert($) {
	my $n = shift;

	my $out = "-----BEGIN PUBLIC KEY-----\n";
	$out .= encode_base64($n);
	$out .= "-----END PUBLIC KEY-----\n";

	return $out;
}

# DER object identifier
# $* sequence of id numbers
# returns octets
sub der_objectid {
	my $v1 = shift;
	my $v2 = shift;

	my $out = chr(40*$v1 + $v2) . join("", map { der_base128($_) } @_);

	return chr(0x06) . der_len_obj($out);
}

# DER signed integer
# $1 number as octet string (base 256 representation, high byte first)
# returns number in DER integer encoding
sub der_bigint($) {
	my $x = shift;

	return chr(0x02) . der_len_obj($x);
}

# DER positive integer with leading zeroes stripped
# $1 number as octet string (base 256 representation, high byte first)
# returns number in DER integer encoding
sub der_pos_bigint($) {
	my $x = shift;

	# strip leading zero digits
	$x =~ s/^[\0]+//;

	# need to prepend a zero if high bit set, since it would otherwise be
	# interpreted as a negative number. Also needed for number 0.
	if (!length($x) || ord(substr($x, 0, 1)) >= 128) {
		$x = chr(0) . $x;
	}

	return der_bigint($x);
}

# $1 number as signed integer
# returns number as signed DER integer encoding
sub der_int($) {
	my $n = shift;
	
	return der_bigint(int_base256_signed($n));
}

# the NULL object constant
sub der_null() {
	return chr(0x05) . chr(0x00);
}

# Unit test helper
# $1 calculated result
# $2 expected result
# no return value, dies if results differ, showing caller's line number
sub der_test($$) {
	my $actual = bin2hex(shift);
	my $expected = shift;

	my @caller = caller;
	$actual eq $expected or die "Error:line $caller[2]:assertion failed: "
		."$actual != $expected\n";
}

# Unit testing for the DER encoding functions
# Examples from http://www.columbia.edu/~ariel/ssleay/layman.html
# No input, no output. Dies if unit tests fail.
sub der_unit_test {
	## uncomment these if you want to test the test framework
	#print STDERR "Unit test running\n";
	#der_test chr(0), "42";

	der_test der_null, "0500";

	# length bytes
	der_test der_len(1), "01";
	der_test der_len(127), "7f";
	der_test der_len(128), "8180";
	der_test der_len(256), "820100";
	der_test der_len(65536), "83010000";

	# bigint
	der_test der_bigint(chr(0)), "020100";
	der_test der_bigint(chr(128)), "020180"; # -128
	der_test der_pos_bigint(chr(128)), "02020080"; # +128
	der_test der_pos_bigint(chr(0).chr(0).chr(1)), "020101";
	der_test der_pos_bigint(chr(0)), "020100";

	# integers (tests base256 conversion)
	der_test der_int(     0), "020100";
	der_test der_int(   127), "02017f";
	der_test der_int(   128), "02020080";
	der_test der_int(   256), "02020100";
	der_test der_int(    -1), "0201ff";
	der_test der_int(  -128), "020180";
	der_test der_int(  -129), "0202ff7f";
	der_test der_int(-65536), "0203ff0000";
	der_test der_int(-65537), "0203feffff";

	# object encoding, "RSA Security"
	der_test der_base128(840), "8648";
	der_test der_objectid(1, 2, 840, 113549), "06062a864886f70d";

	# Combinations
	der_test der_bitstring("ABCD"), "03050041424344";
	der_test der_bitstring(der_null), "0303000500";
	der_test der_seq(der_int(0), der_null), "30050201000500";

	# The big picture
	der_test der_seq(der_seq(der_objectid(1, 2, 840, 113549), der_null),
	                 der_bitstring(der_seq(der_pos_bigint(chr(5)),
	                                       der_pos_bigint(chr(3))))),
	         "3017300a06062a864886f70d05000309003006020105020103";
}

####################################################
# OpenSSL missing functionality workarounds

## Format of an RSA public key:
#    0:d=0  hl=3 l= 159 cons: SEQUENCE          
#    3:d=1  hl=2 l=  13 cons:  SEQUENCE          
#    5:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
#   16:d=2  hl=2 l=   0 prim:   NULL              
#   18:d=1  hl=3 l= 141 prim:  BIT STRING        
#                              [ sequence: INTEGER (n), INTEGER (e) ]

# generate RSA pub key in PEM format
# $1: filename where PEM key is to be stored
# $2: n of the RSA key in hex
# $3: e of the RSA key in hex
# return: nothing, but file created
sub gen_pubrsakey($$$) {
	my $filename=shift;
	my $n = shift;
	my $e = shift;

	# make sure the DER encoder works ;-)
	der_unit_test();

	# generate DER encoding of the public key

	my $rsaEncryption = der_objectid(1, 2, 840, 113549, 1, 1, 1);

	my $der = der_seq(der_seq($rsaEncryption, der_null),
	                  der_bitstring(der_seq(der_pos_bigint(hex2bin($n)),
	                                        der_pos_bigint(hex2bin($e)))));

	open(FH, ">", $filename) or die;
	print FH pem_cert($der);
	close FH;

}

# generate RSA pub key in PEM format
#
# This implementation uses "openssl asn1parse -genconf" which was added
# in openssl 0.9.8. It is not available in older openssl versions.
#
# $1: filename where PEM key is to be stored
# $2: n of the RSA key in hex
# $3: e of the RSA key in hex
# return: nothing, but file created
sub gen_pubrsakey_using_openssl($$$) {
	my $filename=shift;
	my $n = shift;
	my $e = shift;

	my $asn1 = "asn1=SEQUENCE:pubkeyinfo

[pubkeyinfo]
algorithm=SEQUENCE:rsa_alg
pubkey=BITWRAP,SEQUENCE:rsapubkey

[rsa_alg]
algorithm=OID:rsaEncryption
parameter=NULL

[rsapubkey]
n=INTEGER:0x$n

e=INTEGER:0x$e";

	open(FH, ">$filename.cnf") or die "Cannot create file $filename.cnf: $?";
	print FH $asn1;
	close FH;
	my @args = ("openssl", "asn1parse", "-genconf", "$filename.cnf", "-noout", "-out", "$filename.der");
	system(@args) == 0 or die "system @args failed: $?";
	@args = ("openssl", "rsa", "-inform", "DER", "-in", "$filename.der",
		 "-outform", "PEM", "-pubin", "-pubout", "-out", "$filename");
	system(@args) == 0 or die "system @args failed: $?";
	die "RSA PEM formatted key file $filename was not created"
		if (! -f $filename);

	unlink("$filename.cnf");
	unlink("$filename.der");
}

############################################
# Test cases

# This is the Known Answer Test
# $1: the string that we have to put in front of the key
#     when printing the key
# $2: crypto key1 in hex form
# $3: crypto key2 in hex form (TDES, undef otherwise)
# $4: crypto key3 in hex form (TDES, undef otherwise)
# $5: IV in hex form
# $6: Plaintext (enc=1) or Ciphertext (enc=0) in hex form
# $7: cipher
# $8: encrypt=1/decrypt=0
# return: string formatted as expected by CAVS
sub kat($$$$$$$$) {
	my $keytype = shift;
	my $key1 = shift;
	my $key2 = shift;
	my $key3 = shift;
	my $iv = shift;
	my $pt = shift;
	my $cipher = shift;
	my $enc = shift;

	my $out = "";

	$out .= "$keytype = $key1\n";

	# this is the concardination of the keys for 3DES
	if (defined($key2)) {
		$out .= "KEY2 = $key2\n";
		$key1 = $key1 . $key2;
	}
	if (defined($key3)) {
		$out .= "KEY3 = $key3\n";
		$key1= $key1 . $key3;
	}
	
	$out .= "IV = $iv\n" if (defined($iv) && $iv ne "");
	if ($enc) {
		$out .= "PLAINTEXT = $pt\n";
		$out .= "CIPHERTEXT = " . encrypt($key1, $iv, $cipher, $pt) . "\n";
	} else {
		$out .= "CIPHERTEXT = $pt\n";
		$out .= "PLAINTEXT = " . decrypt($key1, $iv, $cipher, $pt) . "\n";
	}

	return $out;
}

# This is the Known Answer Test for Hashes
# $1: Plaintext in hex form
# $2: hash
# $3: hash length (undef if not applicable)
# return: string formatted as expected by CAVS
sub hash_kat($$$) {
	my $pt = shift;
	my $cipher = shift;
	my $len = shift;

	my $out = "";
	$out .= "Len = $len\n" if (defined($len));
	$out .= "Msg = $pt\n";

	$pt = "" if(!$len);
	$out .= "MD = " . &$hash($pt, $cipher) . "\n";
	return $out;
}

# Known Answer Test for HMAC hash
# $1: key length in bytes
# $2: MAC length in bytes
# $3: key for HMAC in hex form
# $4: message to be hashed
# return: string formatted as expected by CAVS
sub hmac_kat($$$$) {
	my $klen = shift;
	my $tlen = shift;
	my $key  = shift;
	my $msg  = shift;

	# XXX this is a hack - we need to decipher the HMAC REQ files in a more
	# sane way
	#
	# This is a conversion table from the expected hash output size
	# to the assumed hash type - we only define here the block size of
	# the underlying hashes and do not allow any truncation
	my %hashtype = (
		20 => 1,
		28 => 224,
		32 => 256,
		48 => 384,
		64 => 512
	);

	die "Hash output size $tlen is not supported!"
		if(!defined($hashtype{$tlen}));

	my $out = "";
	$out .= "Klen = $klen\n";
	$out .= "Tlen = $tlen\n";
	$out .= "Key = $key\n";
	$out .= "Msg = $msg\n";
	$out .= "Mac = " . &$hmac($key, $tlen, $msg, $hashtype{$tlen}) . "\n\n";

	return $out;
}


# Cipher Monte Carlo Testing
# $1: the string that we have to put in front of the key
#     when printing the key
# $2: crypto key1 in hex form
# $3: crypto key2 in hex form (TDES, undef otherwise)
# $4: crypto key3 in hex form (TDES, undef otherwise)
# $5: IV in hex form
# $6: Plaintext (enc=1) or Ciphertext (enc=0) in hex form
# $7: cipher
# $8: encrypt=1/decrypt=0
# return: string formatted as expected by CAVS
sub crypto_mct($$$$$$$$) {
	my $keytype = shift;
        my $key1 = hex2bin(shift);
        my $key2 = shift;
        my $key3 = shift;
        my $iv = hex2bin(shift);
        my $source_data = hex2bin(shift);
	my $cipher = shift;
        my $enc = shift;
        my $line;
        my $next_source;

	my $out = "";

	$key2 = hex2bin($key2) if (defined($key2));
	$key3 = hex2bin($key3) if (defined($key3));
        my $bufsize = length($source_data);

	# for AES: outer loop 0-99, inner 0-999 based on FIPS compliance tests
	# for RC4: outer loop 0-99, inner 0-999 based on atsec compliance tests
	# for DES: outer loop 0-399, inner 0-9999 based on FIPS compliance tests
	my $ciph = substr($cipher,0,3);
	my $oloop=100;
	my $iloop=1000;
	if ($ciph =~ /des/) {$oloop=400;$iloop=10000;}

        my ($CO, $CI);
        my $cipher_imp = &$state_cipher($cipher, $enc, $bufsize, $key1, $iv);
        my $pid = open2($CO, $CI, $cipher_imp);
        my $len;

        for (my $i=0; $i<$oloop; ++$i) {
                my $calc_data;
                my $old_calc_data;
                my $old_old_calc_data;
                my $ov;

		$out .= "COUNT = $i\n";
		if (defined($key2)) {
			$out .= "$keytype = ". bin2hex($key1). "\n";
			$out .= "KEY2 = ". bin2hex($key2). "\n";
			$key1 = $key1 . $key2;
		} else {
			$out .= "$keytype = ". bin2hex($key1). "\n";
		}
		if(defined($key3)) {
			$out .= "KEY3 = ". bin2hex($key3). "\n";
			$key1 = $key1 . $key3;
		}
        	my $keylen = length($key1);

                $out .= "IV = ". bin2hex($iv) . "\n"
			if (defined($iv) && $iv ne "");

                if ($enc) {
                        $out .= "PLAINTEXT = ". bin2hex($source_data). "\n";
                } else {
                        $out .= "CIPHERTEXT = ". bin2hex($source_data). "\n";
                }

                print $CI "1\n"
                          .$iloop."\n"
                          .bin2hex($key1)."\n"
                          .bin2hex($iv)."\n"
                          .bin2hex($source_data)."\n\n" or die;
                
                # fixme: We should skip over empty lines here.

                chomp($line = <$CO>); #print STDERR "        calc=$line\n";
                $calc_data = hex2bin($line);

                chomp($line = <$CO>); #print STDERR "    old_calc=$line\n";
                $old_calc_data = hex2bin($line);

                chomp($line = <$CO>); #print STDERR "old_old_calc=$line\n";
                $old_old_calc_data = hex2bin($line);
                
                chomp($line = <$CO>); #print STDERR "          ov=$line\n";
                $ov = hex2bin($line);
                
                chomp($line = <$CO>); #print STDERR " next source=$line\n";
                $next_source = hex2bin($line);

                # Skip over empty line.
                $line = <$CO>;


                if ($enc) {
                        $out .= "CIPHERTEXT = ". bin2hex($calc_data). "\n\n";
                } else {
                        $out .= "PLAINTEXT = ". bin2hex($calc_data). "\n\n";
                }

		if ( $ciph =~ /aes/ ) {
	                $key1 ^= substr($old_calc_data . $calc_data, -$keylen);
			#print STDERR bin2hex($key1)."\n";
		} elsif ( $ciph =~ /des/ ) {
			die "Wrong keylen $keylen" if ($keylen != 24);

			# $nkey needed as $key holds the concatenation of the
			# old key atm
			my $nkey = fix_key_parity(substr($key1,0,8) ^ $calc_data);
			#print STDERR "KEY1 = ". bin2hex($nkey)."\n";
			if (substr($key1,0,8) ne substr($key1,8,8)) {
				#print STDERR "KEY2 recalc: KEY1==KEY3, KEY2 indep. or all KEYs are indep.\n";
				$key2 = fix_key_parity((substr($key1,8,8) ^ $old_calc_data));
			} else {
				#print STDERR "KEY2 recalc: KEY1==KEY2==KEY3\n";
				$key2 = fix_key_parity((substr($key1,8,8) ^ $calc_data));
			}
			#print STDERR "KEY2 = ". bin2hex($key2)."\n";
			if ( substr($key1,0,8) eq substr($key1,16)) {
				#print STDERR "KEY3 recalc: KEY1==KEY2==KEY3 or KEY1==KEY3, KEY2 indep.\n";
				$key3 = fix_key_parity((substr($key1,16) ^ $calc_data));
			} else {
				#print STDERR "KEY3 recalc: all KEYs are independent\n";
				$key3 = fix_key_parity((substr($key1,16) ^ $old_old_calc_data));
			}
			#print STDERR "KEY3 = ". bin2hex($key3)."\n";

			# reset the first key - concardination happens at
			# beginning of loop
			$key1=$nkey;
		} elsif ($ciph =~ /rc4/ ) {
			$key1 ^= substr($calc_data, 0, 16);
			#print STDERR bin2hex($key1)."\n";
		} else {
			die "Test limitation: cipher '$cipher' not supported in Monte Carlo testing";
		}

                if ($ciph =~ /des/) {
                    $iv = $ov;
                    if ($cipher =~ /des-ede3-ofb/) {
                        $source_data = $source_data ^ $next_source;
                    } else {
                        $source_data = $next_source;
                    }
		} elsif ( $ciph =~ /rc4/ || $cipher =~ /ecb/ ) {
			#No resetting of IV as the IV is all zero set initially (i.e. no IV)
			$source_data = $calc_data;
		} else {
	                $iv = $calc_data;
			$source_data = $old_calc_data;
		}

        }
        close $CO;
        close $CI;
        waitpid $pid, 0;

	return $out;
}

# Hash Monte Carlo Testing
# $1: Plaintext in hex form
# $2: hash
# return: string formatted as expected by CAVS
sub hash_mct($$) {
	my $pt = shift;
	my $cipher = shift;

	my $out = "";

	$out .= "Seed = $pt\n\n";

        for (my $j=0; $j<100; ++$j) {
		$out .= "COUNT = $j\n";
		my $md0=$pt;
		my $md1=$pt;
		my $md2=$pt;
        	for (my $i=0; $i<1000; ++$i) {
			#print STDERR "outer loop $j; inner loop $i\n";
			my $mi= $md0 . $md1 . $md2;
			$md0=$md1;
			$md1=$md2;
			$md2 = &$hash($mi, $cipher);
			$md2 =~ s/\n//;
		}
                $out .= "MD = $md2\n\n";
		$pt=$md2;
	}

	return $out;
}

# RSA SigGen test
# $1: Message to be signed in hex form
# $2: Hash algorithm
# $3: file name with RSA key in PEM form
# return: string formatted as expected by CAVS
sub rsa_siggen($$$) {
	my $data = shift;
	my $cipher = shift;
	my $keyfile = shift;

	my $out = "";

	$out .= "SHAAlg = $cipher\n";
	$out .= "Msg = $data\n";
	$out .= "S = " . &$rsa_sign($data, lc($cipher), $keyfile) . "\n";

	return $out;
}

# RSA SigVer test
# $1: Message to be verified in hex form
# $2: Hash algoritm
# $3: Signature of message in hex form
# $4: n of the RSA key in hex in hex form
# $5: e of the RSA key in hex in hex form
# return: string formatted as expected by CAVS
sub rsa_sigver($$$$$) {
	my $data = shift;
	my $cipher = shift;
	my $signature = shift;
	my $n = shift;
	my $e = shift;

	my $out = "";

	$out .= "SHAAlg = $cipher\n";
	$out .= "e = $e\n";
	$out .= "Msg = $data\n";
	$out .= "S = $signature\n";

	# XXX maybe a secure temp file name is better here
	# but since it is not run on a security sensitive
	# system, I hope that this is fine
	my $keyfile = "rsa_sigver.tmp.$$";
	gen_pubrsakey($keyfile, $n, $e);

	my $sigfile = "$keyfile.sig";
	open(FH, ">$sigfile") or die "Cannot create file $sigfile: $?";
	print FH hex2bin($signature);
	close FH;

	$out .= "Result = " . (&$rsa_verify($data, lc($cipher), $keyfile, $sigfile) ? "P\n" : "F\n");

	unlink($keyfile);
	unlink($sigfile);

	return $out;
}

# X9.31 RNG test
# $1 key for the AES cipher
# $2 DT value
# $3 V value
# $4 type ("VST", "MCT")
# return: string formatted as expected by CAVS
sub rngx931($$$$) {
	my $key=shift;
	my $dt=shift;
	my $v=shift;
	my $type=shift;

	my $out = "Key = $key\n";
	$out   .= "DT = $dt\n";
	$out   .= "V = $v\n";

	my $count = 1;
	$count = 10000 if ($type eq "MCT");

	my $rnd_val = "";

	# we read 16 bytes from RNG
	my $bufsize = 16;

	my ($CO, $CI);
	my $rng_imp = &$state_rng($key, $dt, $v);
	my $pid = open2($CO, $CI, $rng_imp);
	for (my $i = 0; $i < $count; ++$i) {
		my $len = sysread $CO, $rnd_val, $bufsize;
		#print STDERR "len=$len, bufsize=$bufsize\n";
		die "len=$len != bufsize=$bufsize" if $len ne $bufsize;
		#print STDERR "calc_data=", bin2hex($rnd_val), "\n";
	}
	close $CO;
	close $CI;
	waitpid $pid, 0;

	$out .= "R = " . bin2hex($rnd_val) . "\n\n";

	return $out;
}

##############################################################
# Parser of input file and generator of result file
#

sub usage() {

	print STDERR "Usage:
$0 [-R] [-I name] <CAVS-test vector file>

-R	execution of ARCFOUR instead of OpenSSL
-I NAME	Use interface style NAME:
		openssl     OpenSSL (default)
		libgcrypt   Libgcrypt";
}

# Parser of CAVS test vector file
# $1: Test vector file
# $2: Output file for test results
# return: nothing
sub parse($$) {
	my $infile = shift;
	my $outfile = shift;

	my $out = "";

	# Do I need to generate the key?
	my $rsa_keygen = 0;

	# this is my cipher/hash type
	my $cipher = "";

	# Test type
	# 1 - cipher known answer test
	# 2 - cipher Monte Carlo test
	# 3 - hash known answer test
	# 4 - hash Monte Carlo test
	# 5 - RSA signature generation
	# 6 - RSA signature verification
	my $tt = 0;

	# Variables for tests
	my $keytype = ""; # we can have "KEY", "KEYs", "KEY1"
	my $key1 = "";
	my $key2 = undef; #undef needed for allowing
	my $key3 = undef; #the use of them as input variables
	my $pt = "";
	my $enc = 1;
	my $iv = "";
	my $len = undef; #see key2|3
	my $n = "";
	my $e = "";
	my $signature = "";
	my $rsa_keyfile = "";
	my $dt = "";
	my $v = "";
	my $klen = "";
	my $tlen = "";

	my $mode = "";

	open(IN, "<$infile");
	while(<IN>) {

		my $line = $_;
		chomp($line);
		$line =~ s/\r//;

		my $keylen = "";

		# Mode and type check
		# consider the following parsed line
		# '# AESVS MCT test data for CBC'
		# '# TDES Multi block Message Test for CBC'
		# '# INVERSE PERMUTATION - KAT for CBC'
		# '# SUBSTITUTION TABLE - KAT for CBC'
		# '# TDES Monte Carlo (Modes) Test for CBC'
		# '#  "SHA-1 Monte" information for "IBMRHEL5"'
		# '# "SigVer PKCS#1 Ver 1.5" information for "IBMRHEL5"'
		# '# "SigGen PKCS#1 Ver 1.5" information for "IBMRHEL5"'
		# '#RC4VS MCT test data'
		
		# avoid false positives from user specified 'for "PRODUCT"' strings
		my $tmpline = $line;
		$tmpline =~ s/ for ".*"//;

		##### Extract cipher
		# XXX there may be more - to be added
		if ($tmpline =~ /^#.*(CBC|ECB|OFB|CFB|SHA-|SigGen|SigVer|RC4VS|ANSI X9\.31|Hash sizes tested)/) {
			if ($tmpline    =~ /CBC/)   { $mode="cbc"; }
			elsif ($tmpline =~ /ECB/)   { $mode="ecb"; }
			elsif ($tmpline =~ /OFB/)   { $mode="ofb"; }
			elsif ($tmpline =~ /CFB/)   { $mode="cfb"; }
			#we do not need mode as the cipher is already clear
			elsif ($tmpline =~ /SHA-1/) { $cipher="sha1"; }
			elsif ($tmpline =~ /SHA-224/) { $cipher="sha224"; }
			elsif ($tmpline =~ /SHA-256/) { $cipher="sha256"; }
			elsif ($tmpline =~ /SHA-384/) { $cipher="sha384"; }
			elsif ($tmpline =~ /SHA-512/) { $cipher="sha512"; }
			#we do not need mode as the cipher is already clear
			elsif ($tmpline =~ /RC4VS/) { $cipher="rc4"; }
			elsif ($tmpline =~ /SigGen|SigVer/) {
				die "Error: X9.31 is not supported"
					if ($tmpline =~ /X9/);
				$cipher="sha1"; #place holder - might be overwritten later
			}

			# RSA Key Generation test
			if ($tmpline =~ /SigGen/) {
				$rsa_keygen = 1;
			}
			if ($tmpline =~ /^#.*AESVS/) {
				# AES cipher (part of it)
				$cipher="aes";
			}
			if ($tmpline =~ /^#.*(TDES|KAT)/) {
				# TDES cipher (full definition)
				# the FIPS-140 test generator tool does not produce
				# machine readable output!
				if ($mode eq "cbc") { $cipher="des-ede3-cbc"; }
				if ($mode eq "ecb") { $cipher="des-ede3"; }
				if ($mode eq "ofb") { $cipher="des-ede3-ofb"; }
				if ($mode eq "cfb") { $cipher="des-ede3-cfb"; }
			}

			# check for RNG
			if ($tmpline =~ /ANSI X9\.31/) {
				# change the tmpline to add the type of the
				# test which is ONLY visible from the file
				# name :-(
				if ($infile =~ /MCT\.req/) {
					$tmpline .= " MCT";
				} elsif ($infile =~ /VST\.req/) {
					$tmpline .= " VST";
				} else {
					die "Unexpected cipher type with $infile";
				}
			}

			if ($tt == 0) {
			##### Identify the test type
				if ($tmpline =~ /KeyGen RSA \(X9.31\)/) {
					$tt =~ 10;
					die "Interface function for RSA KeyGen testing not defined for tested library"
						if (!defined($gen_rsakey));
				}
				if ($tmpline =~ /Hash sizes tested/) {
					$tt = 9;
					die "Interface function hmac for HMAC testing not defined for tested library"
						if (!defined($hmac));
				} elsif ($tmpline =~ /ANSI X9\.31/ && $tmpline =~ /MCT/) {
					$tt = 8;
					die "Interface function state_rng for RNG MCT not defined for tested library"
						if (!defined($state_rng));
				} elsif ($tmpline =~ /ANSI X9\.31/ && $tmpline =~ /VST/) {
					$tt = 7;
					die "Interface function state_rng for RNG KAT not defined for tested library"
						if (!defined($state_rng));
				} elsif ($tmpline =~ /SigVer/ ) {
					$tt = 6;
					die "Interface function rsa_verify or gen_rsakey for RSA verification not defined for tested library"
						if (!defined($rsa_verify) || !defined($gen_rsakey));
				} elsif ($tmpline =~ /SigGen/ ) {
					$tt = 5;
					die "Interface function rsa_sign or gen_rsakey for RSA sign not defined for tested library"
						if (!defined($rsa_sign) || !defined($gen_rsakey));
				} elsif ($tmpline =~ /Monte|MCT|Carlo/ && $cipher =~ /^sha/) {
					$tt = 4;
					die "Interface function hash for Hashing not defined for tested library"
						if (!defined($hash));
				} elsif ($tmpline =~ /Monte|MCT|Carlo/) {
					$tt = 2;
					die "Interface function state_cipher for Stateful Cipher operation defined for tested library"
						if (!defined($state_cipher));
				} elsif ($cipher =~ /^sha/) {
					$tt = 3;
					die "Interface function hash for Hashing not defined for tested library"
						if (!defined($hash));
				} else {
					$tt = 1;
					die "Interface function encdec for Encryption/Decryption not defined for tested library"
						if (!defined($encdec));
				}
			}
		}

		# This is needed as ARCFOUR does not operate with an IV
		$iv = "00000000000000000000000000000000" if ($cipher eq "rc4"
							     && $iv eq "" );

		# we are now looking for the string
		# '# Key Length : 256'
		# found in AES
		if ($tmpline =~ /^# Key Length.*?(128|192|256)/) {
			if ($cipher eq "aes") {
				$cipher="$cipher-$1-$mode";
			} else {
				die "Error: Key length $1 given for cipher $cipher which is unexpected";
			}
		}

		# Get the test data
		if ($line =~ /^(KEY|KEY1|Key)\s*=\s*(.*)/) { # found in ciphers and RNG
			die "KEY seen twice - input file crap" if ($key1 ne "");
			$keytype=$1;
			$key1=$2;
			$key1 =~ s/\s//g; #replace potential white spaces
		}
		elsif ($line =~ /^(KEYs)\s*=\s*(.*)/) { # found in ciphers and RNG
			die "KEY seen twice - input file crap" if ($key1 ne "");
			$keytype=$1;
			$key1=$2;
			$key1 =~ s/\s//g; #replace potential white spaces
			$key2 = $key1;
			$key3 = $key1;
		}
		elsif ($line =~ /^KEY2\s*=\s*(.*)/) { # found in TDES
			die "First key not set, but got already second key - input file crap" if ($key1 eq "");
			die "KEY2 seen twice - input file crap" if (defined($key2));
			$key2=$1;
			$key2 =~ s/\s//g; #replace potential white spaces
		}
		elsif ($line =~ /^KEY3\s*=\s*(.*)/) { # found in TDES
			die "Second key not set, but got already third key - input file crap" if ($key2 eq "");
			die "KEY3 seen twice - input file crap" if (defined($key3));
			$key3=$1;
			$key3 =~ s/\s//g; #replace potential white spaces
		}
		elsif ($line =~ /^IV\s*=\s*(.*)/) { # found in ciphers
			die "IV seen twice - input file crap" if ($iv ne "");
			$iv=$1;
			$iv =~ s/\s//g; #replace potential white spaces
		}
		elsif ($line =~ /^PLAINTEXT\s*=\s*(.*)/) { # found in ciphers
			if ( $1 !~ /\?/ ) { #only use it if there is valid hex data
				die "PLAINTEXT/CIPHERTEXT seen twice - input file crap" if ($pt ne "");
				$pt=$1;
				$pt =~ s/\s//g; #replace potential white spaces
				$enc=1;
			}
		}
		elsif ($line =~ /^CIPHERTEXT\s*=\s*(.*)/) { # found in ciphers
			if ( $1 !~ /\?/ ) { #only use it if there is valid hex data
				die "PLAINTEXT/CIPHERTEXT seen twice - input file crap" if ($pt ne "");
				$pt=$1;
				$pt =~ s/\s//g; #replace potential white spaces
				$enc=0;
			}
		}
		elsif ($line =~ /^Len\s*=\s*(.*)/) { # found in hashs
			$len=$1;
		}
		elsif ($line =~ /^(Msg|Seed)\s*=\s*(.*)/) { # found in hashs
			die "Msg/Seed seen twice - input file crap" if ($pt ne "");
			$pt=$2;
		}
		elsif ($line =~ /^\[mod\s*=\s*(.*)\]$/) { # found in RSA requests
			$out .= $line . "\n"; # print it
			# generate the private key with given bit length now
			# as we have the required key length in bit
			if ($tt == 5) {
				# XXX maybe a secure temp file name is better here
				# but since it is not run on a security sensitive
				# system, I hope that this is fine
				$rsa_keyfile = "rsa_siggen.tmp.$$";
				&$gen_rsakey($1, $rsa_keyfile);
				my $modulus = pipe_through_program("", "openssl rsa -pubout -modulus -in $rsa_keyfile");
				$modulus =~ s/Modulus=(.*?)\s(.|\s)*/$1/;
				$out .= "\nn = $modulus\n";
		                $out .= "\ne = 10001\n"
			}
		}
		elsif ($line =~ /^SHAAlg\s*=\s*(.*)/) { #found in RSA requests
			$cipher=$1;
		}
		elsif($line =~ /^n\s*=\s*(.*)/) { # found in RSA requests
			$out .= $line . "\n";
			$n=$1;
		}
		elsif ($line =~ /^e\s*=\s*(.*)/) { # found in RSA requests
			$e=$1;
		}
		elsif ($line =~ /^S\s*=\s*(.*)/) { # found in RSA requests
			die "S seen twice - input file crap" if ($signature ne "");
			$signature=$1;
		}
		elsif ($line =~ /^DT\s*=\s*(.*)/) { # X9.31 RNG requests
			die "DT seen twice - check input file"
				if ($dt ne "");
			$dt=$1;
		}
		elsif ($line =~ /^V\s*=\s*(.*)/) { # X9.31 RNG requests
			die "V seen twice - check input file"
				if ($v ne "");
			$v=$1;
		}
		elsif ($line =~ /^Klen\s*=\s*(.*)/) { # HMAC requests
			die "Klen seen twice - check input file"
				if ($klen ne "");
			$klen=$1;
		}
		elsif ($line =~ /^Tlen\s*=\s*(.*)/) { # HMAC RNG requests
			die "Tlen seen twice - check input file"
				if ($tlen ne "");
			$tlen=$1;
		}
		else {
			$out .= $line . "\n";
		}

		# call tests if all input data is there
		if ($tt == 1) {
 			if ($key1 ne "" && $pt ne "" && $cipher ne "") {
				$out .= kat($keytype, $key1, $key2, $key3, $iv, $pt, $cipher, $enc);
				$keytype = "";
				$key1 = "";
				$key2 = undef;
				$key3 = undef;
				$iv = "";
				$pt = "";
			}
		}
		elsif ($tt == 2) {
			if ($key1 ne "" && $pt ne "" && $cipher ne "") {
				$out .= crypto_mct($keytype, $key1, $key2, $key3, $iv, $pt, $cipher, $enc);
				$keytype = "";
				$key1 = "";
				$key2 = undef;
				$key3 = undef;
				$iv = "";
				$pt = "";
			}
		}
		elsif ($tt == 3) {
			if ($pt ne "" && $cipher ne "") {
				$out .= hash_kat($pt, $cipher, $len);
				$pt = "";
				$len = undef;
			}
		}
		elsif ($tt == 4) {
			if ($pt ne "" && $cipher ne "") {
				$out .= hash_mct($pt, $cipher);
				$pt = "";
			}
		}
		elsif ($tt == 5) {
			if ($pt ne "" && $cipher ne "" && $rsa_keyfile ne "") {
				$out .= rsa_siggen($pt, $cipher, $rsa_keyfile);
				$pt = "";
			}
		}
		elsif ($tt == 6) {
			if ($pt ne "" && $cipher ne "" && $signature ne "" && $n ne "" && $e ne "") {
				$out .= rsa_sigver($pt, $cipher, $signature, $n, $e);
				$pt = "";
				$signature = "";
			}
		}
		elsif ($tt == 7 ) {
			if ($key1 ne "" && $dt ne "" && $v ne "") {
				$out .= rngx931($key1, $dt, $v, "VST");
				$key1 = "";
				$dt = "";
				$v = "";
			}
		}
		elsif ($tt == 8 ) {
			if ($key1 ne "" && $dt ne "" && $v ne "") {
				$out .= rngx931($key1, $dt, $v, "MCT");
				$key1 = "";
				$dt = "";
				$v = "";
			}
		}
		elsif ($tt == 9) {
			if ($klen ne "" && $tlen ne "" && $key1 ne "" && $pt ne "") {
				$out .= hmac_kat($klen, $tlen, $key1, $pt);
				$key1 = "";
				$tlen = "";
				$klen = "";
				$pt = "";
			}
		}
		elsif ($tt > 0) {
			die "Test case $tt not defined";
		}
	}

	close IN;
	$out =~ s/\n/\r\n/g; # make it a dos file
	open(OUT, ">$outfile") or die "Cannot create output file $outfile: $?";
	print OUT $out;
	close OUT;

}

# Signalhandler
sub cleanup() {
	unlink("rsa_siggen.tmp.$$");
	unlink("rsa_sigver.tmp.$$");
	unlink("rsa_sigver.tmp.$$.sig");
	unlink("rsa_sigver.tmp.$$.der");
	unlink("rsa_sigver.tmp.$$.cnf");
	exit;
}

############################################################
#
# let us pretend to be C :-)
sub main() {

	usage() unless @ARGV;

	getopts("RI:", \%opt) or die "bad option";

	##### Set library

	if ( ! defined $opt{'I'} || $opt{'I'} eq 'openssl' ) {
		print STDERR "Using OpenSSL interface functions\n";
		$encdec =	\&openssl_encdec;
		$rsa_sign =	\&openssl_rsa_sign;
		$rsa_verify =	\&openssl_rsa_verify;
		$gen_rsakey =	\&openssl_gen_rsakey;
		$hash =		\&openssl_hash;
		$state_cipher =	\&openssl_state_cipher;
	} elsif ( $opt{'I'} eq 'libgcrypt' ) {
		print STDERR "Using libgcrypt interface functions\n";
		$encdec =	\&libgcrypt_encdec;
		$rsa_sign =	\&libgcrypt_rsa_sign;
		$rsa_verify =	\&libgcrypt_rsa_verify;
		$gen_rsakey =	\&libgcrypt_gen_rsakey;
		$hash =		\&libgcrypt_hash;
		$state_cipher =	\&libgcrypt_state_cipher;
		$state_rng =	\&libgcrypt_state_rng;
		$hmac =		\&libgcrypt_hmac;
        } else {
                die "Invalid interface option given";
        }

	my $infile=$ARGV[0];
	die "Error: Test vector file $infile not found" if (! -f $infile);

	my $outfile = $infile;
	# let us add .rsp regardless whether we could strip .req
	$outfile =~ s/\.req$//;
	if ($opt{'R'}) {
		$outfile .= ".rc4";
	} else {
		$outfile .= ".rsp";
	}
	if (-f $outfile) {
		die "Output file $outfile could not be removed: $?"
			unless unlink($outfile);
	}
	print STDERR "Performing tests from source file $infile with results stored in destination file $outfile\n";

	#Signal handler
	$SIG{HUP} = \&cleanup;
	$SIG{INT} = \&cleanup;
	$SIG{QUIT} = \&cleanup;
	$SIG{TERM} = \&cleanup;

	# Do the job
	parse($infile, $outfile);

	unlink("rsa_siggen.tmp.$$");

}

###########################################
# Call it
main();
1;
