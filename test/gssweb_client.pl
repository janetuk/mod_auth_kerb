#!/usr/bin/perl -w

use strict;
use WWW::Mechanize;
use GSSAPI;
use GSSAPI::OID;
use MIME::Base64;
use JSON;
use URI::Encode qw(uri_encode);

sub parse_token($) {
    my ($json) = @_;
    my $ref = decode_json($json);
    return $ref->{'gssweb'}{'token'};
		}


sub token_body($$) {
    my ($target_server, $itoken) = @_;
    my $status;
    my $otoken;
    my $target;
  try: {
     $status = GSSAPI::Name->import( $target,
				       $target_server,
				     GSSAPI::OID::gss_nt_hostbased_service) or last;
     our  $ctx = GSSAPI::Context->new() unless $ctx;
     my $mech;
     $status = GSSAPI::OID->from_str($mech, '{ 1.3.6.1.5.5.15.1.1.17              }') or last;
     my $iflags = GSSAPI::GSS_C_MUTUAL_FLAG | GSSAPI::GSS_C_SEQUENCE_FLAG | GSSAPI::GSS_C_REPLAY_FLAG;
     my $bindings = GSS_C_NO_CHANNEL_BINDINGS;
     my $creds = GSS_C_NO_CREDENTIAL;
     my $itime = 0;

             $status = $ctx->init($creds,$target,
                                  $mech,$iflags,$itime,$bindings,$itoken,
                                  undef, $otoken,undef,undef);
    }
    print "$status\n";
    return undef unless $otoken;
    print "Pre-encoding token: $otoken\n";
    my $encoded_token = encode_base64($otoken);
    chomp($encoded_token);
    my $out =  "token=" . uri_encode($encoded_token, {encode_reserved => 1}) ."&nonce=42";
    print "$out\n";
    return $out;
}

my ($url, $gssname) = @ARGV;
my $www = WWW::Mechanize->new('autocheck' => 0);
my $done = 0;
my $response_token = undef;
   while (!$done) {

    $www->post($url, 'Content' => token_body($gssname, $response_token));
    my $status = $www->status();
    if ($status == 200) {
	$done = 1;
	print "authenticated: response is ".$www->content()."\n";
	if (token_body($gssname, parse_token($www->content()))) {
	    print "Expecting gss success but did not get it!\n";
	}
    } elsif ($status == 401) {
	print "Continuing\n";
	$response_token = parse_token($www->content());
    } else {
	print "Unexpected response status: $status\n";
	print $www->content();
	      $done = 1;
    }
}
