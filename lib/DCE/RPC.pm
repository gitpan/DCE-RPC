# -*- perl -*-
# RPC.pm - An implementation of a DCE RPC Composer/Parser. It is expected
# to cover all the connection oriented PDUs. 
# implemented the client side functions that calculates the NTLM response.
# I will add the corresponding server side functions in the next version.
#

package DCE::RPC;

use strict;
use Carp;
use Socket;
use Authen::Perl::NTLM;
use UNIVERSAL qw(isa);
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require DynaLoader;

*import = \&Exporter::import;

@ISA = qw (Exporter DynaLoader);
@EXPORT = qw ();
@EXPORT_OK = qw (parse_co_hdr);
$VERSION = '0.10';

# Stolen from Crypt::DES.
sub usage {
    my ($package, $filename, $line, $subr) = caller (1);
    $Carp::CarpLevel = 2;
    croak "Usage: $subr (@_)";
}

# DCE RPC PDU Types
use constant RPC_REQUEST            => 0x00;
use constant RPC_PING               => 0x01;
use constant RPC_RESPONSE           => 0x02;
use constant RPC_FAULT              => 0x03;
use constant RPC_WORKING            => 0x04; 
use constant RPC_NOCALL             => 0x05;
use constant RPC_REJECT             => 0x06;
use constant RPC_ACK                => 0x07;
use constant RPC_CL_CANCEL          => 0x08;
use constant RPC_FACK               => 0x09;
use constant RPC_CANCEL_ACK         => 0x0a;
use constant RPC_BIND               => 0x0b; 
use constant RPC_BIND_ACK           => 0x0c;
use constant RPC_BIND_NACK          => 0x0d;
use constant RPC_ALTER_CONTEXT      => 0x0e;
use constant RPC_ALTER_CONTEXT_RESP => 0x0f;
use constant RPC_BIND_RESP          => 0x10;
use constant RPC_SHUTDOWN           => 0x11; 
use constant RPC_CO_CANCEL          => 0x12;

# DCE RPC PFC Flags
# First Fragment
use constant PFC_FIRST_FRAG => 0x01;
# Last Fragment
use constant PFC_LAST_FRAG => 0x02;
# Cancel was pending at sender
use constant PFC_PENDING_CANCEL => 0x04;
# Reserved
use constant PFC_RESERVED_1 => 0x08;
# supports concurrent multiplexing of a single connection
use constant PFC_CONC_MPX => 0x10;
# only meaningful on 'fault' packet; if true, guaranteed call
# did not execute
use constant PFC_DID_NOT_EXECUTE => 0x20;
# 'maybe' call semantics requested
use constant PFC_MAYBE => 0x40;
# if true, a non-nul object UUID was specified in the handle,
# and is present in the optional object field. If false, the 
# object field is omitted.
use constant PFC_OBJECT_UUID => 0x80;

use constant RPC_MAJOR_VERSION => 5;
use constant RPC_MINOR_VERSION => 0;

# Connection Oriented PDU common header size
use constant RPC_CO_HDR_SZ => 16;

use constant RPC_CO_RESP_HDR_SZ => 8;
# Fragment Size
use constant RPC_FRAG_SZ => 5840;

use constant RPC_AUTH_HDR_SZ => 8;

use constant RPC_AUTH_NTLM => 0x0a;
use constant RPC_AUTH_LEVEL_CONNECT => 0x02;

#########################################################################
# Constructor to initialize authentication related information. In this #
# version, we assume NTLM as the authentication scheme of choice.       #
# The constructor only takes the class name as an argument.             #
#########################################################################
sub new_client {
    usage("new_client DCE::RPC, \$host, \$port, \$auth") unless @_ == 4;
    my ($package, $host, $port, $auth) = @_;
    my $auth_type;
    if (isa($auth, 'Authen::Perl::NTLM') and $auth->VERSION(0.05)) {
	$auth_type = RPC_AUTH_NTLM;
    }
    else {
	usage ref($auth), " is not supported.\n" .
	      "The currently supported Authentication classes are:\n" .
	      "Authen::Perl::NTLM 0.10 or above.\n";
    }
    my $proto = getprotobyname('tcp');
    socket(S, AF_INET, SOCK_STREAM, $proto) or usage "Socket: $!\n";
    my $addr = inet_aton($host) or usage "Server inet_aton $!\n";
    my $that = sockaddr_in($port, $addr); 
    connect(S, $that) or usage "Connect: $!\n";
    srand time;
    my $ctx_id = pack("V", rand(2**16) + rand(2**32));
    bless {
	'sock' => *S,
	'auth_type' => $auth_type,
	'auth_level' => RPC_AUTH_LEVEL_CONNECT,
	'auth_ctx_id' => $ctx_id,
	'auth_value' => $auth,
	  }, $package;
}

##############################
# Destructor to close socket #
##############################
sub DESTROY {
    my $self = shift;
    close($self->{'sock'});
}

########################################################################
# new is a constructor that is stripped off the socket part of the     #
# DCE::RPC package. It is not recommended to use. It is mostly written #
# for the test program that comes with this module.                    #
########################################################################
sub new {
    usage("new DCE::RPC, \$auth") unless @_ == 2;
    my ($package, $auth) = @_;
    my $auth_type;
    if (isa($auth, 'Authen::Perl::NTLM') and $auth->VERSION(0.10)) {
	$auth_type = RPC_AUTH_NTLM;
    }
    else {
	usage ref($auth), " is not supported.\n" .
	      "The currently supported Authentication classes are:\n" .
	      "Authen::Perl::NTLM 0.10 or above.\n";
    }
    srand time;
    my $ctx_id = pack("V", rand(2**16)+rand(2**32));
    bless {
	'auth_type' => $auth_type,
	'auth_level' => RPC_AUTH_LEVEL_CONNECT,
	'auth_ctx_id' => $ctx_id,
	'auth_value' => $auth,
	  }, $package;
}

########################################################################
# rpc_request_response takes a client to server RPC PDU and return the #
# reply from the server. If the resulting reply is longer than one     #
# PDU, it will continue to read from socket and concatenate all the    #
# fragments.                                                           #
######################################################################## 
sub rpc_request_response
{
    my ($self, $query) = @_;
    my $reply_size; # DCE RPC Packet Size
    my $flags; # DCE RPC Packet Flags 
    my $type; # DCE RPC Packet Type
    my $pkt;
    my $bytes_read;
    my $buf;
    my $body = "";
    my $auth_size;
    my $sock = $self->{'sock'};

    syswrite($sock, $query, length($query));
    do {
	$bytes_read = 0;
	undef $flags;
	undef $reply_size;
	undef $type;
	undef $pkt;
	undef $auth_size;	
	do {
	    $bytes_read += sysread($sock, $buf, RPC_CO_HDR_SZ-$bytes_read);
	    $pkt .= $buf;
        }
	while ($bytes_read != RPC_CO_HDR_SZ);  # not yet finished reading header
	    if (!defined($flags) or !defined($reply_size)) {
		($type, $flags, $reply_size, $auth_size) =  parse_co_hdr($pkt);
	    }
	while ($bytes_read != $reply_size) {
	    $bytes_read += sysread($sock, $buf, $reply_size-$bytes_read);
	    $pkt .= $buf;

	    usage "Reply Size $reply_size < Bytes Read $bytes_read.\nPlease report this bug to module maintainer." if ($bytes_read > $reply_size); 
        }
	if ($type == RPC_RESPONSE) {
	    if ($auth_size > 0) {
		$body .= substr($pkt, RPC_CO_HDR_SZ+RPC_CO_RESP_HDR_SZ, - $auth_size - RPC_AUTH_HDR_SZ);
	    }
	    else {
		$body .= substr($pkt, RPC_CO_HDR_SZ+RPC_CO_RESP_HDR_SZ);
	    }    
	}
	elsif ($type == RPC_FAULT or $type == RPC_BIND_ACK or $type == RPC_BIND_NACK or $type == RPC_SHUTDOWN) {
	    $body .= $pkt;
	}
	elsif ($type == RPC_ALTER_CONTEXT_RESP) {
	    $body .= $pkt;
	    $flags = PFC_FIRST_FRAG | PFC_LAST_FRAG; # *** Strangely, alt_ctx_resp's fragmentation flag is always 0x00, so we have to force it to be 0x03. 
	}
	else {
	    usage "Unknown Packet type $type! Please contact the module maintainer.\n";
	}
    }
    while (($flags & PFC_LAST_FRAG) == 0);
    return $body;
}

#############################################################################
# rpc_bind_ack_resp is used to complete the bind, bind_ack, bind_resp       #
# sequence in the beginning of an RPC session. It takes the bind arguments: #
# 1) Context Id; 2) Abstract Syntax; 3) Abstract Syntax version; and        #
# 4) a list of transfer syntax.                                             #
#############################################################################
sub rpc_bind_ack_resp
{
    my $self = shift;
    my $ctx_id = shift;
    my $abs_syntax = shift;
    my $abs_syntax_ver = shift;
    my @xfer_syntax = shift;
    my $pkt = $self->rpc_request_response($self->rpc_bind($ctx_id, $abs_syntax, $abs_syntax_ver, @xfer_syntax));
    my ($type, $flags, $reply_size, $auth_size) = parse_co_hdr($pkt);
    my $auth_value = substr($pkt, $reply_size - $auth_size);
    my @fields = $self->{'auth_value'}->parse_challenge($auth_value);
    my $query = $self->rpc_bind_resp($fields[2]);
    syswrite($self->{'sock'}, $query, length($query));
}

sub StrToHexReadable
{
    my ($str) = @_;
    my $newstr;
    $newstr = unpack("H*", $str);
    $newstr =~ s/(....)/$1 . " "/ge;
    return $newstr;
}

############################################################################
# rpc_co_hdr composes the 16-bytes common DCE RPC header that must present #
# in all conection oriented DCE RPC messages. It takes four arguments:     #
# 1) PDU type; 2) PDU flags; 3) size of the PDU part that is specific to   #
# the PDU type; 4) size of the authentication credentials.                 #
# This function is an internal function. It is not supposed to be called   #
# from the outside world.                                                  #
############################################################################
sub rpc_co_hdr($$$$)
{
    my ($type, $flags, $size, $auth_size) = @_;
    my $msg = chr(RPC_MAJOR_VERSION) . chr(RPC_MINOR_VERSION);
    $msg .= chr($type);
    $msg .= chr($flags);
    $msg .= pack("H8", "10000000"); # assume little endian
    $msg .= pack("v", RPC_CO_HDR_SZ+$size+$auth_size);
    $msg .= pack("v", $auth_size);
    $msg .= pack("V", 0x00); # always 0 for call_id for now
    return $msg;
}

#################################################################
# parse_co_hdr parses the first 16-bytes of a string and return #
# the values represented in a Connection Oriented RPC header.   #
#################################################################
sub parse_co_hdr
{
    my ($msg) = @_;
    my $flags = ord(substr($msg, 3, 1));
    my $type = ord(substr($msg, 2, 1));
    my $pkt_size = unpack("v", substr($msg, 8, 2));
    my $auth_size = unpack("v", substr($msg, 10, 2));
    return ($type, $flags, $pkt_size, $auth_size);
}

############################################################################
# rpc_auth_hdr composes the 8-bytes authentication header. It takes four   #
# arguments: 1) Authentication Type; 2) Authentication Level; 3) length of #
# padding; 4) context id of this session.                                  #
############################################################################
sub rpc_auth_hdr($$$$)
{
    my ($auth_type, $auth_level, $pad_len, $ctx_id) = @_;
    my $msg = chr($auth_type);
    $msg .= chr($auth_level);
    $msg .= chr($pad_len);
    $msg .= chr(0);
    $msg .= $ctx_id;
    return $msg;
}

#####################################################################
# rpc_bind composes the DCE RPC bind PDU. To make things simple, it #
# assumes the PDU context list only has one element. It takes four  #
# arguments: 1) Presentation Context Id; 2) Abstract Syntax         #
# concatenated with interface version; 3) list of transfer syntax   #
# concatenated with interface version; 4) authentication            # 
# credentials.                                                      #
#####################################################################
sub rpc_bind($$$$@)
{
    my $self = shift;
    my $ctx_id = shift;
    my $abs_syntax = shift;
    my $abs_syntax_ver = shift;
    my @xfer_syntax = shift;
    my $flags = 
	  $self->{'auth_value'}->NTLMSSP_NEGOTIATE_80000000
	| $self->{'auth_value'}->NTLMSSP_NEGOTIATE_128
	| $self->{'auth_value'}->NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	| $self->{'auth_value'}->NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
	| $self->{'auth_value'}->NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
	| $self->{'auth_value'}->NTLMSSP_NEGOTIATE_NTLM
	| $self->{'auth_value'}->NTLMSSP_NEGOTIATE_UNICODE
	| $self->{'auth_value'}->NTLMSSP_NEGOTIATE_OEM
	| $self->{'auth_value'}->NTLMSSP_REQUEST_TARGET;
    my $auth_value = $self->{'auth_value'}->negotiate_msg($flags);
    my $msg = "";
    my $auth_pad = 0;
    my $i; 
    my $bind_msg = pack("v", RPC_FRAG_SZ) . pack("v", RPC_FRAG_SZ);
    $bind_msg .= pack("V", 0); # ask for new association group id
    $bind_msg .= chr(1) . chr(0) . pack("v", 0);
    $bind_msg .= pack("v", $ctx_id); # ctx id 
    $bind_msg .= chr(@xfer_syntax);
    $bind_msg .= chr(0);
    $bind_msg .= $abs_syntax;
    $bind_msg .= pack("V", $abs_syntax_ver);
    for ($i = 0; $i < @xfer_syntax; ++$i) {
	$bind_msg .= $xfer_syntax[$i]->{'interface'};
	$bind_msg .= pack("V", $xfer_syntax[$i]->{'version'});
    }
    while (length($bind_msg) % 4 != 0) {
	$bind_msg .= chr(0);
	$auth_pad++;
    }
    $bind_msg .= rpc_auth_hdr($self->{'auth_type'}, $self->{'auth_level'}, $auth_pad, $self->{'auth_ctx_id'});
    $msg = rpc_co_hdr(RPC_BIND, PFC_FIRST_FRAG | PFC_LAST_FRAG,
	length($bind_msg), length($auth_value)) . $bind_msg . $auth_value;
    return $msg;
}

##############################################################################
# rpc_bind_resp composes the DCE RPC bind_resp PDU. This PDU is undocumented #
# in the OpenGroup's specification but it is used by DCOM. It's main         #
# responsibility is to respond to the NTLM challenge posted by the bind_ack  #
# PDU from the server. Its lone argument is the NTLM response.               #
##############################################################################
sub rpc_bind_resp($$)
{
    my $self = shift;
    my $nonce = shift;
    my $flags = 
	  $self->{'auth_value'}->NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	| $self->{'auth_value'}->NTLMSSP_NEGOTIATE_NTLM
	| $self->{'auth_value'}->NTLMSSP_NEGOTIATE_UNICODE
	| $self->{'auth_value'}->NTLMSSP_REQUEST_TARGET;
    my $auth_value = $self->{'auth_value'}->auth_msg($nonce, $flags);
    my $msg = "";
    my $auth_pad = 0;
    my $i; 
    my $bind_resp_msg = pack("v", RPC_FRAG_SZ) . pack("v", RPC_FRAG_SZ);
    while (length($bind_resp_msg) % 4 != 0) {
	$bind_resp_msg .= chr(0);
	$auth_pad++;
    }
    $bind_resp_msg .= rpc_auth_hdr($self->{'auth_type'}, $self->{'auth_level'}, $auth_pad, $self->{'auth_ctx_id'});
    $msg = rpc_co_hdr(RPC_BIND_RESP, PFC_FIRST_FRAG | PFC_LAST_FRAG,
	length($bind_resp_msg), length($auth_value)) . $bind_resp_msg . $auth_value;
    return $msg;
}

###########################################################################
# rpc_co_request composes the connection-oriented DCE RPC Request PDU. It #
# takes five arguments: 1) the stub; 2) the presentation context id;      #
# 3) operation # within the interface; 4) object UUID; 5) authetication   #
# credentials. The fourth argument can be "" if there is no UUID          #
# associate with this request PDU.                                        #
########################################################################### 
sub rpc_co_request($$$$$$)
{
    my ($self, $body, $ctx_id, $op_num, $uuid, $auth_value) = @_; 
    my $msg = "";
    my $auth_pad = 0;
    my $i;
    my $flags = PFC_FIRST_FRAG | PFC_LAST_FRAG; 
    my $req_msg = pack("V", length($body));
    $req_msg .= pack("v", $ctx_id);
    $req_msg .= pack("v", $op_num);
    if (defined($uuid) and length($uuid) == 16) {
	$flags |= PFC_OBJECT_UUID;
	$req_msg .= $uuid;
    }
    $req_msg .= $body;
    while (length($req_msg) % 4 != 0) {
	$req_msg .= chr(0);
	$auth_pad++;
    }
    $req_msg .= rpc_auth_hdr($self->{'auth_type'}, $self->{'auth_level'}, $auth_pad, $self->{'auth_ctx_id'});
    $msg = rpc_co_hdr(RPC_REQUEST, $flags,
	length($req_msg), length($auth_value)) . $req_msg . $auth_value;
    return $msg;
}

##########################################################################
# rpc_alt_ctx composes a DCE RPC alter_context PDU. alter_context PDU is #
# used to change the presentation syntax established by the earlier bind #
# PDU. Therefore it has similar format. However, there is no need for    #
# authentication credentials. Like rpc_bind, we also assume the          #
# presentation context list only has one element.                        #
##########################################################################
sub rpc_alt_ctx($$$$@)
{
    my $self = shift;
    my $ctx_id = shift;
    my $abs_syntax = shift;
    my $abs_syntax_ver = shift;
    usage("Abstract Syntax must be 16-bytes long!") unless length($abs_syntax) == 16;
    my @xfer_syntax = shift;
    my $msg = "";
    my $i; 
    my $alt_ctx_msg = pack("v", RPC_FRAG_SZ) . pack("v", RPC_FRAG_SZ);
    $alt_ctx_msg .= pack("V", 0); # ask for new association group id
    $alt_ctx_msg .= chr(1) . chr(0) . pack("v", 0);
    $alt_ctx_msg .= pack("v", $ctx_id); # ctx id 
    $alt_ctx_msg .= chr(@xfer_syntax);
    $alt_ctx_msg .= chr(0);
    $alt_ctx_msg .= $abs_syntax;
    $alt_ctx_msg .= pack("V", $abs_syntax_ver);
    for ($i = 0; $i < @xfer_syntax; ++$i) {
	$alt_ctx_msg .= $xfer_syntax[$i]->{'interface'};
	$alt_ctx_msg .= pack("V", $xfer_syntax[$i]->{'version'});
    }
    $msg = rpc_co_hdr(RPC_ALTER_CONTEXT, PFC_FIRST_FRAG | PFC_LAST_FRAG,
	length($alt_ctx_msg), 0) . $alt_ctx_msg;
    return $msg;
}

1;

__END__

=head1 NAME

DCE::RPC - Perl extension for DCE RPC protocol composer/parser

=head1 SYNOPSIS

use DCE::RPC;
use Authen::Perl::NTLM qw(lm_hash nt_hash);

use constant DCOM_IREMOTEACTIVATION => pack("H32", "B84A9F4D1C7DCF11861E0020AF6E7C57");

use constant DCOM_IF_VERSION => 0x00;

use constant DCOM_XFER_SYNTAX => pack("H32", "045D888AEB1CC9119FE808002B104860");

use constant DCOM_XFER_SYNTAX_VERSION => 0x02;

    $passwd = "passwd";
    $lm_hpw = lm_hash($passwd);
    $nt_hpw = nt_hash($passwd);
    $ntlm = new_client Authen::Perl::NTLM($lm_hpw, nt_hpw);
    $rpc_host = "www.rpc.com";
    $rpc_port = 135;
    $rpc = new DCE::RPC($rpc_host, $rpc_port, $ntlm);
    $bind_msg = $rpc->rpc_bind_ack_resp(1, DCOM_IREMOTEACTIVATION, DCOM_IF_VERSION,
	({'interface' => DCOM_XFER_SYNTAX, 'version' => DCOM_XFER_SYNTAX_VERSION}));
    $request_msg = $rpc->rpc_co_request("Hi, there! This is Stub!", 1, 0x0e, DCOM_IREMOTEACTIVATION, "Authentication Credentials");
    $response_msg = $rpc->rpc_request_response($request_msg);
    $alt_ctx_msg = $rpc->rpc_alt_ctx(1, DCOM_IREMOTEACTIVATION . DCOM_IF_VERSION
,
	({'interface' => DCOM_XFER_SYNTAX, 'version' => DCOM_XFER_SYNTAX_VERSION}));

=head1 DESCRIPTION

The DCE RPC protocol is an application level protocol from OpenGroup
that allows applications to do Remote Procedure Calls. It is the 
underlying wire protocol for DCOM (Distributed Common Object Model)
by Microsoft. 
 
This module was motivated by an reverse-engineering effort on a DCOM
client. Therefore, functions that are implemented gear more toward
client side implementation. Also, the initial version only supports
Connection Oriented version of DCE RPC. It also assumes NTLMSSP as 
the underlying authentication protocol. This can change based on the
input of the users of this modules.

=head1 DEPENDENCIES

In general, it depends on the authentication module. Since we only 
support NTLM, you have to install it first to use it. Currently,
it requires Authen-Perl-NTLM-0.10.

=head1 ASSUMPTIONS

1) The version of DCE RPC Connection Oriented protocol supported is 5.0.

2) NTLM is the only supported authentication scheme.

3) AUTH_LEVEL_CONNECT is the authentication level of choice.

4) Network Data Representation (NDR) is assumed to be ASCII for characters,
little endian for integers and IEEE for floating points.

5) Call Id is always zero. It seems to me my client works regardless of
the value of call id.

=head1 TO-DO

1) Support fragmented CO Requests.

2) Implement Connection Oriented server side functions. 

3) Implement Connection-less functions. 

4) Implement the module in C.

=head1 BUGS

Nothing known. 

=head1 AUTHOR

This implementation was written by Yee Man Chan (ymc@yahoo.com).
Copyright (c) 2002 Yee Man Chan. All rights reserved. This program 
is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself. 

=head1 SEE ALSO

Authen::Perl::NTLM(3), perl(1), m4(1).

=cut

Local Variables:
mode: perl
perl-indent-level: 4
perl-continued-statement-offset: 4
perl-continued-brace-offset: 0
perl-brace-offset: -4
perl-brace-imaginary-offset: 0
perl-label-offset: -4
tab-width: 4
End:                                                                            
