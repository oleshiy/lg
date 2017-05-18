#!/usr/bin/perl
#

use strict qw(subs vars);

my $configfile = "lg.conf";

use XML::Parser;

my $default_ostype = "ios";

my $httpmethod = "GET";
my $timeout;
my $securemode = 1;

my %router_list;
my @routers;
my %namemap;
my %ostypes;
my %logicalsystem;
my %cmdmap;

my $default_router;

my $xml_current_router_name = "";
my $xml_current_cgi_name = "";
my $xml_current_replace_name = "";
my $xml_current_replace_proto = "";

my %valid_query = (
	"ios"		=>	{
		"ipv4"			=>	{
			"bgp"			=>	"show ip bgp %s",
			"advertised-routes"	=>	"show ip bgp neighbors %s advertised-routes",
			"summary"		=>	"show ip bgp summary",
			"ping"			=>	"ping %s",
			"trace"			=>	"traceroute %s"
			},
		"ipv6"		=>	{
			"bgp"			=>	"show bgp ipv6 %s",
			"advertised-routes"	=>	"show bgp ipv6 neighbors %s advertised-routes",
			"summary"		=>	"show bgp ipv6 summary",
			"ping"			=>	"ping ipv6 %s",
			"trace"			=>	"traceroute ipv6 %s"
			}
		},
	"zebra"		=>	{
		"ipv4"			=>	{
			"bgp"			=>	"show ip bgp %s",
			"advertised-routes"	=>	"show ip bgp neighbors %s advertised-routes",
			"summary"		=>	"show ip bgp summary",
			"ping"			=>	"ping %s",
			"trace"			=>	"traceroute %s"
			},
		"ipv6"		=>	{
			"bgp"			=>	"show bgp ipv6 %s",
			"advertised-routes"	=>	"show bgp ipv6 neighbors %s advertised-routes",
			"summary"		=>	"show bgp ipv6 summary",
			"ping"			=>	"ping ipv6 %s",
			"trace"			=>	"traceroute ipv6 %s"
			}
		},
	"junos"		=>	{
		"ipv4"			=>	{
			"trace"			=>	"traceroute %s as-number-lookup"
			},
		"ipv6"		=>	{
			"trace"			=>	"traceroute %s"
			},
		"ipv46"			=>	{
			"bgp"			=>	"show bgp %s",
			"advertised-routes"	=>	"show route advertising-protocol bgp %s %s",
			"summary"		=>	"show bgp summary",
			"ping"			=>	"ping count 5 %s"
			}
		}
);

my %whois = (
	"RIPE"		=>	"http://www.ripe.net/perl/whois?AS%s",
	"ARIN"		=>	"http://www.arin.net/cgi-bin/whois.pl?queryinput=%s",
	"APNIC"		=>	"http://www.apnic.net/apnic-bin/whois.pl?searchtext=AS%s",
	"default"	=>	"http://www.sixxs.net/tools/whois/?AS%s"
);

$| = 1;

# grab CGI data
my $incoming;
if ($ENV{'REQUEST_METHOD'} eq "POST") {
	read(STDIN, $incoming, $ENV{'CONTENT_LENGTH'});
} else {
	$incoming = $ENV{'QUERY_STRING'};
}
my %FORM = &cgi_decode($incoming);

my $date = localtime;
my $query_cmd = "";

if (defined $valid_query{$ostypes{$FORM{router}}}{"ipv46"}{$FORM{query}}) {
	$query_cmd = $valid_query{$ostypes{$FORM{router}}}{"ipv46"}{$FORM{query}};
} elsif (defined $valid_query{$ostypes{$FORM{router}}}{lc($FORM{protocol})}{$FORM{query}}) {
	$query_cmd = $valid_query{$ostypes{$FORM{router}}}{lc($FORM{protocol})}{$FORM{query}};
} elsif (($FORM{router} ne "") || ($FORM{protocol} ne "") || ($FORM{query})) {
	&print_head;
	exit;
}

if ((! defined $router_list{$FORM{router}}) ||
    ($query_cmd eq "")) {
	&print_head;
	exit;
}

$FORM{addr} =~ s/\s.*// if (($FORM{query} eq "ping") || ($FORM{query} eq "trace"));
$FORM{addr} =~ s/[^\s\d\.:\w\-_\/\$]//g;

if ($router_list{$FORM{router}} =~ /^http[s]{0,1}:/) {
	if ($router_list{$FORM{router}} =~ /\?/) {
		$incoming = "&$incoming";
	} else {
		$incoming = "?$incoming";
	}
	my $remote = $router_list{$FORM{router}};
	if (defined $cmdmap{$remote}{lc($FORM{protocol})}) {
		$incoming .= "&";
		my $mapref = $cmdmap{$remote}{lc($FORM{protocol})};
		foreach my $key (keys (%{$mapref})) {
			next if ($key eq "DEFAULT");
			(my $urlkey = $key) =~ s/([+*\/\\])/\\$1/g;
			if (${$mapref}{$key} eq "") {
				$incoming =~ s/([\?\&])($urlkey)=[^\&]*\&/$1/g;
			} elsif (${$mapref}{$key} =~ /=/) {
				$incoming =~ s/([\?\&])($urlkey)\&/"${1}${$mapref}{$2}&"/e;
			}
		}
		foreach my $key (keys (%{$mapref})) {
			next if ($key eq "DEFAULT");
			$incoming =~ s/([\?\&])($key)=/"${1}${$mapref}{$2}="/e;
		}
		$incoming =~ s|&$||g;
		if (defined ${$mapref}{DEFAULT}) {
			$incoming .= "&${$mapref}{DEFAULT}";
		}
	}
	print "Location: $router_list{$FORM{router}}${incoming}\n\n";
	exit;
}

my $command = sprintf($query_cmd, $FORM{addr});

print LOG " \"$FORM{router}\" \"$command\"\n";
close LOG;

&print_head($command);

if ($FORM{addr} !~ /^[\w\.\^\$\-\/ ]*$/) {
	if ($FORM{addr} =~ /^[\w\.\^\$\-\:\/ ]*$/) {
		if (($FORM{protocol} ne "IPv6") && ($ostypes{$FORM{router}} ne "junos")){
			&print_error("ERROR: IPv6 address for IPv4 query");
		}
	} else {
		&print_error("Illegal characters in parameter string");
	}
}

$FORM{addr} = "" if ($FORM{addr} =~ /^[ ]*$/);

if ($query_cmd =~ /%s/) {
	&print_error("Parameter missing") if ($FORM{addr} eq "");
} else {
	&print_warning("No parameter needed") if ($FORM{addr} ne "");
}

my $table;
$table = "table inet.0" if ($FORM{protocol} eq "IPv4");
$table = "table inet6.0" if ($FORM{protocol} eq "IPv6");

if ($ostypes{$FORM{router}} eq "junos") {
	if ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+)$/) {
		# show bgp n.. <IP> ---> show bgp neighbor <IP>
		$command = "show bgp neighbor $1";
	} elsif ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+) ro\w*$/) {
		# show bgp n.. <IP> ro.. ---> show route receive-protocol bgp <IP>
		$command = "show route receive-protocol bgp $1 $table";
	} elsif ($command =~ /^show bgp neighbors ([\d\.A-Fa-f:]+) routes all$/) {
		# show bgp neighbors <IP> routes all ---> show route receive-protocol bgp <IP> all
		$command = "show route receive-protocol bgp $1 all $table";
	} elsif ($command =~ /^show bgp neighbors ([\d\.A-Fa-f:]+) routes damping suppressed$/) {
		# show bgp neighbors <IP> routes damping suppressed ---> show route receive-protocol bgp <IP> damping suppressed
		$command = "show route receive-protocol bgp $1 damping suppressed $table";
	} elsif ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+) advertised-routes ([\d\.A-Fa-f:\/]+)$/) {
		# show ip bgp n.. <IP> advertised-routes <prefix> ---> show route advertising-protocol bgp <IP> <prefix> exact detail
		$command = "show route advertising-protocol bgp $1 $2 exact detail $table";
	} elsif ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+) receive-protocol ([\d\.A-Fa-f:\/]+)$/) {
		# show ip bgp n.. <IP> receive-protocol <prefix> ---> show route receive-protocol bgp <IP> <prefix> exact detail
		$command = "show route receive-protocol bgp $1 $2 exact detail $table";
	} elsif ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+) a[\w\-]*$/) {
		# show ip bgp n.. <IP> a.. ---> show route advertising-protocol bgp <IP>
		$command = "show route advertising-protocol bgp $1 $table";
	} elsif ($command =~ /^show bgp\s+([\d\.A-Fa-f:]+\/\d+)$/) {
		# show bgp <IP>/mask ---> show route protocol bgp <IP> all
		$command = "show route protocol bgp $1 terse exact all $table";
	} elsif ($command =~ /^show bgp\s+([\d\.A-Fa-f:]+)$/) {
		# show bgp <IP> ---> show route protocol bgp <IP> all
		$command = "show route protocol bgp $1 terse $table";
	} elsif ($command =~ /^show bgp\s+([\d\.A-Fa-f:\/]+) exact$/) {
		# show bgp <IP> exact ---> show route protocol bgp <IP> exact detail all
		$command = "show route protocol bgp $1 exact detail all $table";
	} elsif ($command =~ /^show bgp re\w*\s+(.*)$/) {
		# show ip bgp re <regexp> ---> show route aspath-regex <regexp> all
		my $re = $1;
		$re = ".*${re}" if ($re !~ /^\^/);
		$re = "${re}.*" if ($re !~ /\$$/);
		$re =~ s/_/ /g;
		$command = "show route protocol bgp aspath-regex \"$re\" all $table terse";
	}
}

&run_command($FORM{router}, $router_list{$FORM{router}}, $command);

exit;

sub print_head {
	my ($arg) = @_;
	print "Content-type: text/html; charset=utf-8\n\n";
}

sub print_error
{
	print join(" ", @_) . "\n";
	exit 1;
}

sub print_warning
{
	print join(" ", @_) . "\n";
}

my $regexp = 0;

sub run_command
{
	my ($hostname, $host, $command) = @_;
	my $best = 0;
	my $count = 0;
	my $telnet;
	my $ssh;
	my $ssh2;
	my @output;
	# This regexp is from RFC 2396 - URI Generic Syntax
	if ($host !~ /^(([^:\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?/) {
		die ("Illegal URI: \"$host\"");
	}
	my $scheme = $2;
	$host = $4;
	if ($host !~ /^((([^:\@\[]+)(:([^\@]+))?)\@)?([^\/?#]*)$/) {
		die ("Can't extract login/pass from host: \"$host\"");
	}
	my $login = $3;
	my $password = $5;
	$host = $6;
	my $port;
	if ($host =~ /^\[(.+)\](:([\d,]+))?$/) {
		$host = $1;
		$port = $3;
	} elsif ($host =~ /^([^:]+)(:([\d,]+))?$/) {
		$host = $1;
		$port = $3;
	} else {
		die ("Illegal host address \"$host\"");
	}

	print "<B>Router:</B> " . html_encode($hostname) . "\n";
	print "<BR>\n";
	print "<B>Command:</B> " . html_encode($command) . "\n";
	print "<P><PRE><CODE>\n";

	if (($command =~ /show route protocol bgp aspath-regex \"(.*)\"/) ||
	    ($command =~ /show ip bgp reg\w*\s+(.*)/)) {
		$regexp = $1;
	}

	if ($scheme eq "telnet") {
		my @output;
		eval "
			use Net::Telnet;
		";
		die $@ if $@;
		if ($ostypes{$FORM{router}} eq "zebra") {
			if (($command =~ /^ping /) || ($command =~ /^traceroute /)) {
				$port = $1 if ($port =~ /^(\d+),\d*$/);
				$port = 2601 if ($port eq "");
			} else {
				$port = $1 if ($port =~ /^\d*,(\d+)$/);
				$port = 2605 if ($port eq "");
			}
		}
		$port = 23 if ($port eq "");
		my $telnet = new Net::Telnet;
		$telnet->errmode( sub { print "ERROR:" . join('|', @_) . "\n"; } );
		$telnet->timeout($timeout);
		$telnet->option_callback( sub { return; } );
		$telnet->option_accept(Do => 31);		# TELOPT_NAWS
		$telnet->open(Host => $host,
		              Port => $port);

		if ($login ne "") {
			$telnet->waitfor('/(ogin|name|word):.*$/');
			$telnet->print("$login");
		}
		if ($password ne "") {
			$telnet->waitfor('/word:.*$/');
			$telnet->print("$password");
		}

		$telnet->waitfor(Match => '/.*[\$%>] {0,1}$/',
		                 Match => '/^[^#]*[\$%#>] {0,1}$/');

		$telnet->telnetmode(0);
		$telnet->put(pack("C9",
		                  255,			# TELNET_IAC
		                  250,			# TELNET_SB
		                  31, 0, 200, 0, 0,	# TELOPT_NAWS
		                  255,			# TELNET_IAC
		                  240));		# TELNET_SE
		$telnet->telnetmode(1);

		my $telnetcmd = $command;
		$telnetcmd .= " | no-more" if ($ostypes{$FORM{router}} eq "junos");

		$telnet->print("$telnetcmd");
		$telnet->getline;		# read out command line
		while (1) {
			if ($#output >= 0) {
				$_ = shift (@output);
			} elsif (! $telnet->eof) {
				my ($prematch, $match) = $telnet->waitfor(
					Match => '/\n/',
					Match => '/[\$%#>] {0,1}$/',
					Errmode => "return")
				or do {
				};
				if ($match =~ /[\$%#>] {0,1}$/) {
					$telnet->print("quit");
					$telnet->close;
					last;
				}
				push @output, $prematch . $match;
				next;
			} else {
				last;
			}
			showlines($_);
		}
	} else {
		print_error("Configuration error, no such scheme: $scheme\n");
	}
	print "</CODE></PRE>\n";
}

my $best = 0;
my $hidden = 0;
my $count = 0;
my $telnet;
my $lastip = "";
my $inemptyheader = 1;
my $linebuf = "";
my $in_func_showlines = 0;

sub showlines {
	my $input = shift;

	if ($command =~ /^trace/i | $command =~ /^ping/i) {
		if ($command =~ /^trace/i) {
			$input =~ s/(\[AS\s+)(\d+)(\])/($1 . as2link($2) . $3)/e;
		}
		print $input;
		return;
	}

	$linebuf .= $input;
	return if ($in_func_showlines);
	$in_func_showlines = 1;
	while ($linebuf =~ /\n/) {
		my $line1;
		($line1, $linebuf) = split(/\n/, $linebuf, 2);
		showline ($line1);
	}
	$in_func_showlines = 0;
}

sub showline {
	$_ = shift;
	chomp;

	next if (/Type escape sequence to abort./);
	next if (/Translating .*\.\.\.domain server/);
	next if (/Logical system: /);

	next if (($inemptyheader) && (/^$/));
	$inemptyheader = 0;

	$_ = html_encode($_);
	if ($command eq "show ip bgp summary") {
		s/( local AS number )(\d+)/($1 . as2link($2))/e;
		s/^([\d\.]+\s+\d+\s+)(\d+)/($1 . as2link($2))/e;
		s/^(\d+\.\d+\.\d+\.\d+)(\s+.*\s+)([1-9]\d*)$/($1 . $2 . bgplink($3, "neighbors+$1+routes"))/e;
		s/^(\d+\.\d+\.\d+\.\d+)(\s+)/(bgplink($1, "neighbors+$1") . $2)/e;
		# Zebra IPv6 neighbours
		s/^(.{15} 4\s+)(\d+)/($1 . as2link($2))/e;
		s/^([\dA-Fa-f]*:[\dA-Fa-f:]*)(\s+)/(bgplink($1, "neighbors+$1") . $2)/e;
		s/^([\dA-Fa-f]*:[\dA-Fa-f:]*)$/bgplink($1, "neighbors+$1")/e;
	} elsif ($command eq "show bgp ipv6 summary") {
		s/^(.{15} 4\s+)(\d+)/($1 . as2link($2))/e;
		if (/^([\dA-Fa-f]*:[\dA-Fa-f:]*)\s+4\s+/) {
			$lastip = $1;
			s/^([\dA-Fa-f:]+)(\s+.*\s+)([1-9]\d*)$/($1 . $2 . bgplink($3, "neighbors+${lastip}+routes"))/e;
			s/^([\dA-Fa-f:]+)(\s+)/(bgplink($1, "neighbors+$1") . $2)/e;
			$lastip = "";
		}
		if (/^([\dA-Fa-f:]+)$/) {
			$lastip = $1;
			s/^([\dA-Fa-f:]+)$/bgplink($1, "neighbors+$1")/e;
		}
		if (($lastip ne "") && (/^(\s+.*\s+)([1-9]\d*)$/)) {
			s/^(\s+.*\s+)([1-9]\d*)$/($1 . bgplink($2, "neighbors+${lastip}+routes"))/e;
			$lastip = "";
		}
	} elsif ($command eq "show bgp summary") {
		# JunOS
		if ($securemode) {
			next if (/\.l[23]vpn/);		# don't show MPLS
			next if (/inet6?\.2/);		# don't show multicast
			next if (/\.inet6?\.0/);	# don't show VRFs
		}
		if (/^([\dA-Fa-f:][\d\.A-Fa-f:]+)\s+/) {
			$lastip = $1;
			# IPv4
			#s/^(\d+\.\d+\.\d+\.\d+)(\s+.*\s+)([1-9]\d*)(\s+\d+\s+\d+\s+\d+\s+\d+\s+[\d:ywdh]+\s+)(\d+)\/(\d+)\/(\d+)(\s+)/($1 . $2 . bgplink($3, "neighbors+$1+routes") . $4 . bgplink($5, "neighbors+$1+routes") . "\/" . bgplink($6, "neighbors+$1+routes+all") . "\/" . bgplink($7, "neighbors+$1+routes+damping+suppressed") . $8)/e;
			s/^(\d+\.\d+\.\d+\.\d+)(\s+)([1-9]\d*)(\s+\d+\s+\d+\s+\d+\s+\d+\s+[\d:ywdh]+\s+)(\d+)\/(\d+)\/(\d+)(\s+)/($1 . $2 . bgplink($3, "neighbors+$1+routes") . $4 . bgplink($5, "neighbors+$1+routes") . "\/" . bgplink($6, "neighbors+$1+routes+all") . "\/" . bgplink($7, "neighbors+$1+routes+damping+suppressed") . $8)/e;
			# IPv4/IPv6
			s/^([\dA-Fa-f:][\d\.A-Fa-f:]+\s+)(\d+)(\s+)/($1 . as2link($2) . $3)/e;
			s/^([\dA-Fa-f:][\d\.A-Fa-f:]+)(\s+)/(bgplink($1, "neighbors+$1") . $2)/e;
		}
		if (($lastip ne "") && (/(\s+inet6?\.0: )(\d+)\/(\d+)\/(\d+)$/)) {
			s/^(\s+inet6?\.0: )(\d+)\/(\d+)\/(\d+)$/($1 . bgplink($2, "neighbors+${lastip}+routes") . "\/" . bgplink($3, "neighbors+${lastip}+routes+all") . "\/" . bgplink($4, "neighbors+${lastip}+routes+damping+suppressed"))/e;
		}
	} elsif (($command =~ /^show ip bgp\s+n\w*\s+[\d\.]+\s+(ro|re|a)/i) ||
	         ($command =~ /^show bgp ipv6\s+n\w*\s+[\dA-Fa-f:]+\s+(ro|re|a)/i) ||
	         ($command =~ /^show ip bgp\s+re/i) ||
	         ($command =~ /^show bgp ipv6\s+re/i) ||
	         ($command =~ /^show ip bgp\s+[\d\.]+\s+[\d\.]+\s+(l|s)/i) ||
	         ($command =~ /^show (ip bgp|bgp ipv6) prefix-list/i) ||
	         ($command =~ /^show (ip bgp|bgp ipv6) route-map/i)) {
		s/^([\*r ](&gt;|d|h| ).{59})([\d\s,\{\}]+)([ie\?])$/($1 . as2link($3, $regexp) . $4)/e;
		s/^([\*r ](&gt;|d|h| )[i ])([\d\.A-Fa-f:\/]+)(\s+)/($1 . bgplink($3, $3) . $4)/e;
		s/^([\*r ](&gt;|d|h| )[i ])([\d\.A-Fa-f:\/]+)$/($1 . bgplink($3, $3))/e;
		s/^(( ){20}.{41})([\d\s,\{\}]+)([ie\?])$/($1 . as2link($3, $regexp) . $4)/e;
		s/(, remote AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
	} elsif ($command =~ /^show route (?:advertising|receive)-protocol bgp [\d\.A-Fa-f:]+ [\d\.A-Fa-f:\/]+ /i) {
		s/^([ \*] )([\d\.A-Fa-f:\/]+)(\s+)/($1 . bgplink($2, $2) . $3)/e;
		s/^(     AS path: )([\d\s,\{\}\[\]]+)( [IE\?] \((?:LocalAgg)?\))$/($1 . as2link($2) . $3)/e;
		s/^(     Communities: )([\d: ]+)/($1 . community2link($2))/e;
	} elsif ($command =~ /^show route ((advertising|receive)-protocol) bgp\s+([\d\.A-Fa-f:]+)/i) {
		my $type = $1;
		my $ip = $3;
		s/^([\* ] [\d\.\s].{62})([\d\s,\{\}\[\]]+)([IE\?])$/($1 . as2link($2) . $3)/e;
		s/^([\* ] [\d\.\s].{22}\s)([\d\.A-Fa-f:]+)(\s+)/($1 . bgplink($2, "neighbors+$2") . $3)/e;
		s/^([\dA-Fa-f:\/]+)(\s+)/(bgplink($1, "$1+exact") . $2)/e;
		s/^([\d\.\/]+)(\s+)/(bgplink($1, "$1+exact") . $2)/e;
		s/^([\dA-Fa-f:\/]+)(\s*)$/(bgplink($1, "$1+exact") . $2)/e;
		s/^([\d\.\/]+)\s*$/(bgplink($1, "$1+exact"))/e;
		s/^([ \*] )([\d\.A-Fa-f:\/]+)(\s+)/($1 . bgplink($2, "neighbors+$ip+" . (($type eq "advertising-protocol")?"advertised-routes":"receive-protocol") . "+$2") . $3)/e;
	} elsif (($command =~ /^show ip bgp n\w*\s+([\d\.]+)/i) ||
	         ($command =~ /^show ip bgp n\w*$/i)) {
		$lastip = $1 if ($1 ne "");
		$lastip = $1 if (/^BGP neighbor is ([\d\.]+),/);
		if ($securemode) {
			s/((Local|Foreign) port: )\d+/${1}???/g;
		}
		s/(Prefix )(advertised)( [1-9]\d*)/($1 . bgplink($2, "neighbors+$lastip+advertised-routes") . $3)/e;
		s/(    Prefixes Total:                 )(\d+)( )/($1 . bgplink($2, "neighbors+$lastip+advertised-routes") . $3)/e;
		s/(prefixes )(received)( [1-9]\d*)/($1 . bgplink($2, "neighbors+$lastip+routes") . $3)/e;
		s/^(    Prefixes Current: \s+)(\d+)(\s+)(\d+)/($1 . bgplink($2, "neighbors+$lastip+advertised-routes") . $3 .  bgplink($4, "neighbors+$lastip+routes"))/e;
		s/(\s+)(Received)( prefixes:\s+[1-9]\d*)/($1 . bgplink($2, "neighbors+$lastip+routes") . $3)/e;
		s/^(    Saved \(soft-reconfig\):\s+)(\d+|n\/a)(\s+)(\d+)/($1 . $2 . $3 .  bgplink($4, "neighbors+$lastip+received-routes"))/e;
		s/( [1-9]\d* )(accepted)( prefixes)/($1 . bgplink($2, "neighbors+$lastip+routes") . $3)/e;
		s/^(  [1-9]\d* )(accepted|denied but saved)( prefixes consume \d+ bytes)/($1 . bgplink($2, "neighbors+$lastip+received-routes") . $3)/e;
		s/^(BGP neighbor is )(\d+\.\d+\.\d+\.\d+)(,)/($1 . pinglink($2) . $3)/e;
		s/^( Description: )(.*)$/$1<B>$2<\/B>/;
		s/(,\s+remote AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		s/(, local AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		s/( update prefix filter list is )(\S+)/($1 . bgplink($2, "prefix-list+$2"))/e;
		s/(Route map for \S+ advertisements is\s+)(\S+)/($1 . bgplink($2, "route-map+$2"))/e;
	} elsif ($command =~ /^show bgp ipv6 n\w*\s+([\dA-Fa-f:]+)/i) {
		my $ip = $1;
		if ($securemode) {
			s/((Local|Foreign) port: )\d+/${1}???/g;
		}
		s/(Prefix )(advertised)( [1-9]\d*)/($1 . bgplink($2, "neighbors+$ip+advertised-routes") . $3)/e;
		s/^(  [1-9]\d* )(accepted)( prefixes)/($1 . bgplink($2, "neighbors+$ip+routes") . $3)/e;
		s/^( Description: )(.*)$/$1<B>$2<\/B>/;
		s/(\s+remote AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		s/(\s+local AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		s/( update prefix filter list is )(\S+)/($1 . bgplink($2, "prefix-list+$2"))/e;
		s/(Route map for \S+ advertisements is\s+)(\S+)/($1 . bgplink($2, "route-map+$2"))/e;
	} elsif ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+)/i) {
		my $ip = $1;
		if ($securemode) {
			if ($hidden) {
				$hidden = 0 unless (/^    /);
				next if ($hidden);
			}
			s/^(Peer:\s+[\d\.A-Fa-f:]+\+)\d+(\s+AS\s+\d+\s+Local:\s+[\d\.A-Fa-f:]+\+)\d+(\s+AS\s+\d+)/${1}???${2}???${3}/g;
			if (/^  Table (.*\.l[23]vpn|inet6?\.2|\S+\.inet6?\.0)/) {
				s/^(  Table) \S+/$1 (hidden)/g;
				$hidden = 1;
			}
		}
		s/(\s+AS )(\d+)/($1 . as2link($2))/eg;
		s/(\s+AS: )(\d+)/($1 . as2link($2))/eg;
		s/^(    Active prefixes:\s+)(\d+)/($1 . bgplink($2, "neighbors+$ip+routes"))/e;
		s/^(    Received prefixes:\s+)(\d+)/($1 . bgplink($2, "neighbors+$ip+routes+all"))/e;
		s/^(    Suppressed due to damping:\s+)(\d+)/($1 . bgplink($2, "neighbors+$ip+routes+damping+suppressed"))/e;
		s/^(    Advertised prefixes:\s+)(\d+)/($1 . bgplink($2, "neighbors+$ip+advertised-routes"))/e;
		s/^(  )(Export)(: )/($1 . bgplink($2, "neighbors+$ip+advertised-routes") . $3)/e;
		s/^(  )(Import)(: )/($1 . bgplink($2, "neighbors+$ip+routes+all") . $3)/e;
		# JUNOS bugfix
		s/([^ ])( )(Import)(: )/($1 . "\n " . $2 . bgplink($3, "neighbors+$ip+routes+all") . $4)/e;
	} elsif ($command =~ /^show route protocol bgp .* terse/i) {
		s/^(.{20} B .{25} (?:&gt;| ).{15}[^ ]*)( [\d\s,\{\}]+)(.*)$/($1 . as2link($2, $regexp) . $3)/e;
		s/^([\* ] )([\d\.A-Fa-f:\/]+)(\s+)/($1 . bgplink($2, "$2+exact") . $3)/e;
	} elsif (($command =~ /^show route protocol bgp /i) ||
		 ($command =~ /^show route aspath-regex /i)) {
		if ($securemode) {
			s/(Task: BGP_[\d\.A-Fa-f:]+\+)\d+/${1}???/g;
		}
		if (/^        (.)BGP    /) {
			if ($1 eq "*") {
				$best = "\#FF0000";
			} else {
				$best = "";
			}
		} elsif (/^[\d\.A-Fa-f:\/\s]{19}([\*\+\- ])\[BGP\//) {
			if ($1 =~ /[\*\+]/) {
				$best = "\#FF0000";
			} elsif ($1 eq "-") {
				$best = "\#008800";
			} else {
				$best = "";
			}
		} elsif (/^$/) {
			$best = "";
		}
		s/( from )([0-9A-Fa-f][0-9\.A-Fa-f:]+)/($1 . bgplink($2, "neighbors+$2"))/e;
		s/(                Source: )([0-9\.A-Fa-f:]+)/($1 . bgplink($2, "neighbors+$2"))/e;
		s/(\s+AS: )([\d ]+)/($1 . as2link($2))/eg;
		s/(Community: )([\d: ]+)/($1 . community2link($2))/e;
		s/(Communities: )([\d: ]+)/($1 . community2link($2))/e;
		s/(^\s+AS path: )(Merged\[3\]: )?([\d ]+)/($1 . $2 . as2link($3))/e;
		s/^([\dA-Fa-f:]+[\d\.A-Fa-f:\/]+)(\s*)/("<B>" . bgplink($1, "$1+exact") . "<\/B>$2")/e;
		$_ = "<FONT COLOR=\"${best}\">$_</FONT>" if ($best ne "");
	} elsif ($command =~ /bgp/) {
		s|^(BGP routing table entry for) (\S+)|$1 <B>$2</B>|;
		s|^(Paths:\ .*)\ best\ \#(\d+)
		 |$1\ <FONT\ COLOR="\#FF0000">best\ \#$2</FONT>|x
		&& do { $best = $2; };
		# Fix for IPv6 route output where there are no addional 3 spaces before addresses
		if ((/^  Advertised to non peer-group peers:$/) &&
		    ($command =~ / ipv6 /)) {
			$count--;
		}
		if ((/^  (\d+.*)/ && ! /^  \d+\./) || (/^  Local/)) {
			$count++;
			$_ = as2link($_);
		}
		$_ = "<FONT COLOR=\"\#FF0000\">$_</FONT>" if $best && $best == $count;
		s/( from )([0-9A-Fa-f][0-9\.A-Fa-f:]+)( )/($1 . bgplink($2, "neighbors+$2") . $3)/e;
		s/(Community: )([\d: ]+)/($1 . community2link($2))/e;
		s/(Communities: )([\d: ]+)/($1 . community2link($2))/e;
		s/(^\s+AS path: )([\d ]+)/($1 . as2link($2))/e;
		if ($command =~ /-protocol/) {
			s/^([ \*] )([\d\.A-Fa-f:\/]+)(\s+)/($1 . bgplink($2, "$2+exact") . $3)/e;
		}
	}
	print "$_\n";
}

######## Portion of code is borrowed from NCSA WebMonitor "mail" code 

sub cgi_decode {
	my ($incoming) = @_;

	my %FORM;
	my $ref = "FORM";

	my @pairs = split(/&/, $incoming);

	foreach (@pairs) {
		my ($name, $value) = split(/=/, $_);

		$name  =~ tr/+/ /;
		$value =~ tr/+/ /;
		$name  =~ s/%([A-F0-9][A-F0-9])/pack("C", hex($1))/gie;
		$value =~ s/%([A-F0-9][A-F0-9])/pack("C", hex($1))/gie;

		$FORM{$name} .= $value;
	}
	return (%FORM);
}

sub html_encode {
	($_) = @_;
	s|[\r\n]||g;
	s|&|&amp;|g;
	s|<|&lt;|g;
	s|>|&gt;|g;
	return $_;
}
