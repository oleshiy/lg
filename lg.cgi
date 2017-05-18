#!/usr/bin/perl
#

use warnings;
use strict qw(subs vars);

use Net::Telnet;
use CGI;
use Data::Dumper;

$| = 1;

my $default_ostype = "junos";

my $httpmethod = "GET";
my $timeout = 15;
my $securemode = 1;

our %router_list = (
	'mbr1' => {
		'os' => 'junos',
		'protocol' => 'telnet',
		'login'=> 'login',
		'password' => 'pass',
		'host' => 'mbr1',
		'port' => ''
	}, 
	'mbr2' => {
		'os' => 'junos',
		'protocol' => 'telnet',
		'login'=> 'obondar',
		'password' => 'YOSMAT1212',
		'host' => 'mbr2',
		'port' => ''
	}
);


my $cgi=new CGI;

print $cgi->header(-charset => 'utf-8');

# TODO : clean cgi variables
my $query = $cgi->param('query');
my $protocol = $cgi->param('protocol');
my $addr = $cgi->param('addr');
my $router = $cgi->param('router');
my $os = $router_list{$router}{os};

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
			"trace"			=>	"traceroute %s"
			},
		"ipv6"		=>	{
			"trace"			=>	"traceroute %s"
			},
		"ipv46"			=>	{
			#"bgp"			=>	"show bgp %s",
			"bgp"			=>	"show route protocol bgp table inet.0 %s terse",
			"advertised-routes"	=>	"show route advertising-protocol bgp %s %s",
			"summary"		=>	"show bgp summary",
			"ping"			=>	"ping count 5 %s"
			}
		}
);

my $query_cmd = "";

if (defined $valid_query{$os}{"ipv46"}{$query}) {
	$query_cmd = $valid_query{$os}{"ipv46"}{$query};
} elsif (defined $valid_query{$os}{lc($protocol)}{$query}) {
	$query_cmd = $valid_query{$os}{lc($protocol)}{$query};
} elsif (($router ne "") || ($protocol ne "") || ($query)) {
	exit;
}

if ((! defined $router_list{$router}) ||
    ($query_cmd eq "")) 
{
	print 
	exit;
}

$addr =~ s/\s.*// if (($query eq "ping") || ($query eq "trace"));
$addr =~ s/[^\s\d\.:\w\-_\/\$]//g;

my $command = sprintf($query_cmd, $addr);

if ($addr !~ /^[\w\.\^\$\-\/ ]*$/) {
	if ($addr =~ /^[\w\.\^\$\-\:\/ ]*$/) {
		if (($protocol ne "IPv6") && ($os ne "junos")){
			&print_error("ERROR: IPv6 address for IPv4 query");
		}
	} else {
		&print_error("Illegal characters in parameter string");
	}
}

$addr = "" if ($addr =~ /^[ ]*$/);

if ($query_cmd =~ /%s/) {
	&print_error("Parameter missing") if ($addr eq "");
} else {
	&print_warning("No parameter needed") if ($addr ne "");
}

my $table;
$table = "table inet.0" if ($protocol eq "IPv4");
$table = "table inet6.0" if ($protocol eq "IPv6");

if ($os eq "junos") {
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

&run_command($router, $router_list{$router}{'host'}, $command);

exit;

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

	my $login = $router_list{$hostname}{'login'};
	my $password = $router_list{$hostname}{'password'};

	if (($command =~ /show route protocol bgp aspath-regex \"(.*)\"/) ||
	    ($command =~ /show ip bgp reg\w*\s+(.*)/)) {
		$regexp = $1;
	}

	my $port = 23;
	my @output;
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
		                255,				# TELNET_IAC
		                250,				# TELNET_SB
		                31, 0, 200, 0, 0,	# TELOPT_NAWS
		                255,				# TELNET_IAC
		                240));				# TELNET_SE
	$telnet->telnetmode(1);

	my $telnetcmd = $command;
	$telnetcmd .= " | no-more" if ($os eq "junos");

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
		print $_;
	}
}
