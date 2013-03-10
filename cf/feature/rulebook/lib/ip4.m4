divert(0)
VERSIONID(`$Id: ip4.m4,v 5.11 2008/04/09 06:06:12 ak Exp $')
divert(-1)
#  _ _ _       ___       _  _   
# | (_) |__   / (_)_ __ | || |  
# | | | '_ \ / /| | '_ \| || |_ 
# | | | |_) / / | | |_) |__   _|
# |_|_|_.__/_/  |_| .__/   |_|  
#                 |_|           
LOCAL_CONFIG
#############################################################################
### ip4 common configurations                                             ###
#############################################################################
# IPv4 regular expression map
Kipv4 regex -a<IPv4> ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$

LOCAL_RULESETS
#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       isIPv4 -- Checks IP address as an IPv4 address format           ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Using the IPv4 regular expression,  this ruleset checks whether ###
###       or not a given argument is an IPv4 address.                     ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1      -- Naked_IPv4_address ex) 127.0.0.1                     ###
###                                                                       ###
###  RETURNS                                                              ###
###       $1.IPv4 -- Is an IPv4 address.                                  ###
###       $1      -- Is not an IPv4 address.                              ###
###                                                                       ###
#############################################################################
SisIPv4
R$-.$-.$-.$-		$: [ $1.$2.$3.$4 ]
R$~[ $*			$@ $1$2
R$=[ $+ ]		$: $2 $| $(ipv4 $2 $: <ISNOTIPv4> $)
R$+ $| <ISNOTIPv4>	$@ $1
R$+ $| $* <IPv4>	$: $1 $| $1 . <TRUE>
R$+ $| $*.$-.<TRUE>	$1 $| $2. <$(math l $@ $3 $@ 256 $: E $)>
R$+ $| $- . <TRUE>	$: $1 $| <$(math l $@ $2 $@ 256 $: E $)>
R$+ $| <TRUE>		$@ $1.IPv4
R$+ $| $* <$->		$@ $1


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       calc -- A Calculator(extended arith map)                        ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- Numeric value                                             ###
###       $2 -- Operator { + - * / l(ell) = | & % ^ }                     ###
###       $3 -- Numeric value                                             ###
###                                                                       ###
###  RETURNS                                                              ###
###       Numeric value -- Result of calculation                          ###
###       <E>           -- Calculation error                              ###
###                                                                       ###
#############################################################################
Scalc
# Power
R$- ^ 0		$@ 1
R$- ^ 1		$@ $1
R$- ^ 2		$@ $>calc $1 * $1
R$- ^ $-	$: FALSE $1:$(math - $@ $2 $@ 2 $:<E> $):$>calc $1 * $1
RFALSE $-:$-:$-	$(math l $@ $2 $@ 2 $:<E> $) $1:$(math - $@ $2 $@ 1 $:<E> $):$>calc $3 * $1
RTRUE $-:$-:$-	$@ $3

# Normal
R$- $- $-	$@ $(math $2 $@ $1 $@ $3 $: <E> $)
R$* <E> $*	$@ <E>


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       isIANA -- An IPv4 address is assigned by IANA ?                 ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Checks a client IPv4 address. If it is in the range of the pri- ###
###       vate network(10/8,127/8,172.16/12,192.168/16),  or in the other ###
###       assigned network, this ruleset returns *.IANA:* string.         ###
###                                                                       ###
###  IANA RESERVED NETWORK                                                ###
###       0/8             returns $1.IANA:THISNET                         ###
###       10/8            returns $1.IANA:PRIVATENET                      ###
###       100.64/10       returns $1.IANA:RFC6598                         ###
###       127.0.0.1       returns $1.IANA:LOOPBACK                        ###
###       127/8           returns $1.IANA:PRIVATENET                      ###
###       128.0/16        returns $1.IANA:RESERVED                        ###
###       169.254/16      returns $1.IANA:LINKLOCAL                       ###
###       172.16/12       returns $1.IANA:PRIVATENET                      ###
###       191.255/16      returns $1.IANA:RESERVED                        ###
###       192.0.2/24      returns $1.IANA:TESTNET1                        ###
###       192.88.99/24    returns $1.IANA:6TO4                            ###
###       192.168/16      returns $1.IANA:PRIVATENET                      ###
###       198.18/15       returns $1.IANA:BENCHMARK                       ###
###       223.255.255/24  returns $1.IANA:RESERVED                        ###
###       224/4           returns $1.IANA:MULTICAST                       ###
###       240/4           returns $1.IANA:RESERVED                        ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- IPaddress                                                 ###
###                                                                       ###
###  RETURNS                                                              ###
###       $1                  -- Isn't a IANA assigned IPv4 address       ###
###       $1.IANA:description -- Is a IANA assigned IPv4 address          ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       RFC1700 -- ASSIGNED NUMBERS                                     ###
###       RFC1797 -- Class A Subnet Experiment                            ###
###       RFC1918 -- Address Allocation for Private Internets             ###
###       RFC2544 -- Benchmarking Methodology for Network Interconnect... ###
###       RFC3171 -- IANA Guidelines for IPv4 Multicast Address Assign... ###
###       RFC3330 -- Special-Use IPv4 Addresses                           ###
###                                                                       ###
#############################################################################
### http://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.txt
SisIANA
R$+			$: $1 $| $1
R$+ $| 0  .$-.$-.$-	$@ $1.IANA:THISNET	# RFC1700 This network 0/8
R$+ $| 10 .$-.$-.$-	$@ $1.IANA:PRIVATENET	# RFC1918 10/8

R$+ $| 100.$-.$-.$-		$: $1 $| <P1> 100.$2.$3.$4 . $(math l $@ $2 $@ 64 $: <E> $)
R$+ $| <P1>100.$-.$-.$-. FALSE	$: $1 $| <P2> 100.$2.$3.$4 . $(math l $@ $2 $@ 127 $: <E> $)
R$+ $| <P2>100.$-.$-.$-. TRUE	$@ $1.IANA:RFC6598	# RFC6598 100.64/10
R$+ $| <$->100.$-.$-.$-. <E>	$@ $1

R$+ $| 127.0  .0 .1	$@ $1.IANA:LOOPBACK	# RFC1700 Loopback 127/8
R$+ $| 127.$- .$-.$-	$@ $1.IANA:PRIVATENET	# RFC1700 Loopback 127/8
R$+ $| 128.0  .$-.$-	$@ $1.IANA:RESERVED	# IANA Reserved 128.0/16
R$+ $| 169.254.$-.$-	$@ $1.IANA:LINKLOCAL	# IANA Link Local

# Private net(172.16.0.0/12)
R$+ $| 172.$- .$-.$-		$: $1 $| <P1> 172.$2.$3.$4 . $(math l $@ $2 $@ 16 $: <E> $)
R$+ $| <P1>172.$-.$-.$-. FALSE	$: $1 $| <P2> 172.$2.$3.$4 . $(math l $@ $2 $@ 32 $: <E> $)
R$+ $| <P2>172.$-.$-.$-. TRUE	$@ $1.IANA:PRIVATENET	# RFC1918 172.16/12
R$+ $| <$->172.$-.$-.$-. <E>	$@ $1

R$+ $| 191.255.$- .$-	$@ $1.IANA:RESERVED	# IANA Reserved 191.255/16
R$+ $| 192.0  .2  .$-	$@ $1.IANA:TESTNET1	# IANA Test Net 192.0.2/24
R$+ $| 192.88 .99 .$-	$@ $1.IANA:6TO4		# IANA 6to4 relay anycast 192.88.99/24
R$+ $| 192.168.$- .$-	$@ $1.IANA:PRIVATENET	# RFC1918 192.168/16
R$+ $| 198.18 .$- .$-	$@ $1.IANA:BENCHMARK	# RFC2544 198.18/15
R$+ $| 198.19 .$- .$-	$@ $1.IANA:BENCHMARK	# RFC2544 198.18/15
R$+ $| 198.51 .100.$-	$@ $1.IANA:TESTNET2	# RFC5737 198.51.100/24
R$+ $| 203.0. 113 .$-	$@ $1.IANA:TESTNET3	# RFC5737 203.0.113.0/24
R$+ $| 223.255.255.$-	$@ $1.IANA:RESERVED	# IANA Reserved 223.255.255/24
R$+ $| $-.$-.$-.$-	$: $1 $| <M1> $2.$3.$4.$5.$(math l $@ $2 $@ 224 $: <E> $)

# Multicast|Class-E
R$+ $| <M1>$-.$-.$-.$-.FALSE 	$: $1 $| <M2> $2.$3.$4.$5.$(math l $@ $2 $@ 240 $: <E> $)
R$+ $| <M1>$-.$-.$-.$-.TRUE 	$@ $1
R$+ $| <M2>$-.$-.$-.$-.FALSE 	$: $1 $| <E1> $2.$3.$4.$5.$(math l $@ $2 $@ 256 $: <E> $)
R$+ $| <M2>$-.$-.$-.$-.TRUE 	$@ $1.IANA:MULRTCAST	# RFC3171 Multicast 224/4
R$+ $| <E1>$-.$-.$-.$-.FALSE 	$@ $1			# 256/8 ... :-(
R$+ $| <E1>$-.$-.$-.$-.TRUE 	$@ $1.IANA:CLASS-E	# RFC1700 Class-E 240/4
R$+ $| $+			$@ $1


