divert(0)
VERSIONID(`$Id: countryroads.m4,v 5.7 2008/03/21 23:26:36 ak Exp $')
divert(-1)
#                        _                                  _     
#   ___ ___  _   _ _ __ | |_ _ __ _   _ _ __ ___   __ _  __| |___ 
#  / __/ _ \| | | | '_ \| __| '__| | | | '__/ _ \ / _` |/ _` / __|
# | (_| (_) | |_| | | | | |_| |  | |_| | | | (_) | (_| | (_| \__ \
#  \___\___/ \__,_|_| |_|\__|_|   \__, |_|  \___/ \__,_|\__,_|___/
#                                 |___/                           
ifdef(`_USE_RULEBOOK_',
	`errprint(`*** ERROR: FEATURE(`countryroads') must occur before FEATURE(`use_rulebook')
')`'m4exit(1)',
	`')dnl

ifelse(defn(`_ARG_'),`',
	`errprint(`*** ERROR: FEATURE(`countryroads') requires argument')
	`'m4exit(1)',
	`')dnl
ifelse(_ARG_,tarpit,
	`ifdef(`_GREET_PAUSE_',`',
		`errprint(`*** ERROR: FEATURE(`countryroads') requires greet_pause')
		')`'m4exit(1)'
	`ifdef(`_ARG2_',
		`define(`_COUNTRYROADS_TARPIT_',`_ARG2_')',
		`define(`_COUNTRYROADS_TARPIT_',`30000')')'
	`ifdef(`_LOCAL_GREET_PAUSE_',
		`',
		define(`_LOCAL_GREET_PAUSE_',`1'))
',
	`define(`_COUNTRYROADS_', _ARG_)')
	ifdef(`_LOCAL_CHECK_RCPT_',
		`',
		define(`_LOCAL_CHECK_RCPT_',`1'))
')dnl
ifdef(`_LIB_DNS_',
	`',
	define(`_LIB_DNS_',`1'))dnl
ifdef(`_LIB_IP4_',
	`',
	define(`_LIB_IP4_',`1'))dnl
define(`_DEFAULT_POLICY_',`_ARG_')

LOCAL_CONFIG
#############################################################################
### countryroads Configurations                                           ###
#############################################################################
Kcctab hash -o MAPDIR/cctable
D{a2code}??
HX-Country: ${a2code}

LOCAL_RULESETS
#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       countryRoads -- Control Connections by using IP GeoLocation     ###
###                                                                       ###
###  CATEGORY                                                             ###
###       Connection Filter                                               ###
###                                                                       ###
###  SYNOPSIS                                                             ###
###       feat.(countryroads,arg1[,arg2])                                 ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       countryroads control connections by using IP GeoLocation,  and  ###
###       country name  ( ISO-3166 Country Code, A2 Code ) of a client IP ###
###       address. This filter use dnszonetable(dnsztab) & cctable(cctab).###
###                                                                       ###
###  CALLED FROM                                                          ###
###       Local_greet_pause                                               ###
###       Local_check_rcpt                                                ###
###                                                                       ###
###  M4 ARGUMENTS                                                         ###
###       arg1 -- default policy                                          ###
###             accept  -- Receive a message if no record in the db map   ###
###             reject  -- Reject messages except countries in the db     ###
###             discard -- Discard messages except countries in the db    ###
###             tarpit  -- Greet pause for 30 or specified seconds.       ###
###                                                                       ###
###       arg2 -- The number of milli-seconds for slamming.               ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1  -- [<]local-part@recipient.domain.part[>]                   ###
###                                                                       ###
###  RETURNS                                                              ###
###       2xx -- $@ ${lcr} -- call from Local_check_rcpt                  ###
###       2xx -- $@ ${lgp} -- call from Local_greet_pause                 ###
###       4xx --                                                          ###
###       5xx -- $#error(5.3.2|554) reject                                ###
###       5xx -- $#error(5.3.2|550) discard                               ###
###                                                                       ###
###  FILES                                                                ###
###       /etc/mail/lcf/cctable (hash)                                    ###
###       /etc/mail/lcf/dnszonetable (hash)                               ###
###                                                                       ###
#############################################################################
Scountryroads
# Check the rulebook database
R$*		$: $1 $| $>can countryroads
R$* $| <ON>	$: $1
ifelse(_ARG_,tarpit,`dnl
R$* $| <OFF>	$@ $&{lgp}
',`dnl
R$* $| <OFF>	$@ $&{lcr}
')dnl

ifelse(_ARG_,tarpit,`dnl
# Expand macro lgp
R$*		$: $&{lgp}
',`dnl

# Check a recipient and a sender address
R$*		$: A: $>isabuse $1
RA: <ABUSE>	$: <SKIP>	# rcpt to: abuse
RA: $*		$: B: $>iv $&{lcm}
RB: $-		$: <SKIP>	# mail from: <single token>
RB: $@		$: <SKIP>	# mail from: null
RB: <$@>	$: <SKIP>	# mail from: <>
RB: $*		$: $&{client_name} $| $&{client_addr}
')dnl

# Check a client address
R$+ $| $+		$: <> $1 $| $2
R<> $+ $| $+		$: <> $1 $| $>islocalca $2
R<> $+ $| <LOCALNET>	$: <SKIP>
R<> $+ $| $+		$: <> $2 $| $>islocalcn $1
R<> $+ $| <LOCALNET>	$: <SKIP>
R<> $+ $| $+		$: <@> $2 $| $1 <@>
R<> $@ $| $@		$: <SKIP>	# null
R<> $@ $| $*		$: <SKIP>	# null
R<> $* $| $@		$: <SKIP>	# null

# Is client IP address IANA?
R<@> $+ $| $+ <@>		$: $1 $| $2 $| $>isIANA $2
R$+ $| $+ $| $+ . IANA:$-	$: <SKIP>	# IANA
R$+ $| $+ $| $+			$: <@> $1 $| $2 <@>

# Lookup the client IP address from cctable database.
R<@> $+ $| $+ <@>	$: $1 $| $2 $| IP:$2
R$+ $| $+ $| IP:$* $-	$1 $| $2 $| $(cctab $3$4 $: IP:$3 $)
R$+ $| $+ $| OK		$: <OK>
R$+ $| $+ $| REJECT	$: <NG:RJ:IPADDR>
R$+ $| $+ $| DISCARD	$: <NG:DI:IPADDR>
R$+ $| $+ $| IP:$@	$: $1 $| $2 $| HN:$1

# Lookup a client hostname from the cctable database.
R$+ $| $+ $| HN:$- $*	$1 $| $2 $| $(cctab $3$4 $: HN:$4 $)
R$+ $| $+ $| OK		$: <OK>
R$+ $| $+ $| REJECT	$: <NG:RJ:HOSTNAME>
R$+ $| $+ $| DISCARD	$: <NG:DI:HOSTNAME>
R$+ $| $+ $| HN:$@	$: <> $1 $| $2 <>

# Lookup the order of IP GeoLocation from dnszonetable
R<> $+ $| $+ <>		$: $1 $| $2 $| O: $(dnsztab LHSGL:TXT $: <@> $)
R$+ $| $+ $| O: <@>	$: <SKIP>	# The Order is not defined.

# Use 2 zones only.
R$+ $| $+ $| O: $-		$: $1 $| $2 $| C:$3,0
R$+ $| $+ $| O: $-,$- $*	$: $1 $| $2 $| C:$3,$4

# Reverse client IP address
R$+ $| $-.$-.$-.$- $| C:$+	$: $1 $| R:$5.$4.$3.$2 $| C:$6

# 1.Select ISO-3166 Country Code from the zone by using the order.
R$+ $| R:$+ $| C:$-,$-			$: $1 $| R:$2 $| C:$4 $| Z:$(dnsztab $3 $: <E> $)
R$+ $| R:$+ $| C:$- $| Z:<E>		$: $1 $| R:$2 $| Z:$(dnsztab $3 $: <E> $)
R$+ $| R:$+ $| C:$- $| Z:$+		$: $1 $| R:$2 $| C:$3 $| CC:$>hasTXTRR $2.$4
R$+ $| R:$+ $| C:$- $| CC:$-.TXTRR	$: $1 $| R:$2 $| A2:<$4>
R$+ $| R:$+ $| C:$- $| CC:<TMPERR>	$: $1 $| R:$2 $| Z:$(dnsztab $3 $: <E> $)
R$+ $| R:$+ $| C:$- $| CC:<NOTXTRR>	$: $1 $| R:$2 $| Z:$(dnsztab $3 $: <E> $)
R$+ $| R:$+ $| C:$- $| CC:$+		$: $1 $| R:$2 $| Z:$(dnsztab $3 $: <E> $)

# 2.Select ISO-3166 Country Code From the zone by using the order, Again.
R$+ $| R:$+ $| Z:<E>		$: <SKIP>	# The Zone is not defined.
R$+ $| R:$+ $| Z:$+		$: $1 $| R:$2 $| CC:$>hasTXTRR $2.$3
R$+ $| R:$+ $| CC:$-.TXTRR	$: $1 $| R:$2 $| A2:<$3> $(put {a2code} $3 $)
R$+ $| R:$+ $| CC:<TMPERR>	$: <TMPF>	# Temporary lookup failure
R$+ $| R:$+ $| CC:<NOTXTRR>	$: <SKIP>	# Country name not found
R$+ $| R:$+ $| CC:$+		$: <SKIP>	# Other TXT RR

# Lookup A2 Code(ISO-3166 Country Code) From cctable database.
R$+ $| R:$+ $| A2:<$->			$: $1 $| R:$2 $| CC: $3 $| AC:$(cctab A2:$3 $: <E> $)
R$+ $| R:$+ $| CC:$- $| AC:OK		$: <OK>		# Allowed country.
R$+ $| R:$+ $| CC:$- $| AC:REJECT	$: <NG:RJ:$3>	# Disallowed country.
R$+ $| R:$+ $| CC:$- $| AC:DISCARD	$: <NG:DI:$3>	# Disallowed country(Discard).
R$+ $| R:$+ $| CC:$- $| AC:<E>		$: <DP:$3>	# Decide by default policy

# Check the default policy
R<DP:$->		$: <DP:$1> _DEFAULT_POLICY_
R<DP:$-> ACCEPT		$: <OK>
R<DP:$-> ALLOW		$: <OK>
R<DP:$-> OK		$: <OK>
R<DP:$-> REJECT		$: <NG:RJ:$1>
R<DP:$-> REFUSE		$: <NG:RJ:$1>
R<DP:$-> DENY		$: <NG:RJ:$1>
R<DP:$-> NG		$: <NG:RJ:$1>
R<DP:$-> DISCARD	$: <NG:DI:$1>
R<DP:$-> TARPIT		$: <OK>
R<DP:$-> $*		$: <OK>

# Check the runmode macro(LOG)
R<NG:$-:$->		$: <NG:$1:$2> <$(math & $@ $&{runmode} $@ 2 $: 0 $)>
R<NG:$-:$-> <2>		$: <NG:$1> $>locallog C:countryroads $| $&{client_name} $| $&{client_addr} $| $2
R<NG:$-:$-> <0>		$: <NG:$1>	# No logging.

ifdef(`_USE_SCOREBOOK_',`dnl
# Check runmode macro(SCORE)
R<NG:$->		$: <NG:$1> $| S:<$(math & $@ $&{runmode} $@ 8 $: 0 $)>
R<NG:$-> $| S:<8>	$: <SKIP> $>scoreCtl countryroads
R<NG:$-> $| S:<0>	$: <NG:$1>	# is not score mode.
',`')dnl

# Check runmode macro(SKIP bit)
R<NG:$->		$: <NG:$1> $| T:<$(math & $@ $&{runmode} $@ 128 $: 0 $)>
R<NG:$-> $| T: <128>	$: <SKIP>	# Test mode.
R<NG:$-> $| T: <0>	$: <NG:$1>	# Not test mode.

# Return or exit
ifelse(_ARG_,tarpit,`dnl
R<OK>			$@ $&{lgp}
R<SKIP>			$@ $&{lgp}
R<NG:$->		$# _COUNTRYROADS_TARPIT_
R<TMPF>			$@ $&{lgp}
R$*			$@ $&{lgp}
',`dnl
R<OK>			$@ $&{lcr}
R<SKIP>			$@ $&{lcr}
R<NG:RJ>		$#error $@ 5.3.2 $: 554 Client address $&{client_addr} is denied.
R<NG:DI>		$#discard $@ 5.3.2 $: 550 Client address $&{client_addr} is denied.
R$*			$@ $&{lcr}
')dnl


