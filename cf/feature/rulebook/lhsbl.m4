divert(0)
VERSIONID(`$Id: lhsbl.m4,v 5.9 2008/03/21 19:25:35 ak Exp $')
divert(-1)
#  _     _   _ ____  ____  _     
# | |   | | | / ___|| __ )| |    
# | |   | |_| \___ \|  _ \| |    
# | |___|  _  |___) | |_) | |___ 
# |_____|_| |_|____/|____/|_____|
#                                
ifdef(`_USE_RULEBOOK_',
	`errprint(`*** ERROR: FEATURE(`lhsbl') must occur before FEATURE(`use_rulebook')
')`'m4exit(1)',
	`')dnl
define(`_LHSBL_', 1)dnl
ifdef(`_LOCAL_CHECK_MAIL_',
	`',
	define(`_LOCAL_CHECK_MAIL_',`1'))dnl
ifdef(`_LIB_DNS_',
	`',	
	define(`_LIB_DNS_',`1'))dnl
ifdef(`_LIB_IP4_',
	`',
	define(`_LIB_IP4_',`1'))dnl

LOCAL_CONFIG
#############################################################################
### lhsbl configurations                                                  ###
#############################################################################

LOCAL_RULESETS
#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       lhsbl -- Checks a client IP address by using dnszonetable.db    ###
###                                                                       ###
###  CATEGORY                                                             ###
###       Anti-spma Filter                                                ###
###                                                                       ###
###  SYNOPSIS                                                             ###
###       feat.(lhsbl[,arg1])                                             ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Sendmail checks the  client address by using  LHSBL zones which ###
###       are defined in dnszonetable.db file.                            ###
###                                                                       ###
###  CALLED FROM                                                          ###
###       Local_check_mail                                                ###
###                                                                       ###
###  M4 ARGUMENT                                                          ###
###       arg1 -- Toggle of using whitelist                               ###
###             use_wl -- Use DNS-Based Whitelist                         ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- [<]local-part@sender.domain.part[>]                       ###
###                                                                       ###
###  RETURNS                                                              ###
###       2xx -- $@ ${lcm}                                                ###
###       4xx -- $#error(4.1.8|451)                                       ###
###       5xx -- $#error(5.7.0|550)                                       ###
###                                                                       ###
###  FILES                                                                ###
###       /etc/mail/lcf/dnszonetable (hash)                               ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       http://wiki.openrbl.org/wiki/Category:LHSBL                     ###
###                                                                       ###
###  KNOWN BUGS                                                           ###
###       Quoted from '"Sendmail 3rd Edition" p888, 23.7.6 dns'           ###
###       " The value returned by the dns-type database map is always a   ###
###         single item. If a host has multiple MX, A, or AAAA records,   ###
###         a successful lookup  will return only  one such record.  In   ###
###         the case of MX records,  only a lowest-cost(most preferred)   ###
###         record will be returned. "                                    ###
###                                                                       ###
#############################################################################
Slhsbl
# Check the rulebook database
R$*		$: $1 $| $>can lhsbl
R$* $| <ON>	$: $1
R$* $| <OFF>	$@ $&{lcm}

# Expand macro lcm
R$*		$: $&{lcm}

# Check a client name
R<>			$@ <>		# Skip if from postmaster
R$+			$: $1 $| CN:$&{client_name}
R$+ $| CN:$@		$: <SKIP>
R$+ $| CN:[ $+ ]	$: $1 $| CA:$&{client_addr}
R$+ $| CN:$+		$: $1 $| CN:$>islocalcn $2
R$+ $| CN:<LOCALNET>	$: <SKIP>	# OK Locals
R$+ $| CN:$* $={cpHost}	$: <SKIP>	# OK Cellular phone operators
R$+ $| CN:$* $={mjHost}	$: <SKIP>	# OK Major companies
R$+ $| CN:$+		$: $1 $| CA: $&{client_addr}

# Check a Client Address
R$+ $| CA:$@		$: <SKIP>	# Client address is NULL
R$+ $| CA:0		$: <SKIP>	# Bypass a 'sendmail -bs' session
R$+ $| CA:$+		$: $1 $| CA: $>islocalca $2
R$+ $| CA:<LOCALNET>	$: <SKIP>	# Client address is local.

ifelse(_ARG_,use_wl,`dnl
# Use DNS-Based Whitelist
# WL: Select The Order of LHSWL From dnsztab db map
R$+ $| CA:$+			$: WL:$1 $| CA:$2 $| ORDER:$(dnsztab LHSWL:A $: <E> $)
RWL:$+ $| CA:$+ $| ORDER:<E>	$: $1 $| CA:$2			# WL Order is not found
RWL:$+ $| CA:$+ $| ORDER:$+ ,	WL:$1 $| CA:$2 $| ORDER:$3	# Remove Commna in line end
RWL:$+ $| CA:$+ $| ORDER:$+	$: WL:$1 $| CA:$2 $| O:<$3>

# WL: Select The Threshold value of LHSWL from dnsztab db map.
RWL:$+ $| CA:$+ $| O:<$+>		$: WL:$1 $| CA: $2 $| O:<$3> $| X:$(dnsztab LHSWL:@ $: <E> $)
RWL:$+ $| CA:$+ $| O:<$+> $| X:<E>	$: WL:$1 $| CA: $2 $| X:<1>  $| O:$3
RWL:$+ $| CA:$+ $| O:<$+> $| X:$-	$: WL:$1 $| CA: $2 $| X:<$4> $| O:$3

# WL: To check DNSWL, call dnszctl ruleset defined in lib/dns.m4 
RWL:$+ $| CA:$+ $| X:<$-> $| O:$+			$: WL:$1 $| A:$2 $| X:$3 $| Q:0 $| O:$4 $| V:NULL
RWL:$+ $| A:$+ $| X:$- $| Q:$- $| O:$-,$+ $| V:$-	WL:$1 $| A:$2 $| X:$3 $| Q:$5 $| O:$6 $| V:$>dnszctl $3 $| $2 $| $5
RWL:$+ $| A:$+ $| X:$- $| Q:$- $| O:$-    $| V:$-	$: WL:$1 $| A:$2 $| Q:$5 $| V:$>dnszctl $3 $| $2 $| $5

# WL: Judgement of The Result of dnszctl
RWL:$+ $| A:$+ $| X:$- $| Q:$- $| O:$+ $| V:<>	$: <SKIP>	# It is whitelisted.
RWL:$+ $| A:$+ $| Q:$- $| V:<>			$: <SKIP>	# It is whitelisted.
RWL:$+ $| A:$+ $| X:$- $| Q:$- $| O:$+ $| V:$-	$: $1 $| CA:$2	# It is NOT whitelisted.
RWL:$+ $| A:$+ $| Q:$- $| V:$-			$: $1 $| CA:$2	# It is NOT whitelisted.
',`')dnl

# Select The Order of LHSBL From dnszonetable db map
R$+ $| CA:$+			$: $1 $| CA: $2 $| ORDER:$(dnsztab LHSBL:A $: <E> $)
R$+ $| CA:$+ $| ORDER:<E>	$: <SKIP>		# The Order is not defined
R$+ $| CA:$+ $| ORDER:$+ ,	$1 $| CA:$2 $| ORDER:$3	# Remove Comma in line end.
R$+ $| CA:$+ $| ORDER:$+	$: $1 $| CA: $2 $| O:<$3>

# Select The Threshold value of LHSBL from dnsztab db map
R$+ $| CA:$+ $| O:<$+>		$: $1 $| CA: $2 $| O:<$3> $| X:$(dnsztab LHSBL:@ $: <E> $)
R$+ $| CA:$+ $| O:<$+> $| X:<E>	$: $1 $| CA: $2 $| X:<2>  $| O:$3
R$+ $| CA:$+ $| O:<$+> $| X:$-	$: $1 $| CA: $2 $| X:<$4> $| O:$3

# Call dnszctl Ruleset defined in lib/dns.m4
R$+ $| CA:$+ $| X:<$-> $| O:$+			$: $1 $| A:$2 $| X:$3 $| Q:0 $| O:$4 $| V:NULL
R$+ $| A:$+ $| X:$- $| Q:$- $| O:$-,$+ $| V:$-	$1 $| A:$2 $| X:$3 $| Q:$5 $| O:$6 $| V:$>dnszctl $3 $| $2 $| $5
R$+ $| A:$+ $| X:$- $| Q:$- $| O:$-    $| V:$-	$: $1 $| A:$2 $| Q:$5 $| V:$>dnszctl $3 $| $2 $| $5

# Judge the result of dnszctl
R$+ $| A:$+ $| X:$- $| Q:$- $| O:$+ $| V:<>	$: <NG:$4>	# Reached to the threshold
R$+ $| A:$+ $| Q:$- $| V:<>			$: <NG:$3>
R$+ $| A:$+ $| X:$- $| Q:$- $| O:$+ $| V:$-	$: <OK>
R$+ $| A:$+ $| Q:$- $| V:$-			$: <OK>

# Expand the LHSBL Zone name which is found in dnsztab.
R<NG:$->		$: <NG:$1> $| <$(dnsztab $1 $: E $)>
R<NG:$-> $| <E>		$: <NG>		# Zone is not found
R<NG:$-> $| <$+>	$: <NG:$2>

# Check the runmode macro(LOG)
R<NG:$+>		$: <NG:$1> $| <$(math & $@ $&{runmode} $@ 2 $: 0 $)>
R<NG:$+> $| <2>		$: <NG:$1> $>locallog C:lhsbl $| $| $&{client_addr} $| $&{lcm}
R<NG:$+> $| <0>		$: <NG:$1>	# No logging

# Check the runmode macro(SKIP bit)
R<NG:$+>		$: <NG:$1> $| <$(math & $@ $&{runmode} $@ 128 $: 0 $)>
R<NG:$+> $| <128>	$: <SKIP>	# Test mode.
R<NG:$+> $| <0>		$: <NG:$1>	# Not test mode.

# return or exit
R<SKIP>		$@ $&{lcm}
R<OK>		$@ $&{lcm}
R<NG:$+>	$#error $@ 5.7.0 $: 550 $&{client_addr} listed at $1
R<NG>		$#error $@ 5.7.0 $: 550 $&{client_addr} Access Denied
R<TMPF>		$#error $@ 4.1.8 $: "451 Failed to resolve sender domain. Try again later."
R$*		$@ $&{lcm}


