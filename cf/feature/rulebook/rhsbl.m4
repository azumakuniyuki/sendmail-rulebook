divert(0)
VERSIONID(`$Id: rhsbl.m4,v 5.4 2008/03/21 19:25:35 ak Exp $')
divert(-1)
#  ____  _   _ ____  ____  _     
# |  _ \| | | / ___|| __ )| |    
# | |_) | |_| \___ \|  _ \| |    
# |  _ <|  _  |___) | |_) | |___ 
# |_| \_\_| |_|____/|____/|_____|
#                                
ifdef(`_USE_RULEBOOK_',
	`errprint(`*** ERROR: FEATURE(`rhsbl') must occur before FEATURE(`use_rulebook')
')`'m4exit(1)',
	`')dnl
define(`_RHSBL_', 1)dnl
ifdef(`_LOCAL_CHECK_RCPT_',
	`',
	define(`_LOCAL_CHECK_RCPT_',`1'))dnl
ifdef(`_LIB_RESOLV_',
	`',	
	define(`_LIB_DNS_',`1'))dnl
ifdef(`_LIB_IP4_',
	`',
	define(`_LIB_IP4_',`1'))dnl

ifelse(defn(`_ARG2_'),`',`',
lower(substr(_ARG2_,0,1)),`h',`dnl 
LOCAL_CONFIG
#############################################################################
### rhsbl configurations                                                  ###
#############################################################################
HFrom: $>rhsbl
',`')dnl  

LOCAL_RULESETS
#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       rhsbl -- Checks a hostname,sender domain by using dnszonetable  ###
###                                                                       ###
###  CATEGORY                                                             ###
###       Anti-Spam Filter                                                ###
###                                                                       ###
###  SYNOPSIS                                                             ###
###       feat.(rhsbl[,arg1[,arg2]])                                      ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Sendmail check  the client hostname and  sender domain by using ###
###       rhsbl zones which are defined in dnszonetable.db file.          ###
###                                                                       ###
###  CALLED FROM                                                          ###
###       Local_check_rcpt                                                ###
###       H Command (if 2nd argument starts with "h")                     ###
###                                                                       ###
###  M4 ARGUMENT                                                          ###
###       arg1 -- Toggle of using whitelist                               ###
###             use_wl -- Use DNS-Based Whitelist                         ###
###       arg2 -- Toggle of checking header                               ###
###             h[*]   -- Check the domain part of From: header           ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- [<]local-part@recipient.domain.part[>]                    ###
###                                                                       ###
###  RETURNS                                                              ###
###       2xx -- $@ ${lcr}                                                ###
###       2xx -- $@ OK -- (header check)                                  ###
###       4xx -- $#error(4.1.8|451)                                       ###
###       5xx -- $#error(5.1.8|550)                                       ###
###       5xx -- $#error(5.7.0|554) -- (header check)                     ###
###                                                                       ###
###  FILES                                                                ###
###       /etc/mail/lcf/dnszonetable (hash)                               ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       http://wiki.openrbl.org/wiki/Category:RHSBL                     ###
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
Srhsbl
# Check The Rulebook Database
R$*		$: $1 $| $>can rhsbl
R$* $| <ON>	$: $1
R$* $| <OFF>	$@ $&{lcr}

# Check The addr_type macro
R$*		$: $1 $| <$&{addr_type}>
R$* $| <e s>	$: <E> $1
R$* $| <e r>	$: <E> $1
R$* $| <h>	$: <H> $1

# Expand Macros(Envelope)
R<E>$*			$: <E> $>iv $&{mail_addr} 
R<E>$-			$@ $&{lcr}              # Single token is local user
R<E>$@			$@ $&{lcr}              # Null address
R<E><$@>		$@ $&{lcr}              # came from postmaster
R<E>$+			$: <E> $1 $| $>islocal $1 
R<E>$+ $| <LOCAL>	$@ $&{lcr}              # came from local site
R<E>$+ $| $+		$: <E> $1 $| $>iv $&{lcr} 
R<E>$+ $| $@		$@ $&{lcr}              # Null address
R<E>$+ $| <$@>		$@ $&{lcr}              # goes to postmaster
R<E>$+ $| $+		$: <E> $1 $| $>isabuse $2 
R<E>$+ $| <ABUSE>	$@ $&{lcr}              # goes to abuse user
R<E>$+ $| $+		$: <E> $1

# Check a client name
R<E>$+				$: <E> $1 $| CN:$&{client_name}
R<E>$+ $| CN:$@			$: <SKIP>
R<E>$+ $| CN:[ $+ ]		$: <E> $1 $| CA:$&{client_addr}
R<E>$+ $| CN:$+			$: <E> $1 $| CN:$>islocalcn $2
R<E>$+ $| CN:<LOCALNET>		$: <SKIP>	# OK Locals
R<E>$+ $| CN:$+			$: <E> $1 $| CA: $&{client_addr}

# Check a Client Address
R<E>$+ $| CA:$@			$: <SKIP>	# Client address is NULL
R<E>$+ $| CA:0			$: <SKIP>	# Bypass a 'sendmail -bs' session
R<E>$+ $| CA:$+			$: <E> $1 $| CA: $>islocalca $2
R<E>$+ $| CA:<LOCALNET>		$: <SKIP>	# Client address is local.
R<E>$+ $| CA:$+			$: <E> $1	# Client Address is Not Local.

# Canonify and get a domain name 
R<E>$+				$: <E>$1 $| MC:$>3 $1
R<E>$+ $| MC: $+ < @ $+ . >	$: $1 $| DP:$3 $(put {mfAddr} $@ $2@$3 $)
R<E>$+ $| MC: <@>		$@ $&{lcr}

# Check value(Header)   
R<H>$@				$#error $@ 5.7.0 $: "554 Header error"
R<H>$+				$: <H> $1 $| $>islocal $1
R<H>$+ $| <LOCAL>		$@ OK
R<H>$+ $| $* $&{mfAddr} $*	$@ OK	# Already Checked
R<H>$+ $| $+			$: <H> $1 $| MC:$>3 $2
R<H>$+ $| MC:$+<@ $+ .> $*	$: $1 $| DP:$3
R<H>$+ $| MC:<@>		$@ OK

ifelse(_ARG_,use_wl,`dnl
# Use DNS-Based Whitelist
# WL: select the order of RHSWL from dnszonetable db map
R$+ $| DP:$+			$: WL:$1 $| DP:$2 $| ORDER:$(dnsztab RHSWL:A $: <E> $)
RWL:$+ $| DP:$+ $| ORDER:<E>	$: $1 $| DP:$2			# WL Order is not found
RWL:$+ $| DP:$+ $| ORDER:$+ ,	WL:$1 $| DP:$2 $| ORDER:$3	# Remove Commna in line end
RWL:$+ $| DP:$+ $| ORDER:$+	$: WL:$1 $| DP:$2 $| O:<$3>

# WL: select the threshold value of RHSWL from dnszonetable db map.
RWL:$+ $| DP:$+ $| O:<$+>		$: WL:$1 $| DP: $2 $| O:<$3> $| X:$(dnsztab RHSWL:@ $: <E> $)
RWL:$+ $| DP:$+ $| O:<$+> $| X:<E>	$: WL:$1 $| DP: $2 $| X:<1>  $| O:$3
RWL:$+ $| DP:$+ $| O:<$+> $| X:$-	$: WL:$1 $| DP: $2 $| X:<$4> $| O:$3

# WL: To Check DNSWL, Call dnszCtl Ruleset defined in lib/dns.m4 
RWL:$+ $| DP:$+ $| X:<$-> $| O:$+			$: WL:$1 $| H:$2 $| X:$3 $| Q:0 $| O:$4 $| V:NULL
RWL:$+ $| H:$+ $| X:$- $| Q:$- $| O:$-,$+ $| V:$-	WL:$1 $| H:$2 $| X:$3 $| Q:$5 $| O:$6 $| V:$>dnszctl $3 $| $2 $| $5
RWL:$+ $| H:$+ $| X:$- $| Q:$- $| O:$-    $| V:$-	$: WL:$1 $| H:$2 $| Q:$5 $| V:$>dnszctl $3 $| $2 $| $5

# WL: Judge the result of dnszctl
RWL:$+ $| H:$+ $| X:$- $| Q:$- $| O:$+ $| V:<>	$: <SKIP>	# It is whitelisted.
RWL:$+ $| H:$+ $| Q:$- $| V:<>			$: <SKIP>	# It is whitelisted.
RWL:$+ $| H:$+ $| X:$- $| Q:$- $| O:$+ $| V:$-	$: $1 $| DP:$2	# It is NOT whitelisted.
RWL:$+ $| H:$+ $| Q:$- $| V:$-			$: $1 $| DP:$2	# It is NOT whitelisted.
',`')dnl

# select the order of rhsbl from dnsztable db map
R$+ $| DP:$+			$: $1 $| Dp: $2 $| ORDER:$(dnsztab rhsbl:A $: <E> $)
R$+ $| DP:$+ $| ORDER:<E>	$: <SKIP>		# The Order is not defined
R$+ $| DP:$+ $| ORDER:$+ ,	$1 $| DP:$2 $| ORDER:$3	# Remove Comma in line end.
R$+ $| DP:$+ $| ORDER:$+	$: $1 $| DP: $2 $| O:<$3>

# select the threshold value of rhsbl from dnsztab db map
R$+ $| DP:$+ $| O:<$+>		$: $1 $| DP: $2 $| O:<$3> $| X:$(dnsztab rhsbl:@ $: <E> $)
R$+ $| DP:$+ $| O:<$+> $| X:<E>	$: $1 $| DP: $2 $| X:<2>  $| O:$3
R$+ $| DP:$+ $| O:<$+> $| X:$-	$: $1 $| DP: $2 $| X:<$4> $| O:$3

# call dnszctl ruleset defined in lib/dns.m4
R$+ $| DP:$+ $| X:<$-> $| O:$+			$: $1 $| H:$2 $| X:$3 $| Q:0 $| O:$4 $| V:NULL
R$+ $| H:$+ $| X:$- $| Q:$- $| O:$-,$+ $| V:$-	$1 $| H:$2 $| X:$3 $| Q:$5 $| O:$6 $| V:$>dnszctl $3 $| $2 $| $5
R$+ $| H:$+ $| X:$- $| Q:$- $| O:$-    $| V:$-	$: $1 $| H:$2 $| Q:$5 $| V:$>dnszctl $3 $| $2 $| $5

# Judge the result of dnszctl
R$+ $| H:$+ $| X:$- $| Q:$- $| O:$+ $| V:<>	$: <NG:$4>	# Reached to the threshold
R$+ $| H:$+ $| Q:$- $| V:<>			$: <NG:$3>
R$+ $| H:$+ $| X:$- $| Q:$- $| O:$+ $| V:$-	$: <OK>
R$+ $| H:$+ $| Q:$- $| V:$-			$: <OK>

# expand the rhsbl zone name which is found in dnsztab.
R<NG:$->		$: <NG:$1> $| <$(dnsztab $1 $: E $)>
R<NG:$-> $| <E>		$: <NG>		# Zone is not found
R<NG:$-> $| <$+>	$: <NG:$2>

# Check runmode macro(LOG)
R<NG:$+>		$: <NG:$1> $| <$(math & $@ $&{runmode} $@ 2 $: 0 $)>
R<NG:$+> $| <2>		$: <NG:$1> $>locallog C:rhsbl $| $| $&{client_addr} $| $&{lcm}
R<NG:$+> $| <0>		$: <NG:$1>	# No logging

# Check runmode macro(SKIP bit)
R<NG:$+>		$: <NG:$1> $| <$(math & $@ $&{runmode} $@ 128 $: 0 $)>
R<NG:$+> $| <128>	$: <SKIP>	# Test mode.
R<NG:$+> $| <0>		$: <NG:$1>	# Not test mode.

# return or exit
R<SKIP>		$@ $&{lcm}
R<OK>		$@ $&{lcm}
R<NG:$+>	$#error $@ 5.7.0 $: 550 Sender domain listed at $1
R<NG>		$#error $@ 5.7.0 $: 550 Access Denied
R<TMPF>		$#error $@ 4.1.8 $: "451 Failed to resolve sender domain. Try again later."
R$*		$@ $&{lcm}


