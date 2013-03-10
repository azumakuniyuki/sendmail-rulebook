divert(0)
VERSIONID(`$Id: rulebook.m4,v 5.41 2008/04/09 04:33:23 ak Exp $')
divert(-1)
#  _ _ _       __          _      _                 _    
# | (_) |__   / / __ _   _| | ___| |__   ___   ___ | | __
# | | | '_ \ / / '__| | | | |/ _ \ '_ \ / _ \ / _ \| |/ /
# | | | |_) / /| |  | |_| | |  __/ |_) | (_) | (_) |   < 
# |_|_|_.__/_/ |_|   \__,_|_|\___|_.__/ \___/ \___/|_|\_\
#                                                        
dnl syscmd(`test -r 'MAPDIR`/rulebook')dnl
dnl ifelse(sysval,0,
dnl	`',
dnl	`errprint(`*** ERROR: CAN NOT READ 'MAPDIR`/rulebook
dnl ')`'m4exit(1)')

LOCAL_CONFIG
#############################################################################
### Core library of Sendmail-Rulebook ver.5.15                            ###
#############################################################################
# Macros, class macros
D{runmode}0
C{abuseUser} root postmaster abuse
F{lsAddr}  -o MAPDIR/local-site-addrs
F{lsHost}  -o MAPDIR/local-site-names

# Database maps
Krulebook hash -o MAPDIR/rulebook
Kstorage macro
Kmath arith
Kput macro
Klog syslog -D

LOCAL_RULESETS
#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       iv -- Similar to Sfinal=4                                       ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- <envelope.user@any.domain>                                ###
###       $1 -- envelope.user<@any.domain.>                               ###
###                                                                       ###
###  RETURNS                                                              ###
###       2xx -- envelope.user@any.domain                                 ###
###                                                                       ###
#############################################################################
Siv
R$-		$@ $1		# Includes no domain
R$* <@$+ .> $*	< $1 @ $2 > $3	# Strip
R$* <$+ > $*	$2		# Defocus

#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       can -- Reads the rulebook.db                                    ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Checks the rulebook.db database whether or not a ruleset can be ###
###       execute.                                                        ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- filter_name                                               ###
###                                                                       ###
###  RETURNS                                                              ###
###       <ON>  -- Specified feature is executable.                       ###
###       <OFF> -- Specified feature is not executable.                   ###
###                                                                       ###
###  FILES                                                                ###
###       /etc/mail/lcf/rulebook.db (hash)                                ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       /etc/mail/lcf/RULEBOOK.README                                   ###
###                                                                       ###
#############################################################################
Scan
# 1. Initialize
R$+		$: 1i: $1 $(put {runmode} $@ 0 $)
ifelse(_RULEBOOK_FINERCTRL_,1,`dnl
R1i:$+	$: 2a: $1

# *** FINER CONTROL IS ENABLED ***
# 2. Search a client IP address or network
R2a:$+			$: 2a: $1 $| $&{client_addr}
R2a:$+ $| $@		$: 3h: $1
R2a:$+ $| $+ $-		2a: $1 $| $(rulebook $1:$2$3 $: $2 $)
R2a:$+ $| ON		$@ <ON> $(put {runmode} $@ 1 $)
R2a:$+ $| OFF		$@ <OFF>
R2a:$+ $| LOG		$@ <ON> $(put {runmode} $@ 3 $)
R2a:$+ $| TEST		$@ <ON> $(put {runmode} $@ 135 $)
R2a:$+ $| SCORE		$@ <ON> $(put {runmode} $@ 139 $)
R2a:$+ $| $-		$: 3h: $1

# 3. Search a client host name or domain
R3h:$+			$: 3h: $1 $| $&{client_name}
R3h:$+ $| $@		$: 4m: $1
R3h:$+ $| $=[$*		$: 4m: $1
R3h:$+ $| $- $+		3h: $1 $| $(rulebook $1:$2$3 $: $3 $)
R3h:$+ $| ON		$@ <ON> $(put {runmode} $@ 1 $)
R3h:$+ $| OFF		$@ <OFF>
R3h:$+ $| LOG		$@ <ON> $(put {runmode} $@ 3 $)
R3h:$+ $| TEST		$@ <ON> $(put {runmode} $@ 135 $)
R3h:$+ $| SCORE		$@ <ON> $(put {runmode} $@ 139 $)
R3H:$+ $| $-		$: 4m: $1

# 4. Search a domain name which is picked from a sender address.
R4m:$+			$: 4m: $1 $| $&{mail_addr}
R4m:$+ $| $@		$: 9x: $1
R4m:$+ $| $+@$+		$: 4m: $1 $| $(rulebook $1:@$3 $: FEAT. $)
R4m:$+ $| FEAT.		$: 9x: $1
R4m:$+ $| LOG		$: <ON> $(put {runmode} $@ 3 $)
R4m:$+ $| TEST		$: <ON> $(put {runmode} $@ 135 $)
R4m:$+ $| SCORE		$: <ON> $(put {runmode} $@ 139 $)
R4m:$+ $| $-		$: <$2>
',`dnl
R1i:$+				$: 9x: $1

# 2-8. Skip rules to check following macros,
#      client_name, client_addr, domain name of sender address
#      *** FINER CONTROL IS DISABLED ***
')dnl

# 9. Search a feature name
R9x: $+			$: 9x: $1 $| $(rulebook $1 $: DEFAULT $)
R9x: $+ $| DEFAULT	$: <ON>
R9x: $+ $| ON		$: <ON> $(put {runmode} $@ 1 $)
R9x: $+ $| LOG		$: <ON> $(put {runmode} $@ 3 $)
R9x: $+ $| TEST		$: <ON> $(put {runmode} $@ 135 $)
R9x: $+ $| SCORE	$: <ON> $(put {runmode} $@ 139 $)
R9x: $+ $| $-		$: <$2>

# 10. Return
R<ON>	$@ <ON>		# Status is ON
R<OFF>	$@ <OFF>	# Status is OFF
R<<?>>	$@ <ON>		# Default is ON
R<$*>	$@ <OFF>	# Other value is OFF
R$*	$@ <OFF>	# Other value is OFF


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       islocal -- Is a mail address local ?                            ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Checks a recipient, a sender address, and a hostname with class ###
###       macro w, {VirtHost}, {lsHost}.                                  ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- [<]envelope.user@sender.domain[>]                         ###
###       $1 -- envelope.user<@sender.domain.>                            ###
###       $1 -- <envelope.user@sender.domain> username                    ###
###                                                                       ###
###  RETURNS                                                              ###
###       $1      -- Is not a local mail address                          ###
###       <LOCAL> -- Is a local mail address                              ###
###                                                                       ###
###  FILES                                                                ###
###       /etc/mail/lcf/local-site-names (class macro lsHost)             ###
###       /etc/mail/local-host-names (class macro w)                      ###
###       /etc/mail/virtuser-domains (class macro VirtHost)               ###
###                                                                       ###
#############################################################################
Sislocal
# Canonify address format
R$-		$@ <LOCAL>
R<>		$@ <LOCAL>
R$+		$: $1 $| $1
R$+ $| $+	$: $1 $| <> $>iv $2
R$+ $| <> $-	$@ <LOCAL>
R$+ $| <> $+	$: $1 $| $>canonify $2

# Check an address with classes
R$+ $| $+ <@ $=w . > $*			$@ <LOCAL>
R$+ $| $+ <@ $+ . $=w . > $*		$@ <LOCAL>
R$+ $| $+ <@ $={VirtHost} . > $*	$@ <LOCAL>
R$+ $| $+ <@ $+. $={VirtHost} .> $*	$@ <LOCAL>
R$+ $| $+ <@ $={lsHost} .> $*		$@ <LOCAL>
R$+ $| $+ <@ $+ $={lsHost} .> $*	$@ <LOCAL>

# Return or exit
R$+ $| $*	$@ $1
R$+ $| <@>	$@ <LOCAL>


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       islocalcn -- Check whether or not a hostname is local.          ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Checks a client hostname by class macros w,{VirtHost},{lsHost}  ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- hostname                                                  ###
###                                                                       ###
###  RETURNS                                                              ###
###       $1         -- Is not a local host name                          ###
###       <LOCALNET> -- Is a local host name                              ###
###                                                                       ###
###  FILES                                                                ###
###       /etc/mail/lcf/local-site-names (class macro lsHost)             ###
###       /etc/mail/local-host-names (class macro w)                      ###
###       /etc/mail/virtuser-domains (class macro VirtHost)               ###
###                                                                       ###
#############################################################################
Sislocalcn
R$+			$: $1 $| $1
R$+ $| $=[ $+ ]		$: $1 $| $>islocalca $3
R$+ $| localhost	$@ <LOCALNET>	# localhost
R$+ $| $w.$m		$@ <LOCALNET>	# fqdn
R$+ $| $j		$@ <LOCALNET>	# fqdn
R$+ $| $+ . $m		$@ <LOCALNET>	# same domain name
R$+ $| $* $=w		$@ <LOCALNET>	# local-host-names
R$+ $| $* $={VirtHost}	$@ <LOCALNET>	# virtuser-domains
R$+ $| $* $={lsHost}	$@ <LOCALNET>	# local-site-names
R$+ $| <LOCALNET>	$@ <LOCALNET>	# return of islocalca
R$+ $| $+		$@ $1
R$*			$@ $1


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       islocalca -- Check whether or not an IP address is local.       ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Checks a client IP address by class macros R, w, {lsAddr}.      ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- A IPaddress                                               ###
###                                                                       ###
###  RETURNS                                                              ###
###       $1         -- Is not a local ip address                         ###
###       <LOCALNET> -- Is a local ip address                             ###
###                                                                       ###
###  FILES                                                                ###
###       /etc/mail/local-host-names                                      ###
###       /etc/mail/lcf/local-site-addrs                                  ###
###                                                                       ###
#############################################################################
Sislocalca
R$+			$: $1 $| <> $1
R$+ $| <> 0		$@ <LOCALNET>	# Bypass a 'sendmail -bs' session
R$+ $| <> 127.0.0.1	$@ <LOCALNET>	# IPv4 loopback
R$+ $| <> IPv6:::1	$@ <LOCALNET>	# IPv6 loopback
R$+ $| <> [ $=w ]	$@ <LOCALNET>	# local-host-names
R$+ $| <> $=R $*	$@ <LOCALNET>	# relay-domains
R$+ $| <> $={lsAddr} $*	$@ <LOCALNET>	# local-site-addrs
R$+ $| <> $+		$@ $1
R$*			$@ $1


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       isabuse -- Checks abuse address                                 ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Checks a recipient, a sender address, and a hostname with class ###
###       macros w, {abuseUser}. If it matches, returns string <ABUSE>    ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- [<]envelope.user@recipient.domain[>]                      ###
###                                                                       ###
###  RETURNS                                                              ###
###       $1      -- is not a mail address for abuse                      ###
###       <ABUSE> -- is a mail address for abuse                          ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       RFC2142 -- MAILBOX NAMES FOR COMMON SERVICES, ROLES AND FUNC... ###
###                                                                       ###
#############################################################################
Sisabuse
R<@>		$@ <ABUSE>	# no address
R$+		$: $1 $| $1
R$+ $| $+	$: $1 $| <> $>iv $2
R$+ $| <> $+	$: $1 $| $>canonify $2
R$+ $| <> $@	$@ $1

# check address
R$+ $| $={abuseUser}				$@ <ABUSE>
R$+ $| $={abuseUser} <@ $=w .> $*		$@ <ABUSE>
R$+ $| $={abuseUser} <@ $={VirtHost} .> $*	$@ <ABUSE>
R$+ $| <@>					$@ <ABUSE>
R$+ $| $*					$@ $1


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       locallog -- Write custom log                                    ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Write checked records to the MTA log file /var/log/maillog with ###
###       custom log format.                                              ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       A:$1 $| $2 $| $3 $| $4                                          ###
###             $1 -- filter_name                                         ###
###             $2 -- env.from.addr@sender.domain                         ###
###             $3 -- env.to.addr@rcpt.domain                             ###
###             $4 -- other information                                   ###
###                                                                       ###
###       C:$1 $| $2 $| $3 $| $4                                          ###
###             $1 -- filter_name                                         ###
###             $2 -- client host name or macro s                         ###
###             $3 -- client address                                      ###
###             $4 -- other information                                   ###
###                                                                       ###
###       H:$1 $| $2 $| $3                                                ###
###             $1 -- filter_name                                         ###
###             $2 -- header contents                                     ###
###             $3 -- other information                                   ###
###                                                                       ###
###  RETURNS                                                              ###
###       null token                                                      ###
###                                                                       ###
#############################################################################
Slocallog
# Check an address as the log format
RA:$@ $| $* $| $* $| $*		$@
RA:$+ $| $@ $| $@ $| $*		$@
RA:$+ $| $@ $| $+ $| $*		$: A:$1 $| %% $| $2 $| $3
RA:$+ $| $+ $| $@ $| $*		$: A:$1 $| $2 $| %% $| $3
RA:$+ $| $+ $| $+ $| $*		$: A:$1 $| I:($4) $| S:$2 $| R:$>iv $3
RA:$+ $| I:$+ $| S:$+ $| R:$+	$: A:$1 $| I:$2 $| R:$4 $| S:$>iv $3
RA:$+ $| I:$+ $| R:$+ $| S:$+	$: A:$1 $| S:$4 $| R:$3 $| I:$2
RA:$+ $| S:%% $| R:%% $| I:$+	$@
RA:$+ $| S:%% $| R:$+ $| I:$+	$: X:$1 $| L:$2 <+> $3
RA:$+ $| S:$+ $| R:%% $| I:$+	$: X:$1 $| L:$2 <+> $3
RA:$+ $| S:$+ $| R:$+ $| I:$+	$: X:$1 $| L:$2 <@> $3 <+> $4

# Check a client as the log format
RC:$@ $| $* $| $* $| $*		$@
RC:$+ $| $@ $| $@ $| $*		$@
RC:$+ $| $@ $| $+ $| $*		$: C:$1 $| %% $| $2 $| $3
RC:$+ $| $+ $| $@ $| $*		$: C:$1 $| $2 $| %% $| $3
RC:$+ $| $+ $| $+ $| $*		$: C:$1 $| N:$2 $| A:$3 $| I:($4)
RC:$+ $| N:%% $| A:%% $| I:$+	$@
RC:$+ $| N:%% $| A:$+ $| I:$+	$: X:$1 $| L:$2 <+> $3
RC:$+ $| N:$+ $| A:%% $| I:$+	$: X:$1 $| L:$2 <+> $3
RC:$+ $| N:[$+] $| A:$+ $| I:$+	$: X:$1 $| L:$3 <+> $4
RC:$+ $| N:$+ $| A:$+ $| I:$+	$: X:$1 $| L:$2 <-> $3 <+> $4

# Check a header content as the log format
RH:$@ $| $* $| $*		$@
RH:$+ $| $@ $| $*		$: H:$1 $| <> $| $2
RH:$+ $| $+ $| $*		$: H:$1 $| V:$2 $| I:($3)
RH:$+ $| V:$+ $| I:$+		$: X:$1 $| L:$2 <+> $3

# Check log format
RX:$+ $| L:$+ <+> ($@)		$: Y:$1 $| L:$2
RX:$+ $| L:$+ <+> ($+)		$: Y:$1 $| L:$2($3)

# Logging
RY:$+ $| L:$+			$: Y:$1 $| L:$2 $| <$(math & $@ $&{runmode} $@ 128 $: 0 $)>
RY:$+ $| L:$+ $| <128>		$@ $(log ---CHECK--->$1:$2 $)
RY:$+ $| L:$+ $| <$*>		$@ $(log >$1:$2 $)
R$*				$@

Stranslate
# Fake for sendmail -bt mode.
R$* $$| $*			$: $1 $| $2




