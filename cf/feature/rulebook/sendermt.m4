divert(0)
VERSIONID(`$Id: sendermt.m4,v 5.15 2008/03/21 19:25:35 ak Exp $')
divert(-1)
#                     _                     _   
#  ___  ___ _ __   __| | ___ _ __ _ __ ___ | |_ 
# / __|/ _ \ '_ \ / _` |/ _ \ '__| '_ ` _ \| __|
# \__ \  __/ | | | (_| |  __/ |  | | | | | | |_ 
# |___/\___|_| |_|\__,_|\___|_|  |_| |_| |_|\__|
#                                               
ifdef(`_USE_RULEBOOK_',
	`errprint(`*** ERROR: FEATURE(`sendermt') must occur before FEATURE(`use_rulebook')
')`'m4exit(1)',
	define(`_SENDERMT_',`'))
ifdef(`_LOCAL_PARSE_',
	`',
	define(`_LOCAL_PARSE_',`YES'))

LOCAL_CONFIG
#############################################################################
### sendermt configurations                                               ###
#############################################################################
Ksendermt hash -o MAPDIR/sendermt

LOCAL_RULESETS
#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       sendermt -- The mailertable decided by envelope sender address  ###
###                                                                       ###
###  SYNOPSIS                                                             ###
###       feat.(sendermt)                                                 ###
###                                                                       ###
###  CATEGORY                                                             ###
###       Routing Filter                                                  ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       The sendermt is  the another implementation of mailertable. The ###
###       sendermt ruleset decides "triple":the delivery agent, the relay ###
###       host, and the recipient by sendermt database map.               ###
###                                                                       ###
###  CALLED FROM                                                          ###
###       LocalParse=98                                                   ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1  -- local-part<@sender-domain-part.> (canonified)            ###
###                                                                       ###
###  RETURNS                                                              ###
###       2xx -- $#delivery-agent $@ relay-host $: recipient              ###
###       2xx -- local-part<@sender-domain-part.>                         ###
###       4xx --                                                          ###
###       5xx --                                                          ###
###                                                                       ###
###  FILES                                                                ###
###       /etc/mail/lcf/sendermt (hash)                                   ###
###                                                                       ###
#############################################################################
Ssendermt
# Check the rulebook database
R$*		$: $1 $| $>can sendermt
R$* $| <ON>	$: $1
R$* $| <OFF>	$@ $1

# Check addr_type macro
R$+		$: $1 $| <$&{addr_type}>
R$+ $| <e r>	$: $1	# OK, address is a envelope recipient
R$+ $| <e s>	$@ $1	# NG, address is a envelope sender
R$+ $| <h>	$@ $1	# NG, address is a header.
R$+ $| <$*>	$@ $1	# NG, other unknown value.

# Check mail_host and mail_mailer Macro
R$+		$: $1 $| <$&{mail_host}> <$&{mail_mailer}>
R$+ $| <$+><$+>	$@ $1	# NG, Initial Parse of sender address
R$+ $| <$@><$@>	$: $1	# OK

# Check envelope recipient address
R$-		$@ $1		# destination is local.
R<@>		$@ <@>		# destination is postmaster.
R$+		$: $1 $| $>islocal $1
R$+ $| <LOCAL>	$@ $1		# destination is local site.
R$+ $| $+	$: $1		# destination is remode.

# Expand envelope sender address, after strip angle bracket
R$+ <@ $+ . >	$: $1 <@ $2 . > $| $>iv $&f
R$+ $| <>	$@ $1		# came from postmaster.
R$+ $| $@	$@ $1		# null macro
R$+ $| $+	$: $1 $| <S> $2

# Lookup
R$+ $| <S> $+ @ $+	$: $1 $| $(sendermt $2@$3 $: <S>@$3 $)
R$+ $| <S> @ $- $+	$1 $| $(sendermt $2$3 $: <S>@$3 $)
R$+ $| <S> @ $-		$: $1 $| $(sendermt $2 $: <S><E> $)
R$+ $| <S> <E>		$: <SKIP>::$1

# Check the delivery agent and the relay host
R$+ $| $-:$=[ $+ ]	$: <OK> $1 $| <SMT> $2:[$4]
R$+ $| $-:$+		$: <OK> $1 $| <SMT> $2:$3

# Check the runmode macro(LOG)
R<OK>$+ $| <SMT>$-:$+		$: <OK>$1 $| <SMT>$2:$3 <$(math & $@ $&{runmode} $@ 2 $: 0 $)>
R<OK>$+ $| <SMT>$-:$+ <2>	$: <OK>$1 $| <SMT>$2:$3 $>locallog A:sendermt $| $&f $| $1 $| $2
R<OK>$+ $| <SMT>$-:$+ <0>	$: <OK>$1 $| <SMT>$2:$3	# No logging.

# Check the runmode macro(SKIP bit)
R<OK>$+ $| <SMT>$-:$+		$: <OK>$1 $| <SMT>$2:$3 <$(math & $@ $&{runmode} $@ 128 $: 0 $)>
R<OK>$+ $| <SMT>$-:$+ <128>	$: <SKIP>::$1		# Test mode.
R<OK>$+ $| <SMT>$-:$+ <0>	$: <OK>$1 $| <SMT>$2:$3	# Not test mode.

# Return or exit
R<SKIP>::$+		$@ $1
R<OK>$+ $| <SMT>$-:$+	$# $2 $@ $3 $: $1
R$*			$@ $&{lcp}


