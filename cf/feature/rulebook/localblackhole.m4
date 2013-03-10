divert(0)
VERSIONID(`$Id: localblackhole.m4,v 5.13 2008/03/23 19:25:35 ak Exp $')
divert(-1)
#  _                    _   ____  _            _    _           _      
# | |    ___   ___ __ _| | | __ )| | __ _  ___| | _| |__   ___ | | ___ 
# | |   / _ \ / __/ _` | | |  _ \| |/ _` |/ __| |/ / '_ \ / _ \| |/ _ \
# | |__| (_) | (_| (_| | | | |_) | | (_| | (__|   <| | | | (_) | |  __/
# |_____\___/ \___\__,_|_| |____/|_|\__,_|\___|_|\_\_| |_|\___/|_|\___|
#                                                                      
ifdef(`_USE_RULEBOOK_',
	`errprint(`*** ERROR: FEATURE(`localblackhole') must occur before FEATURE(`use_rulebook')
')`'m4exit(1)',
	`')
define(`_LOCALBLACKHOLE_',`1')
ifdef(`_LOCAL_CHECK_RCPT_',
	`',
	define(`_LOCAL_CHECK_RCPT_',`1'))

LOCAL_CONFIG
#############################################################################
### localblackhole configurations                                         ###
#############################################################################

LOCAL_RULESETS
#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       localblackhole -- Delete any messages silently                  ###
###                                                                       ###
###  CATEGORY                                                             ###
###       Delivery Filter                                                 ###
###                                                                       ###
###  SYNOPSIS                                                             ###
###       feat.(localblackhole)                                           ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Any messages will be discarded.                                 ###
###                                                                       ###
###  CALLED FROM                                                          ###
###       Local_check_rcpt                                                ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- ANY TOKEN                                                 ###
###                                                                       ###
###  RETURNS                                                              ###
###       2xx -- $@ $1                                                    ###
###       4xx --                                                          ###
###       5xx -- $#discard                                                ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       O'Reilly sendmail 3rd Edition/6.3.3 An Email Blackhole          ###
###                                                                       ###
#############################################################################
Slocalblackhole
# check the rulebook database
R$*		$: $1 $| $>can localblackhole
R$* $| <ON>	$: $1
R$* $| <OFF>	$@ $1

# Check a local user
R$*		$: $1 $| $>islocal $&{rcpt_addr}
R$* $| <LOCAL>	$@ $1
R$* $| $+	$: $1

# Check runmode macro(LOG)
R$*	$: $1 <$(math & $@ $&{runmode} $@ 2 $: 0 $)>
R$*<2>	$: $1 $>locallog A:localblackhole $| $&{mail_addr} $| $&{rcpt_addr} $| $&{client_addr}
R$*<0>	$: $1	# No logging.

# Check runmode macro(SKIP bit)
R$*		$: $1 $| <$(math & $@ $&{runmode} $@ 128 $: 0 $)>
R$* $| <128>	$: <SKIP>	# Test mode. 
R$* $| <0>	$: $1		# Not test mode.

# Discard any message
R<SKIP>		$@ OK
R$*		$#discard $: Message died away to blackhole.

