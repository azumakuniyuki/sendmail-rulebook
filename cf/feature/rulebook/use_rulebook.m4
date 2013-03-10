divert(0)
VERSIONID(`$Id: use_rulebook.m4,v 5.30 2008/03/23 09:43:31 ak Exp $')
divert(-1)
#  ____        _      _                 _    
# |  _ \ _   _| | ___| |__   ___   ___ | | __
# | |_) | | | | |/ _ \ '_ \ / _ \ / _ \| |/ /
# |  _ <| |_| | |  __/ |_) | (_) | (_) |   < 
# |_| \_\\__,_|_|\___|_.__/ \___/ \___/|_|\_\
#                                            
ifdef(`_USE_RULEBOOK_',
	`',
	`define(`_USE_RULEBOOK_',`RULEBOOK')')dnl
ifelse(defn(`_ARG_'),`',
	`',
lower(substr(_ARG_,0,1)),`e',`dnl
	define(`_RULEBOOK_FINERCTRL_',`1')
',
	`define(`_RULEBOOK_FINERCTRL_',`0')')dnl
define(`_LIB_RULEBOOK_',`../feature/rulebook/lib/rulebook.m4')dnl
include(_LIB_RULEBOOK_)dnl
ifdef(`_LIB_DNS_',`include(`../feature/rulebook/lib/dns.m4')',`')dnl
ifdef(`_LIB_IP4_',`include(`../feature/rulebook/lib/ip4.m4')',`')dnl

ifdef(`_LOCAL_PARSE_',`dnl
LOCAL_RULE_0
R$+ <@ $+ .> $*			$: $1<@$2.> $3 $| <eLP: _LOCAL_PARSE_ >
R$+ <@ $+ .> $* $| <eLP:YES>	$: $>localzero eLP:$1<@$2.> $3
R$+ <@ $+ .> $* $| <eLP:$*>	$@ $1 < @ $2 . > $3
R$# $*				$# $1
R$+				$@ $1

LOCAL_RULESETS
#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       localzero -- A hook into the ParseLocal=98(local part of S0)    ###
###                                                                       ###
###  CALLED FROM                                                          ###
###       ParseLocal=98                                                   ###
###                                                                       ###
###  ARGUMENTS                                                            ###
###       $1 -- local-part < @ domain-part. >                             ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       "Sendmail 3rd Edition" p158, 4.3.3.2 LOCAL RULE 0 mc macro      ###
###                                                                       ###
#############################################################################
Slocalzero
ReLP:$+		$: <LP:$1> $(put {lcp} $@ $1 $)
R<LP:$+>	$: $1
ifdef(`_GOODNIGHT_',`dnl
R$*		$: $>goodnight $&{lcp}
',`')dnl
ifdef(`_SENDERMT_',`dnl
R$*		$: $>sendermt $&{lcp}
',`')dnl
R$*		$: $1 $(put {lcp} $)
R$*		$@ $1		# return
R$# $*		$# $1		# exit  
',`')dnl


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       Local_check_relay -- A hook into the check_relay rule set.      ###
###                                                                       ###
###  CALLED FROM                                                          ###
###       check_rcpt                                                      ###
###                                                                       ###
###  ARGUMENTS                                                            ###
###       $1 -- client host name $| client IP address                     ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       "Sendmail 3rd Edition" p288,                                    ###
###         7.1.1 Local_check_relay and check_relay                       ###
###                                                                       ###
#############################################################################
SLocal_check_relay
R$+		$: <LCr:$1> $(put {lcl} $@ $1 $)
R<LCr:$+>	$: $1
ifdef(`_LOCAL_CHECK_RELAY_',`',`')dnl

#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       Local_greet_pause -- A hook into the greet_pause rule set.      ###
###                                                                       ###
###  CALLED FROM                                                          ###
###       greet_pause                                                     ###
###                                                                       ###
###  ARGUMENTS                                                            ###
###       $1 -- client host name $| client IP address                     ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       "sendmail 8.13 Companion" p51, 7.1.3 The greet_pause Feature    ###
###                                                                       ###
#############################################################################
SLocal_greet_pause
R$+		$: <LGP:$1> $(put {lgp} $@ $1 $)
R<LGP:$+>	$: $1
ifdef(`_LOCAL_GREET_PAUSE_',`dnl
ifdef(`_COUNTRYROADS_TARPIT_',`dnl
R$+		$: $>countryroads $&{lgp}
',`')dnl
R$+		$: $1 $(put {lgp} $)
',`')dnl

#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       Local_check_mail -- A hook into the check_mail rule set.        ###
###                                                                       ###
###  CALLED FROM                                                          ###
###       check_mail                                                      ###
###                                                                       ###
###  ARGUMENTS                                                            ###
###       $1 -- envelope sender address                                   ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       "Sendmail 3rd Edition" p290,                                    ###
###         7.1.2 Local_check_mail and check_mail                         ###
###                                                                       ###
#############################################################################
SLocal_check_mail
R$*		$: <LCM:$1> $(put {lcm} $@ $1 $)
R<LCM:$*>	$: $1
ifdef(`_LOCAL_CHECK_MAIL_',`dnl
ifdef(`_LHSBL_',`dnl
R$*		$: $>lhsbl $&{lcm}
',`')dnl
ifdef(`_HELO_CONTROL_',`dnl
R$*		$: $>heloControl $&{lcm}
',`')dnl
ifdef(`_PPP_CONTROL_',`dnl
R$*		$: $>pppControl $&{lcm}
',`')',`')dnl


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       Local_check_rcpt -- A hook into the check_rcpt rule set.        ###
###                                                                       ###
###  CALLED FROM                                                          ###
###       check_rcpt                                                      ###
###                                                                       ###
###  ARGUMENTS                                                            ###
###       $1 -- envelope recipient address                                ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       "Sendmail 3rd Edition" p292,                                    ###
###         7.1.3 Local_check_rcpt and check_rcpt                         ###
###                                                                       ###
#############################################################################
SLocal_check_rcpt
R$*		$: <LCR:$1> $(put {lcr} $@ $1 $)
R<LCR:$+>	$: $1
ifdef(`_LOCAL_CHECK_RCPT_',`dnl
ifdef(`_COUNTRYROADS_',`dnl
R$+		$: $>countryroads $&{lcr}
',`')dnl
ifdef(`_RHSBL_',`dnl
R$*		$: $>rhsbl $&{lcr}
',`')dnl
ifdef(`_CHECK_ARR_',`dnl
R$*		$: $>checkARR $&{lcr}
',`')dnl
ifdef(`_LOCALBLACKHOLE_',`dnl
R$*		$: $>localblackhole $&{lcr}
',`')',`')dnl


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       check_data -- Check just after SMTP DATA command.               ###
###                                                                       ###
###  ARGUMENTS                                                            ###
###       $1 -- the number of envelope recipients                         ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       "Sendmail 3rd Edition" p692, 19.9.1 check_data                  ###
###                                                                       ###
#############################################################################
Scheck_data
R$*		$: <CDT:$1> $(put {lcd} $@ $1 $)
R<CDT:$*>	$: $1
ifdef(`_CHECK_DATA_',`dnl
',`')dnl


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       check_eoh -- Called after all headers have been processed.      ###
###                                                                       ###
###  ARGUMENTS                                                            ###
###       $1 -- the number of headers $| total bytes                      ###
###                                                                       ###
###  SEE ALSO                                                             ###
###       "Sendmail 3rd Edition" p1095 25.5.3 The check_eoh Rule Set      ###
###                                                                       ###
#############################################################################
Scheck_eoh
R$*		$: <EOH:$1> $(put {lce} $@ $1 $)
R<EOH:$+>	$: $1
ifdef(`_CHECK_EOH_',`dnl
ifdef(`_USE_SCOREBOOK_',`dnl
R$*		$: $>judgeTheScore $1
',`')dnl
',`')dnl

# Undefine macros for policy rulesets
R$*		$: $1 $(put {lcm} $)
R$*		$: $1 $(put {lcr} $)
R$*		$: $1 $(put {lcd} $)
R$*		$: $1 $(put {lce} $)


