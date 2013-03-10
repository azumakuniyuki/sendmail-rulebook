divert(0)
VERSIONID(`$Id: goodnight.m4,v 5.7 2008/03/21 19:25:35 ak Exp $')
divert(-1)
#                        _       _       _     _   
#   __ _  ___   ___   __| |_ __ (_) __ _| |__ | |_ 
#  / _` |/ _ \ / _ \ / _` | '_ \| |/ _` | '_ \| __|
# | (_| | (_) | (_) | (_| | | | | | (_| | | | | |_ 
#  \__, |\___/ \___/ \__,_|_| |_|_|\__, |_| |_|\__|
#  |___/                           |___/           
ifdef(`_USE_RULEBOOK_',
	`errprint(`*** ERROR: FEATURE(`goodnight') must occur before FEATURE(`use_rulebook')
')`'m4exit(1)',
	define(`_GOODNIGHT_',`'))
ifdef(`_LOCAL_PARSE_',
	`',
	define(`_LOCAL_PARSE_',`YES'))
define(`GOODNIGHT_MAILER_FLAGS',`%')

LOCAL_CONFIG
#############################################################################
### goodnight configurations                                              ###
#############################################################################
Kzzz hash -o MAPDIR/zzz
Krm0 regex -s2 ^(0+)([0-9]+)$

LOCAL_RULESETS
#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       goodnight -- Sleep mode implementation of Sendmail              ###
###                                                                       ###
###  SYNOPSIS                                                             ###
###       feat.(goodnight)                                                ###
###                                                                       ###
###  CATEGORY                                                             ###
###       Routing Filter                                                  ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       The goodnight filter is a sleep mode implementation of sendmail.###
###       Sendmail drops message  into the spool  by using the sleep time ###
###       which decided by a envelope sender address,a envelope recipient ###
###       address. The sleep time is defined at zzz db map.               ###
###                                                                       ###
###  CALLED FROM                                                          ###
###       LocalParse=98                                                   ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1  -- local-part<@domain-part.> (canonified)                   ###
###                                                                       ###
###  RETURNS                                                              ###
###       2xx -- $#goodnight $@ host $: user                              ###
###       2xx -- local-part<@domain-part.>                                ###
###       4xx --                                                          ###
###       5xx --                                                          ###
###                                                                       ###
#############################################################################
Sgoodnight
# Check the rulebook database
R$*		$: $1 $| $>can goodnight
R$* $| <ON>	$: $1
R$* $| <OFF>	$@ $1

# Check {addr_type} macro
R$+		$: $1 $| <$&{addr_type}>
R$+ $| <e r>	$: $1		# OK, address is an envelope recipient
R$+ $| <e s>	$@ $1		# NG, address is an envelope sender
R$+ $| <h>	$@ $1		# NG, address is a header.
R$+ $| <$*>	$@ $1		# NG, other unknown or empty value.

# Check an envelope recipient address
R$-		$@ $1		# destination is local.
R<@>		$@ <@>		# destination is postmaster.
R$+		$: $1 $| $>islocal $1
R$+ $| <LOCAL>	$@ $1		# destination is local site.
R$+ $| $+	$: Z0:$1	# destination is remode.

# 0. Check {gnAlarm} macro
# RZ0:$+			$: Z0:$1 $| <$&{gnAlarm}>
# RZ0:$+ $| <$+>		$@ $1		# alarm is ON!, must wake up
# RZ0:$+ $| <$@>		$: Z1:$1	# alarm is OFF
RZ0:$+				$: Z1:$1	# sendmail does not use gnAlarm

# 1. expand a client address and lookup / it does not work :-(
# RZ1:$+			$: Z1:$1 $| CA:$&{client_addr}
# RZ1:$+ $| CA:$@		$: Z2:$1	# Client Address is Null
# RZ1:$+ $| CA:0		$: Z2:$1	# Sendmail -bs 
# RZ1:$+ $| CA:$-.$-.$-.$-	$: Z1:$1 $| $(zzz Connect:$2.$3.$4.$5 $: CA:$2.$3.$4 $)
# RZ1:$+ $| CA:$+ $-		Z1:$1 $| $(zzz Connect:$2$3 $: CA:$2 $)
# RZ1:$+ $| CA:$-		$: Z1:$1 $| $(zzz Connect:$2 $: CA:<E> $)
# RZ1:$+ $| CA:<E>		$: Z2:$1			# Not Found
# RZ1:$+ $| $-:$-<>$-:$-	$: Z5:$1 $| ZT/$2:$3<>$4:$5	# Found
# RZ1:$+ $| $*			$: Z2:$1			# Invalid Format in RHS
RZ1:$+				$: Z2:$1

# 2. expand an envelope sender address after strip angle brackets.
RZ2:$+ <@ $+ . >		$: Z2:$1 <@ $2 . > $| $>iv $&f
RZ2:$+ $| <>			$@ $1				# came from postmaster.
RZ2:$+ $| $@			$@ $1				# f macro is null.
RZ2:$+ $| $+			$: Z2:$1 $| T:<S> $2
RZ2:$+ $| T:<S> $+ @ $+		$: Z2:$1 $| T:$(zzz From:$2@$3 $: <S> @$3 $)
RZ2:$+ $| T:<S> @ $- $+		Z2:$1 $| T:$(zzz From:$2$3 $: <S> @$3 $)
RZ2:$+ $| T:<S> @ $-		$: Z2:$1 $| T:$(zzz From:$2 $: <S><E> $)
RZ2:$+ $| T:<S><E>		$: Z3:$1			# not found
RZ2:$+ $| T:$-:$-<>$-:$-	$: Z5:$1 $| ZT/$2:$3<>$4:$5	# found
RZ2:$+ $| T:SLEEP		$: Z5:$1 $| ZT/00:00<>23:59	# anytime sleeping
RZ2:$+ $| T:AWAKE		$@ $1				# must be awake
RZ2:$+ $| T:$*			$: Z3:$1			# invalid format in RHS

# 3. check an envelope recipient address
RZ3:$+				$: Z3:$1 $| $>iv $1
RZ3:$+ $| <>			$@ $1				# goes to postmaster
RZ3:$+ $| $+			$: Z3:$1 $| T:<R> $2
RZ3:$+ $| T:<R> $+ @ $+		$: Z3:$1 $| T:$(zzz To:$2@$3 $: <R> @$3 $)
RZ3:$+ $| T:<R> @ $- $+		Z3:$1 $| T:$(zzz To:$2$3 $: <R> @$3 $)
RZ3:$+ $| T:<R> @ $-		$: Z3:$1 $| T:$(zzz To:$2 $: <R><E> $)
RZ3:$+ $| T:<R><E>		$: Z4:$1 			# not found
RZ3:$+ $| T:$-:$-<>$-:$-	$: Z5:$1 $| ZT/$2:$3<>$4:$5	# found
RZ3:$+ $| T:SLEEP		$: Z5:$1 $| ZT/00:00<>23:59	# anytime sleeping
RZ3:$+ $| T:AWAKE		$@ $1				# must be awake
RZ3:$+ $| T:$*			$: Z4:$1			# invalid format in RHS

# 4. check the default value defined in zzz.db
RZ4:$+				$: Z4:$1 $| T:$(zzz @ $:<E> $)
RZ4:$+ $| T:<E>			$: $1 $| <SKIP>			# no default value
RZ4:$+ $| T:$-:$-<>$-:$-	$: Z5:$1 $| ZT/$2:$3<>$4:$5	# found default value
RZ4:$+ $| T:SLEEP		$: Z5:$1 $| ZT/00:00<>23:59	# anytime sleeping
RZ4:$+ $| T:AWAKE		$@ $1				# must be awake
RZ4:$+ $| T:$*			$: $1 $| <SKIP>			# invalid format in RHS

# 5. remove zeros in found value( 09 -> 9 )
RZ5:$+				$: Z5a:$1
RZ5a:$+ $| ZT/$-:$-<>$-:$-	$: Z5b:$1 $| ZT/$(rm0 $2 $:$2 $):$3 <> $4:$5	# S-H
RZ5b:$+ $| ZT/$-:$-<>$-:$-	$: Z5c:$1 $| ZT/$2:$(rm0 $3 $:$3 $) <> $4:$5	# S-M
RZ5c:$+ $| ZT/$-:$-<>$-:$-	$: Z5d:$1 $| ZT/$2:$3 <> $(rm0 $4 $:$4 $):$5	# E-H
RZ5d:$+ $| ZT/$-:$-<>$-:$-	$: Z5e:$1 $| ZT/$2:$3 <> $4:$(rm0 $5 $:$5 $)	# E-M
RZ5e:$+				$: Z7:$1

# 7. expand a date string (macro d)
RZ7:$+ $| ZT/$+				$: Z7:$1 $| $2 $| <$&d>
RZ7:$+ $| $+ $| <$@>			$: $1 $| <SKIP>		# macro d is NULL
RZ7:$+ $| $+ $| <$- $- $- $-:$-:$- $->	$: Z8:$1 $| RA:$2 $| CT:$6:$7

# 8. remove zeros in current time (macro d)
RZ8:$+					$: Z8a:$1
RZ8a:$+ $| RA:$+ $| CT:$-:$-		$: Z8b:$1 $| RA:$2 $| CT:$(rm0 $3 $:$3 $):$4
RZ8b:$+ $| RA:$+ $| CT:$-:$-		$: Z8c:$1 $| RA:$2 $| CT:$3:$(rm0 $4 $:$4 $)
RZ8c:$+					$: ZA:$1

# A. convert the value of hours and minutes, ex) 23:45 -> 2345
RZA:$+ $| RA:$-:$-<>$-:$- $| CT:$-:$-	$: ZA1:$1 $| RA:$(math * $@ $2 $@ 100 $:0 $):$3<>$4:$5 $| CT:$6:$7
RZA1:$+ $| RA:$-:$-<>$-:$- $| CT:$-:$-	$: ZA2:$1 $| RA:$(math + $@ $2 $@ $3 $:0 $)<>$4:$5 $| CT:$6:$7
RZA2:$+ $| RA:$-<>$-:$- $| CT:$-:$-	$: ZA3:$1 $| RA:$2 <> $(math * $@ $3 $@ 100 $:0 $):$4 $| CT:$5:$6
RZA3:$+ $| RA:$-<>$-:$- $| CT:$-:$-	$: ZA4:$1 $| RA:$2 <> $(math + $@ $3 $@ $4 $:0 $) $| CT:$5:$6
RZA4:$+ $| RA:$-<>$- $| CT:$-:$-	$: ZA5:$1 $| RA:$2<>$3 $| CT:$(math * $@ $4 $@ 100 $:0 $):$5 
RZA5:$+ $| RA:$-<>$- $| CT:$-:$-	$: ZA6:$1 $| RA:$2<>$3 $| CT:$(math + $@ $4 $@ $5 $:0 $)
RZA6:$+ $| RA:0 <> 0 $| CT: 0		$: $1 $| <SKIP>			# all zero
RZA6:$+ $| RA:$- <> $- $| CT: $-	$: ZB:$1 $| $2 <> $3 $| $4

# B. check the beginning time and the end time( ( END - START ) < 0? )
RZB:$+ $| $- <> $- $| $-		$: ZB:$1 $| $2 <> $3 $| $4 $| <$(math - $@ $3 $@ $2 $:E $)>
RZB:$+ $| $- <> $- $| $- $| <$->	$: ZB:$1 $| $2 <> $3 $| $4 $| <$(math l $@ $5 $@ 0 $:E $)>
RZB:$+ $| $- <> $- $| $- $| <E>		$: $1 | <SKIP>			# calculation error
RZB:$+ $| $- <> $- $| $- $| <TRUE>	$: ZD:$1 $| $2 <> $3 $| $4	# negative integer(-)
RZB:$+ $| $- <> $- $| $- $| <FALSE>	$: ZC:$1 $| $2 <> $3 $| $4	# positive integer(+)

# C. compare converted values (the beginning time < the end time, /e.g. 23:00 - 07:00)
RZC:$+ $| $- <> $- $| $-		$: ZC:$1 $| $2 <> $3 $| $4 $| C1: $(math l $@ $2 $@ $4 $:<E> $)
RZC:$+ $| $- <> $- $| $- $| C1:TRUE	$: ZC:$1 $| $2 <> $3 $| $4 $| C5: $(math l $@ $4 $@ $3 $:<E> $)
RZC:$+ $| $- <> $- $| $- $| C1:FALSE	$: ZC:$1 $| $2 <> $3 $| $4 $| C2: $(math = $@ $2 $@ $4 $:<E> $)
RZC:$+ $| $- <> $- $| $- $| C2:TRUE	$: ZC:$1 $| $2 <> $3 $| $4 $| C5: $(math l $@ $4 $@ $3 $:<E> $)
RZC:$+ $| $- <> $- $| $- $| C2:FALSE	$: $1 $| <WAKE>		# running
RZC:$+ $| $- <> $- $| $- $| C5:TRUE	$: ZZZ:$1		# during sleep time
RZC:$+ $| $- <> $- $| $- $| C5:FALSE	$: ZC:$1 $| $2 <> $3 $| $4 $| C6: $(math = $@ $4 $@ $3 $:<E> $)
RZC:$+ $| $- <> $- $| $- $| C6:TRUE	$: ZZZ:$1		# during sleep time
RZC:$+ $| $- <> $- $| $- $| C6:FALSE	$: $1 $| <WAKE>		# running

# D. compare converted values (the beginning time > the end time, /e.g. 3:00 - 07:00)
RZD:$+ $| $- <> $- $| $-		$: ZD:$1 $| $2 <> $3 $| $4 $| C1: $(math l $@ $2 $@ $4 $:<E> $)
RZD:$+ $| $- <> $- $| $- $| C1:TRUE	$: ZD:$1 $| $2 <> $3 $| $4 $| C5: $(math l $@ $3 $@ $4 $:<E> $)
RZD:$+ $| $- <> $- $| $- $| C1:FALSE	$: ZD:$1 $| $2 <> $3 $| $4 $| C2: $(math = $@ $2 $@ $4 $:<E> $)
RZD:$+ $| $- <> $- $| $- $| C2:TRUE	$: ZZZ:$1		# the beginning time of sleeping.
RZD:$+ $| $- <> $- $| $- $| C2:FALSE	$: ZD:$1 $| $2 <> $3 $| $4 $| C6: $(math l $@ $3 $@ $4 $:<E> $)
RZD:$+ $| $- <> $- $| $- $| C5:TRUE	$: ZZZ:$1		# during sleep Time
RZD:$+ $| $- <> $- $| $- $| C5:FALSE	$: ZZZ:$1		# during sleep Time
RZD:$+ $| $- <> $- $| $- $| C6:TRUE	$: $1 $| <WAKE>		# running
RZD:$+ $| $- <> $- $| $- $| C6:FALSE	$: ZZZ:$1		# during sleep Time

# E. catch a calculation error
R$-:$+ $| $- <> $- $| $- $| $-:<E>	$: $1 $| <SKIP>		# calculation error, $1 is ZC or ZD

# check runmode macro(LOG)
RZZZ:$+			$: ZZZ:$1 $| <$(math & $@ $&{runmode} $@ 2 $:0 $)> <$&{client_port}>
RZZZ:$+ $| <2> <$->	$: ZZZ:$1 $>locallog A:goodnight $| $&f $| $1 $| 
RZZZ:$+ $| <2> <$@>	$: ZZZ:$1	# no logging, run by queueing process.
RZZZ:$+ $| <0> <$*>	$: ZZZ:$1	# no logging.

# Check runmode macro(SKIP bit)
RZZZ:$+			$: ZZZ:$1 $| <$(math & $@ $&{runmode} $@ 128 $:0 $)>
RZZZ:$+ $| <128>	$: <SKIP>::$1	# is in test mode.
RZZZ:$+ $| <0>		$: ZZZ:$1	# is not in test mode.

# drop a message into the spool or delivery a message.
RZZZ:$+ <@ $+ . >	$#goodnight $@ $2. $: $1 <@ $2 .>
R$+ $| <WAKE>		$@ $1
R$+ $| <SKIP>		$@ $1
R$*			$@ $1


#############################################################################
### Sleep Mode Mailer                                                     ###
#############################################################################
Mgoodnight,	P=[IPC], F=GOODNIGHT_MAILER_FLAGS, E=\r\n, L=990, N=-12, 
		T=DNS/RFC822/SMTP, A=TCP $h

