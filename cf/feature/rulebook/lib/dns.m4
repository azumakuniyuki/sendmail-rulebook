divert(0)
VERSIONID(`$Id: dns.m4,v 5.19 2008/04/09 05:22:48 ak Exp $')
divert(-1)
#  _ _ _       __  _           
# | (_) |__   / /_| |_ __  ___ 
# | | | '_ \ / / _` | '_ \/ __|
# | | | |_) / / (_| | | | \__ \
# |_|_|_.__/_/ \__,_|_| |_|___/
#                              
LOCAL_CONFIG
#############################################################################
### dns common configurations                                             ###
#############################################################################
KmxLookup dns -RMX -a<FOUND> -T<TMPERR> -d5s -r2
KaLookup dns -RA -a<FOUND> -T<TMPERR> -d5s -r2
KnsLookup dns -RNS -a<FOUND> -T<TMPERR> -d5s -r2
KptrLookup dns -RPTR -a<FOUND> -T<TMPERR> -d5s -r2
KtxtLookup dns -RTXT -a<FOUND> -T<TMPERR> -d5s -r2
KhostLookup host -a<OK> -T<TMPF> -d5s -r1
Kdnsztab hash -O MAPDIR/dnszonetable
D{MatchedDNSZ}0


LOCAL_RULESETS
#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       hasMXRR -- lookup MX resource record of a given domain name     ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Check whether or not the domain name has MX resource record.    ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- hostname                                                  ###
###                                                                       ###
###  RETURNS                                                              ###
###       MXhost.MXRR -- found MX record(s)                               ###
###       <NOMXRR>    -- found no MX record                               ###
###       <TMPERR>    -- temporary lookup failure                         ###
###                                                                       ###
###  MAPS                                                                 ###
###       mxLookup (dns)                                                  ###
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
ShasMXRR
R$-			$@ <NOMXRR>
R$+			$: $1 $| $1
R$+ $| $+		$: $1 $| Q:$2
R$+ $| Q: $+		$: $1 $| Q: $(mxLookup $2 $: <!> $)
R$+ $| Q: <!>		$: <HAS_NO_MXRR>
R$+ $| Q: $@ <FOUND>	$: <INVALID_MXRR>
R$+ $| Q: $- <FOUND>	$: <INVALID_MXRR>
R$+ $| Q: $+ <FOUND>	$: <HAS_MXRR> $2
R$+ $| Q: $+ <TMPERR>	$: <TMPERR>
R<HAS_NO_MXRR>		$@ <NOMXRR>
R<INVALID_MXRR>		$@ <NOMXRR>
R<TMPERR>		$@ <TMPERR>
R<HAS_MXRR> $*		$@ $1.MXRR
R$+ $| $*		$@ $1


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       hasARR -- lookup A resource record of a given domain name.      ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Check whether or not the domain name has A resource record.     ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- hostname                                                  ###
###                                                                       ###
###  RETURNS                                                              ###
###       IPaddress.ARR -- found A record                                 ###
###       <NOARR>       -- found no A record                              ###
###       <TMPERR>      -- temporary lookup failure                       ###
###                                                                       ###
###  MAPS                                                                 ###
###       aLookup(dns)                                                    ###
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
ShasARR
R$+			$: $1 $| $1
R$+ $| $+		$: $1 $| Q:$2
R$+ $| Q:$+		$: $1 $| Q:$(aLookup $2 $: <!> $)
R$+ $| Q:<!>		$: <HAS_NO_ARR>
R$+ $| Q:$+ <FOUND>	$: <HAS_ARR> $2
R$+ $| Q:$+ <TMPERR>	$: <TMPERR>
R$+ $| Q:$*		$: <TMPERR>
R<HAS_NO_ARR>		$@ <NOARR>
R<HAS_ARR> $*		$@ $1.ARR
R<TMPERR>		$@ <TMPERR>
R$+ $| $*		$@ $1


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       hasNSRR -- lookup NS resource record of a given domain name.    ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Check whether or not the domain name has NS resource record.    ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- hostname                                                  ###
###                                                                       ###
###  RETURNS                                                              ###
###       dnshost.NSRR -- found NS record(s)                              ###
###       <NONSRR>     -- found no NS record                              ###
###       <TMPERR>     -- temporary lookup failure                        ###
###                                                                       ###
###  MAPS                                                                 ###
###       nsLookup (dns)                                                  ###
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
ShasNSRR
R$-			$@ $1
R$+			$: $1 $| $1
R$+ $| $+		$: $1 $| Q:$2
R$+ $| Q:$+		$: $1 $| Q: $(nsLookup $2 $: <!> $)
R$+ $| Q: <!>		$: <HAS_NO_NSRR>
R$+ $| Q: $+ <FOUND>	$: <HAS_NSRR> $2
R$+ $| Q: $+ <TMPERR>	$: <TMPERR>
R<HAS_NO_NSRR>		$@ <NONSRR>
R<TMPERR>		$@ <TMPERR>
R<HAS_NSRR> $*		$@ $1.NSRR
R$+ $| $*		$@ $1


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       hasPTRRR -- lookup PTR resource record of a given IP address.   ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Check whether or not the IP address name has pointer record.    ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- IPaddress                                                 ###
###                                                                       ###
###  RETURNS                                                              ###
###       ReverseName.PTRRR -- found PTR record                           ###
###       <NOPTRRR>         -- found no PTR record                        ###
###       <TMPERR>          -- temporary lookup failure                   ###
###                                                                       ###
###  MAPS                                                                 ###
###       ptrLookup (dns)                                                 ###
###                                                                       ###
#############################################################################
ShasPTRRR
R$-			$@ $1
R$+			$: $1 $| $1
R$+ $| $-.$-.$-.$-	$: $1 $| Q: $(ptrLookup $5.$4.$3.$2.in-addr.arpa. $: <!> $)
R$+ $| Q: <!>		$: <HAS_NO_PTRRR>
R$+ $| Q: $+ <TMPERR>	$: <TMPERR>
R$+ $| Q: $+ <FOUND>	$: <HAS_PTRRR> $2
R<HAS_NO_PTRRR>		$@ <NOPTRRR>
R<HAS_PTRRR> $*		$@ $1.PTRRR
R<TMPERR>		$@ <TMPERR>
R$+ $| $*		$@ $1


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       hasTXTRR -- lookup TXT resource record of a given domain name.  ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Check whether or not the domain name has TXT resource record.   ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- IPaddress                                                 ###
###       $1 -- hostname                                                  ###
###                                                                       ###
###  RETURNS                                                              ###
###       hostname.TXTRR -- found TXT record                              ###
###       <NOTXTRR>      -- found no TXT record                           ###
###       <TMPERR>       -- temporary lookup failure                      ###
###                                                                       ###
###  MAPS                                                                 ###
###       txtLookup (dns)                                                 ###
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
ShasTXTRR
R$-			$@ $1
R$+			$: $1 $| $1
R$+ $| $+		$: $1 $| Q:$2
R$+ $| Q:$+		$: $1 $| Q: $(txtLookup $2 $: <!> $)
R$+ $| Q: <!>		$: <HAS_NO_TXTRR>
R$+ $| Q: $+ <FOUND>	$: <HAS_TXTRR> $2
R$+ $| Q: $+ <TMPERR>	$: <TMPERR>
R<HAS_NO_TXTRR>		$@ <NOTXTRR>
R<TMPERR>		$@ <TMPERR>

# Parse TXT Resource Record(SPF)
R<HAS_TXTRR>v=spf1 $*		$@ $1.SPF
R<HAS_TXTRR>spf2.0/mfrom,pra $*	$@ $1.SAS
R<HAS_TXTRR>spf2.0/mfrom $*	$@ $1.SPF
R<HAS_TXTRR>spf2.0/pra $*	$@ $1.SID
R<HAS_TXTRR> $*			$@ $1.TXTRR
R$+ $| $*			$@ $1
 


#############################################################################
###                                                                       ###
###  NAME                                                                 ###
###       dnszctl -- Looks for IP or Host by using DNS Zone database.     ###
###                                                                       ###
###  DESCRIPTION                                                          ###
###       Ruleset dnszctl looks for  IP address or  hostname by using DNS ###
###       Zone(dnsztab) map.  And it checks the  discovered frequency and ###
###       the threshold are compared, every time.                         ###
###                                                                       ###
###  PARAMETERS                                                           ###
###       $1 -- threshold                                                 ###
###       $2 -- IP address or hostname                                    ###
###       $3 -- The order number defined in dnsztab(LHS, RHS)             ###
###                                                                       ###
###  RETURNS                                                              ###
###       0   -- Not found                                                ###
###       1   -- Discoverd                                                ###
###       2   -- Temporary error                                          ###
###       <>  -- Discoverd and reached to the threshold                   ###
###                                                                       ###
#############################################################################
Sdnszctl
# Check arguments and Reverse Client IP address
R$- $| $+ $| $-			$: $1 $| $3 $| $>isIPv4 $2
R$- $| $- $| $-.$-.$-.$-.IPv4	$: <X:$1> $| CL:$6.$5.$4.$3 $| O:$2
R$- $| $- $| $+			$: <X:$1> $| CL:$3 $| O:$2

# Get DNS zone name
R<X:$-> $| CL:$+ $| O:$-	$: <X:$1> $| CL:$2 $| L:$(dnsztab $3 $:<E> $)
R<X:$-> $| CL:$+ $| L:<E>	$@ 0	# The order number is not found.

# Resolve
R<X:$-> $| CL:$+ $| L:$+	$: <X:$1> $| Q:$2.$3 $| RR:$>hasARR $2.$3
R<X:$-> $| Q:$+ $| RR:<NOARR>	$@ 0	# The IP Address is not found
R<X:$-> $| Q:$+ $| RR:<TMPERR>	$@ 2	# Temporary Lookup Failure

# log
R<X:$-> $| Q:$+ $| RR:$+.ARR		$: <X:$1> $| Q:$2 $| RR:$3.ARR $| LC:<$(math & $@ $&{xState} $@ 2 $: 0 $)>
R<X:$-> $| Q:$+ $| RR:$+.ARR $| LC:<2>	$: <X:$1> $| RR:$3.ARR $>localLog C:dnszctl $| $2 $| $3 $| $&{lcm}
R<X:$-> $| Q:$+ $| RR:$+.ARR $| LC:<0>	$: <X:$1> $| RR:$3.ARR

# Check the threshold
R<X:$-> $| RR:$+.ARR	$: <X:$1> $| CT:$&{MatchedDNSZ} 
R<X:$-> $| CT:$-	$: <X:$1> $| CM:<$(math + $@ $2 $@ 1 $:E $)>
R<X:$-> $| CT:$@	$: <X:$1> $| CM:<0>
R<X:$-> $| CM:<E>	$: <X:$1> $| CM:<0>
R<X:$-> $| CM:<$->	$: COMP: <$(math l $@ $2 $@ $1 $:E $)> $(put {MatchedDNSZ} $@ $2 $)

#  Return the result value
RCOMP:<E> 	$@ 2	# Calculation Error
RCOMP:<TRUE>	$@ 1	# Less than the threshold
RCOMP:<FALSE>	$@ <>	# Greater equals to the threshold
R$*		$@ 0

