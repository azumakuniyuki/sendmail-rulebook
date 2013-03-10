dnl ## sendmail 8.12 requires new user,group "smmsp", "mailnull" ############
dnl #
dnl # /etc/passwd
dnl #  smmsp:*:25:25::0:0:submission:/var/spool/clientmqueue:/sbin/nologin
dnl #  mailnull:*:26:26::0:0:sendmail:/var/spool/mqueue:/sbin/nologin
dnl #
dnl # /etc/group
dnl #  smmsp:*:25:
dnl #  mailnull:*:26:
dnl #
dnl #
dnl ## MSP:Mail Submission Program uses /var/spool/clientmqueue #############
dnl #
dnl #  mkdir /var/spool/clientmqueue
dnl #  chown smmsp:smmsp /var/spool/clientmqueue
dnl #  chmod 770 /var/spool/clientmqueue
dnl #
dnl #
dnl ## Permission ###########################################################
dnl #
dnl #  chmod go-rwx /var/spool/mqueue
dnl #
dnl #  chown root:wheel /etc/mail/sendmail.cf /etc/mail/submit.cf
dnl #  chmod 444 /etc/mail/sendmail.cf /etc/mail/submit.cf
dnl #
dnl #
dnl ## sendmail 8.12 operation ##############################################
dnl #
dnl #                            -------------------
dnl #               ----------   |   |             |
dnl #               |network |-->|MTA|             |-->> send >
dnl #               ----------   | 25|sendmail -bd | 
dnl #                            |---| ( daemon )  |
dnl #               -----------  |   |sendmail.cf  |
dnl # -----------   |sendmail |->|MSA|             |-->> MDA >>
dnl # |/bin/mail|-->|MSP:587  |  |587|             |
dnl # | (local) |   |submit.cf|  -------------------
dnl # -----------   -----------       
dnl #                 
dnl #
dnl ## sequence of mc #######################################################
dnl #
dnl #  VERSIONID()
dnl #  OSTYPE()
dnl #  DOMAIN()
dnl #  options
dnl #  FEATURE()
dnl #  macros
dnl #  MAILER()
dnl #  LOCAL_RULE


dnl ## Rulesets #############################################################
dnl # Rulesets
dnl # No builtin Purpose
dnl #  0 yes	Parsing
dnl #  1 yes	Sender rewriting
dnl #  2 yes	Recipient rewriting
dnl #  3 yes	Canonicalization
dnl #  4 yes	Post cleanup
dnl #  5 yes	Local address rewrite (after aliasing)
dnl # 1x no	mailer rules (sender qualification)
dnl # 2x no	mailer rules (recipient qualification)
dnl # 3x no	mailer rules (sender header qualification)
dnl # 4x no	mailer rules (recipient header qualification)
dnl # 5x no	mailer subroutines (general)
dnl # 6x no	mailer subroutines (general)
dnl # 7x no	mailer subroutines (general)
dnl # 8x no	reserved
dnl # 90 no	Mailertable host stripping
dnl # 96 no	Bottom half of Ruleset 3 (ruleset 6 in old sendmail)
dnl # 97 no	Hook for recursive ruleset 0 call (ruleset 7 in old sendmail)
dnl # 98 no	Local part of ruleset 0 (ruleset 8 in old sendmail)


dnl ## m4 diversions @ cf/m4/cfhead.m4 ######################################
dnl #
dnl # 1 : LOCAL_NET_CONFIG / local host detection & resolution
dnl # 2 : LOCAL_RULE_3 
dnl # 3 : LOCAL_RULE_0
dnl # 4 : LOCAL_UUCP / uucp ruleset 0 additions
dnl # 5 :  / locally interpreted names (overrides $R)
dnl # 6 : LOCAL_CONFIG / local configuration @ top of file
dnl # 7 : MAILER_DEFINITIONS
dnl # 8 :  / DNS based blacklists
dnl # 9 : LOCAL_RULE_{1,2}, LOCAL_RULESETS ...etc
dnl #
dnl #
VERSIONID(`$Id: sendmail-8.13.mc,v 5.13 2007/09/05 04:46:35 ak Exp $')dnl


dnl #########################################################################
dnl ### OS/DOMAIN configuration ( cf/{ostype,domain} )                    ###
dnl #########################################################################
dnl #
dnl #  OSTYPE(`sunos3.5')
dnl #  OSTYPE(`sunos4.1')
dnl #  OSTYPE(`bsd4.4')
dnl #  OSTYPE(`openbsd')
dnl #  OSTYPE(`freebsd4')
dnl #  OSTYPE(`freebsd5')
dnl #  OSTYPE(`darwin')
dnl #  OSTYPE(`linux')
dnl #  OSTYPE(`solaris8')
dnl #
dnl #
dnl # * DOMAIN() ************************************************************
dnl #
dnl #  DOMAIN(`sendmail.org')dnl requires cf/domain/sendmail.org.m4
dnl #


dnl #########################################################################
dnl ### common macros,defined macros                                      ###
dnl #########################################################################
dnl #
dnl #  define(`MAIL_SETTINGS_DIR',`CF/')dnl
dnl #
define(`SENDMAILROOT',`')
define(`CF',`SENDMAILROOT/etc/mail')
define(`MAPDIR',`CF/maps')
define(`SPOOL',`/var/spool')
define(`ZERO',`0s')

dnl ** sendmail D MACROS ****************************************************
dnl #
dnl #  define(`confCF_VERSION',`ver')			$Z
dnl #  define(`confDOMAIN_NAME',`$w.$m')		$j
dnl #  define(`confMAILER_NAME',`mailer-daemon')	$n
dnl #
Dwhostname
Dmexample.jp
define(`confDOMAIN_NAME',`$w.$m')

dnl #########################################################################
dnl ### sendmail options:file,directory                                   ###
dnl #########################################################################
dnl #
dnl #  define(`confDEAD_LETTER_DROP',`/var/tmp/dl')	DeadLetterDrop
dnl #  define(`confERROR_MESSAGE',`CF/sendmail.oE')	ErrorHeader
dnl #  define(`confERROR_MESSAGE',`text')		ErrorHeader
dnl #  define(`confCT_FILE',`-o CF/sendmail.ct')	F{t} trusted-user
dnl #  define(`HELP_FILE',`CF/sendmail.hf')		HelpFile
dnl #  define(`confHOSTS_FILE',`/etc/hosts')		HostsFile
dnl #  define(`confHOST_STATUS_DIRECTORY',`SPOOL/stat')	HostStatusDirectory
dnl #  define(`confPID_FILE',`/var/run/sendmail.pid')	PidFile
dnl #  define(`QUEUE_DIR',`SPOOL/sendmail')		QueueuDirectory(Q)
dnl #  define(`QUEUE_DIR',`SPOOL/mqueue')		QueueuDirectory(Q)
dnl #  define(`QUEUE_DIR',`SPOOL/queues/q.*')		QueueuDirectory
dnl #  define(`STATUS_FILE',`-o CF/sendmail.st')	StatusFile(S)
dnl #  define(`confUSERDB_SPEC',`CF/userdb.db')		UserDatabaseSpec

dnl #########################################################################
dnl ### sendmail options:queue                                            ###
dnl #########################################################################
dnl #
dnl #  define(`confCHECKPOINT_INTERVAL',`4')	CheckpointInterval
dnl #  define(`confMAX_QUEUE_RUN_SIZE',`64')	MaxQueueRunSize
dnl #  define(`confQUEUE_SORT_ORDER',`filename')QueueSortOrder
dnl #  define(`confSAFE_QUEUE',`interactive')	SuperSafe(s)

dnl #########################################################################
dnl ### sendmail options:alias                                            ###
dnl #########################################################################
dnl #
dnl #  define(`ALIAS_FILE',`CF/aliases')	AliasFile
dnl #  define(`confALIAS_WAIT',`10m')		AliasWait
dnl #  define(`confCHECK_ALIASES',`True')	CheckAliases
dnl #  define(`confMAX_ALIAS_RECURSION',`10')	MaxAliasRecursion

dnl #########################################################################
dnl ### sendmail options:loadaverage,process                              ###
dnl #########################################################################
dnl #
dnl #  define(`confWORK_CLASS_FACTOR',`1800')		ClassFactor
dnl #  define(`confCONNECTION_RATE_THROTTLE',`0')	ConnectionRateThrottle
dnl #  define(`confDELAY_LA',`7')			DelayLA
dnl #  define(`confSEPARATE_PROC',`True')		ForkEachJob
dnl #  define(`confCON_EXPENSIVE',`True')		HoldExpensive
dnl #  define(`confMAX_DAEMON_CHILDREN',`12')		MaxDaemonChildren :-(
dnl #  define(`confMAX_RUNNERS_PER_QUEUE',`24')		MaxRunnersPerQueue
dnl #  define(`confMAX_QUEUE_CHILDREN',`4')		MaxQueueChildren
dnl #  define(`confMIN_QUEUE_AGE',`27m')		MinQueueAge
dnl #  define(`confNICE_QUEUE_RUN',`0')			NiceQueueRun
dnl #  define(`confPROCESS_TITLE_PREFIX',`prefix')	ProcessTitlePrefix
dnl #  define(`confQUEUE_FACTOR','600000')		QueueFactor
dnl #  define(`confQUEUE_LA',`8')			QueueLA(x)
dnl #  define(`confREFUSE_LA',`12')			RefuseLA(X)
dnl #  define(`confWORK_RECIPIENT_FACTOR',`30000')	RecipientFactor
dnl #  define(`confWORK_TIME_FACTOR',`90000')		RetryFactor
dnl #
define(`confMIN_QUEUE_AGE',`27m')

dnl #########################################################################
dnl ### sendmail options:timeout                                          ###
dnl #########################################################################
dnl #
dnl #  define(`confDIAL_DELAY',`10s')		DialDelay
dnl #  define(`confTO_ACONNECT',`0s')		Timeout.aconnect
dnl #  define(`confTO_AUTH',`10m')		Timeout.auth
dnl #  define(`confTO_COMMAND',`1h')		Timeout.commmand
dnl #  define(`confTO_CONNECT',`1m')		Timeout.connect
dnl #  define(`confTO_DATABLOCK',`1h')		Timeout.datablock
dnl #  define(`confTO_DATAFINAL',`1h')		Timeout.datafinal
dnl #  define(`confTO_DATAINIT',`5m')		Timeout.datainit
dnl #  define(`confTO_FILEOPEN',`0s')		Timeout.fileopen
dnl #  define(`confTO_HELO',`5m')		Timeout.helo
dnl #  define(`confTO_HOSTSTATUS',`30m')	Timeout.hoststatus
dnl #  define(`confTO_ICONNECT',`5m')		Timeout.iconnect
dnl #  define(`confTO_IDENT',`5s')		Timeout.ident
dnl #  define(`confTO_LHLO',`2m')		Timeout.lhlo
dnl #  define(`confTO_INITIAL',`5m')		Timeout.initial
dnl #  define(`confTO_MAIL',`10m')		Timeout.mail
dnl #  define(`confTO_MISC',`2m')		Timeout.misc
dnl #  define(`confTO_QUEUEWARN',`4d')		Timeout.queuewarn
dnl #  define(`confTO_QUEUEWARN_DSN',`4d')	Timeout.queuewarn.dsn
dnl #  define(`confTO_QUEUERETURN',`5d')	Timeout.queuereturn
dnl #  define(`confTO_QUEUERETURN_DSN',`5d')	Timeout.queuereturn.dsn
dnl #  define(`confTO_QUIT',`2m')		Timeout.quit
dnl #  define(`confTO_RESOLVER_RETRANS',`5s')	Timeout.resolver.retrans
dnl #  define(`confTO_RESOLVER_RETRY',`5s')	Timeout.resolver.retry
dnl #  define(`confTO_STARTTLS',`0s')		Timeout.starttls
dnl #
define(`confTO_QUEUEWARN',`4d')
define(`confTO_COMMAND',`3m')
define(`confTO_DATABLOCK',`3m')
define(`confTO_DATAFINAL',`3m')
define(`confTO_HOSTSTATUS',`5m')
define(`confTO_IDENT',`ZERO')

dnl #########################################################################
dnl ### sendmail options:connection cache                                 ###
dnl #########################################################################
dnl #
dnl #  define(`confMCI_CACHE_SIZE',`2')			ConnectionCacheSize(k)
dnl #  define(`confMCI_CACHE_TIMEOUT',`5m')		ConnectionCacheTimeout(K)
dnl #  define(`confSINGLE_THREAD_DELIVERY',`True')	SingleThreadDelivery
dnl #

dnl #########################################################################
dnl ### sendmail options:security,slamming                                ###
dnl #########################################################################
dnl #
dnl #  define(`confALLOW_BOGUS_HELO',`False')		AllowBogusHELO
dnl #  define(`confBAD_RCPT_THROTTLE',`2')		BadRcptThrottle
dnl #  define(`confDEF_USER_ID',`mailnull')		DefaultUser
dnl #  define(`confDONT_BLAME_SENDMAIL',`Safe')		DontBlameSendmail,see p394
dnl #  define(`confMAX_RCPTS_PER_MESSAGE',`2')		MaxRecipientsPerMessage
dnl #  define(`confPRIVACY_FLAGS',`goaway')		PrivacyOptions(p)
dnl #  define(`confPRIVACY_FLAGS',`goaway,restrictmailq,restrictqrun')
dnl #  define(`confQUEUE_FILE_MODE',`0600')		QueueFileMode
dnl #  define(`confRUN_AS_USER',`user:group')		RunAsUser
dnl #  define(`confSMTP_LOGIN_MSG',`$j MAIL SYSTEM')	SmtpGreetingMessage,$e
dnl #  define(`confTRUSTED_USER',`mailadmin')		TrustedUser
dnl #  define(`confUNSAFE_GROUP_WRITES',`true')		UnsafeGroupWrites :-(
dnl #  define(`confCONNECTION_RATE_WINDOW_SIZE',`60')	ConnectionRateWindowSize
dnl #
define(`confALLOW_BOGUS_HELO',`False')
define(`confMAX_RCPTS_PER_MESSAGE',`3')
define(`confBAD_RCPT_THROTTLE',`2')
define(`confDEF_USER_ID',`mailnull')
define(`confDONT_BLAME_SENDMAIL',`Safe')
define(`confPRIVACY_FLAGS',`goaway')
define(`confSMTP_LOGIN_MSG',`$j MAIL SYSTEM')

dnl #########################################################################
dnl ### sendmail options:STARTTLS                                         ###
dnl #########################################################################
dnl #
dnl #  define(`CERT_DIR',`CF/certs')
dnl #  define(`confCACERT_PATH',`CERT_DIR')
dnl #  define(`confCACERT',`CERT_DIR`'/cacert.pem')
dnl #  define(`confSERVER_CERT',`CERT_DIR`'/client.cert.pem')
dnl #  define(`confSERVER_KEY',`CERT_DIR`'/client.key.pem')
dnl #  define(`confCLIENT_CERT',`CERT_DIR`'/client.key.pem')
dnl #  define(`confCLIENT_KEY',`CERT_DIR`'/client.key.pem')
dnl #

dnl #########################################################################
dnl ### sendmail options:header,body                                      ###
dnl #########################################################################
dnl #
dnl #  define(`confDEF_CHAR_SET',`iso-2022-jp')		DefaultCharSet
dnl #  define(`confEIGHT_BIT_HANDLING',`mimefy')	EightBitMode
dnl #  define(`confNO_RCPT_ACTION',`add-to-undisclosed')NoRecipientAction
dnl #  define(`confOLD_STYLE_HEADERS',`True')		OldStyleHeaders
dnl #  define(`confRRT_INPLIES_DSN',`True')		RrtInpliesDsn
dnl #  define(`confSAVE_FROM_LINES',`True')		SaveFromLines
dnl #  define(`confMIME_FORMAT_ERRORS',`True')		SendMimeErrors
dnl #  define(`confUSE_ERRORS_TO',`False')		UseErrorsTo
dnl #  define(`confMAX_HEADER_LENGTH',`32768')		MaxHeaderLength
dnl #  define(`confMAX_MIME_HEADER_LENGTH',`32768')	MaxMimeHeaderLength
dnl #  define(`confFROM_HEADER',`From:$f')		HFrom:
dnl #  define(`confMESSAGEID_HEADER',`<$t.$i@$j>'	HMessage-Id:
dnl #  define(`confRECEIVED_HEADER',`')			HReceived:
dnl #
define(`confNO_RCPT_ACTION',`add-to-undisclosed')
define(`confMIME_FORMAT_ERRORS',`True')


dnl #########################################################################
dnl ### sendmail options:size                                             ###
dnl #########################################################################
dnl #
dnl #  define(`confDF_BUFFER_SIZE',8192)		DataFileBufferSize
dnl #  define(`confMAX_HOP',`64')			MaxHopCount(h)
dnl #  define(`confMAX_MESSAGE_SIZE',`infinite')	MaxMessageSize
dnl #  define(`confMIN_FREE_BLOCKS',`1024')		MinFreeBlocks
dnl #  define(`confXF_BUFFER_SIZE',8192)		XScriptFileBufferSize
dnl #
define(`confMAX_HOP',`64')
define(`confMAX_MESSAGE_SIZE',`10485760')dnl =10MB

dnl #########################################################################
dnl ### sendmail options:tune,daemon,operation                            ###
dnl #########################################################################
dnl #
dnl #  DAEMON_OPTIONS(``Port=25,Addr=0.0.0.0'')		DaemonPortOptions(O)
dnl #  define(`confDELIVER_BY_MIN',`300')		DeliverByMin
dnl #  define(`confDIRECT_SUBMISSION_MODIFIERS',`A')	DirectSubmissionModifiers
dnl #  define(`confDELIVERY_MODE',`deferred')		DeliveryMode(d)
dnl #  define(`confDONT_EXPAND_CNAME',`true')		DontExpandCnames
dnl #  define(`confDONT_PROBE_INTERFACES',`True')	DontProbeInterfaces
dnl #  define(`confDONT_PRUNE_ROUTES',`True')		DontPruneRoutes(R)
dnl #  define(`confERROR_MODE',`p')			ErrorMode
dnl #  define(`confFALLBACK_MX',`10.0.0.1')		FallBackMXhost(V)
dnl #  define(`confFALLBACK_SMARTHOST',`10.0.0.1')	FallBackSmartHost
dnl #  define(`confFAST_SPLIT',`1')			FastSplit
dnl #  define(`confTRY_NULL_MX_LIST',`true')		TryNullMXList
dnl #  define(`conf_REQUIRES_DIR_FSYNC',`')		RequiresDirFsync
dnl #
DAEMON_OPTIONS(``Port=25,Addr=0.0.0.0,Name=MTA'')
DAEMON_OPTIONS(``Port=587,Addr=0.0.0.0,Name=MSA,Modify=Ea'')
define(`confDONT_PROBE_INTERFACES',`True')
define(`confTRY_NULL_MX_LIST',`True')

dnl #########################################################################
dnl ### sendmail options:auth                                             ###
dnl #########################################################################
dnl #
dnl #  define(`confAUTH_MAX_BITS',`192')		AuthMaxBits
dnl #  define(`confAUTH_MECHANISMS',`LOGIN PLAIN CRAM-MD5 DIGEST-MD5')dnl
dnl #  define(`confAUTH_OPTIONS',``A,a,c,d'')		AuthOptions

dnl ##########################################################################
dnl ### shared memory configuration ( to enable sendmail -bP )             ###
dnl ##########################################################################
dnl #
dnl #  define(`confSHARED_MEMORY_KEY',`32768')	SharedMemoryKey
dnl # 
dnl #  * SHARED_MEMORY_KEY requires -DSM_CONF_SHM compile time macro
dnl #  | % vi ./devtools/Site/config.m4
dnl #  | APPENDDEF(`conf_sendmail_ENVDEF',`-DSM_CONF_SHM=1')  
dnl #  | % ./Build -c
dnl #  | # ./Build install
dnl #

dnl #########################################################################
dnl ### sendmail options:debug, others                                    ###
dnl #########################################################################
dnl #
dnl #  define(`confCONNECT_ONLY_TO',`10.0.0.1')		ConnectOnlyTo
dnl #  define(`confCONTROL_SOCKET_NAME',`SPOOL/.ctrl')	ControlSocketName
dnl #  define(`confDOUBLE_BOUNCE_ADDRESS',`addr')	DoubleBounceAddress
dnl #  define(`confLOG_LEVEL',`15')			LogLevel(L)
dnl #  define(`confREJECT_LOG_INTERVAL',`3h')		RejectLogInterval
dnl #  define(`confCOPY_ERRORS_TO',`postmaster')	PostmasterCopy(P)
dnl #
define(`confCOPY_ERRORS_TO',`postmaster')

dnl #########################################################################
dnl ### sendmail options: Milter                                          ###
dnl #########################################################################
dnl #
dnl #  define(`confMILTER_LOG_LEVEL',`9')		Milter.LogLvel
dnl #  define(`confMILTER_MACROS_CONNECT',``'')		Milter.macros.connect
dnl #  define(`confMILTER_MACROS_HELO',``'')		Milter.macros.helo
dnl #  define(`confMILTER_MACROS_ENVFROM',``'')		Milter.macros.envfrom
dnl #  define(`confMILTER_MACROS_ENVRCPT',``'')		Milter.macros.envrcpt
dnl #

dnl #########################################################################
dnl ### sendmail FEATURES,MACROS: masquerade                              ###
dnl #########################################################################
dnl #
dnl #  FEATURE(`allmasquerade')				masquerade envelope-to :-(
dnl #  FEATURE(`always_add_domain')			add @domain to local mail 
dnl #  FEATURE(`domaintable')				migrate old domain to new
dnl #  FEATURE(`genericstable',`hash -o CF/genericstable')masquerade sender addr.
dnl #  FEATURE(`generics_entire_domain')		generics sub domains
dnl #  FEATURE(`limited_masquerade')			masquerade only my hostname 
dnl #  FEATURE(`local_no_masquerade')			no masquerade local 
dnl #  FEATURE(`masquerade_entire_domain')		masquerade sub domains.
dnl #  FEATURE(`masquerade_envelope')			masquerade envelope-from
dnl #
dnl #  EXPOSED_USER(`root postmaster')			C{E} username
dnl #  EXPOSED_USER_FILE(`-o CF/sendmail.cE')		F{E} exposedusers
dnl #  GENERICS_DOMAIN(`sendmail.org')			C{G} domainname
dnl #  GENERICS_DOMAIN_FILE(`-o CF/sendmail.cG')	F{G} genericsdomains
dnl #  MASQUERADE_AS(`my.domain.net')			DM   domainname
dnl #  MASQUERADE_DOMAIN(`myolddomain.jp')		C{M} domainname
dnl #  MASQUERADE_DOMAIN_FILE(`-o CF/sendmail.cM')	F{M} masquerade-domain
dnl #  MASQUERADE_EXCEPTION(`mx.sendmail.org')dnl	C{N} domainname
dnl #  MASQUERADE_EXCEPTION_FILE(`-o CF/sendmail.cN')	D{N} donotmasq
dnl #

dnl #########################################################################
dnl ### sendmail FEATURES,MACROS: local configurations                    ###
dnl #########################################################################
dnl #
dnl #  FEATURE(`use_cw_file')			local-host-names
dnl #  FEATURE(`nocanonify',`canonify_hosts')	do not $[ host $] at S3
dnl #  FEATURE(`no_default_msa')		close port 587
dnl #  CANONIFY_DOMAIN(`sendmail.org')		C{Canonify} domainname
dnl #  CANONIFY_DOMAIN_FILE(`-o CF/sendmail.cC')F{Canonify} canonify-domains
dnl #  LOCAL_DOMAIN(`sendmail.org hoge.mil')	C{w} hostname
dnl #  LOCAL_USER(`root mailer-daemon')		C{L} username
dnl #  LOCAL_USER_FILE(`CF/sendmail.cL')	F{L} local-user-names
dnl #  define(`confCW_FILE',`-o CF/sendmail.cw')F{w} local-host-names
dnl #  define(`_REC_BY_',`$.by $j (R8/cf1)$?r with $r$. id $i$?{tls_version}')
dnl #
FEATURE(`use_cw_file')
FEATURE(`no_default_msa')
FEATURE(`nocanonify',`canonify_hosts')
define(`_REC_BY_',`$.by $j (R8/cf1)$?r with $r$. id $i$?{tls_version}')dnl

dnl #########################################################################
dnl ### sendmail FEATURES: access_db                                      ###
dnl #########################################################################
dnl #
dnl #  FEATURE(`access_db',`hash -o -T<TMPF> CF/access')
dnl #  FEATURE(`blacklist_recipients')		anti-SPAM rcpt in access.db
dnl #  FEATURE(`lookupdotdomain')		enable .sendmail.org REJECT
dnl #
dnl # ************ following may act as OPEN RELAY :-( **********************
dnl #
dnl #  FEATURE(`relay_mail_from')		From:user@sendmail.org RELAY
dnl #  FEATURE(`relay_mail_from',`domain')
dnl #  FEATURE(`relay_local_from')		$f(@domain) = $w relay
dnl #  FEATURE(`promiscuous_relay')		makes me *OPEN RELAY*
dnl # 
dnl # ***********************************************************************
dnl #
dnl #  FEATURE(`relay_hosts_only')		set RELAY_DOMAIN macro
dnl #  FEATURE(`loose_relay_check')		%hack, user%hostB@hostA
dnl #  FEATURE(`delay_checks',`friend|hate')	To:user@my.jp SPAM{FRIEND|HATE}
dnl #  FEATURE(`queuegroup')			requires access_db
dnl #  FEATURE(`compat_check')			Compat:a@b.jp<@>c@d.jp ERROR
dnl #
dnl #  define(`confREJECT_MSG',`$@ 5.7.1 $: "550 Access denied"')
dnl #  define(`confRELAY_MSG',`$@ 5.7.1 $: "550 can not relay"')
dnl #
FEATURE(`access_db',`hash -o -T<TMPF> CF/access')
FEATURE(`blacklist_recipients')

dnl #########################################################################
dnl ### sendmail FEATURES,MACROS: relay,delivery                          ###
dnl #########################################################################
dnl #
dnl #  FEATURE(`mailertable',`hash -o CF/mailertable')
dnl #  FEATURE(`nullclient',`10.0.0.1')		relays to 10.0.0.1
dnl #  FEATURE(`relay_based_on_MX')
dnl #  FEATURE(`redirect')			enable user.REDIRECT
dnl #  FEATURE(`preserve_local_plus_detail')	keep bob+nospam address
dnl #  FEATURE(`preserve_luser_host')		keep hostname LUSER_RELAY
dnl #  FEATURE(`local_lmtp',`/bin/mail.local')
dnl #  FEATURE(`local_procmail',`LBIN/procmail')
dnl #  FEATURE(`local_procmail',`LBIN/maildrop')
dnl #  RELAY_DOMAIN(`my.local.domain')		C{R}
dnl #  RELAY_DOMAIN_FILE(`CF/sendmail.cR')	F{R} relay-domains
dnl #  define(`confCR_FILE',`-o CF/sendmail.cR')F{R} relay-domains
dnl #  define(`MAIL_HUB',`local.mail.relay')	relay @my.host mail
dnl #  define(`SMART_HOST',`mx.relay.server')	DS
dnl #  define(`LUSER_RELAY',`local:username')	DL
dnl #  define(`LUSER_RELAY',`mailer:relay.host')relay unknown localuser
dnl #  define(`LOCAL_RELAY',`local.mail.relay')	relay local mail
dnl #
FEATURE(`mailertable',`hash -o CF/mailertable')
undefine(`BITNET_RELAY')
undefine(`DECNET_RELAY')
undefine(`FAX_RELAY')

dnl #########################################################################
dnl ### sendmail FEATURES,MACROS: virtuser                                ###
dnl #########################################################################
dnl #
dnl #  FEATURE(`virtusertable',`hash -o CF/virtusertable')
dnl #  FEATURE(`virtuser_entire_domain')	verify sub domains
dnl #  VIRTUSER_DOMAIN(`sendmail.org hoge.mil')	CR$={VirtHost}
dnl #  VIRTUSER_DOMAIN_FILE(`-o CF/sendmail.cV')F{VirtHost} virtuser-domains

dnl #########################################################################
dnl ### sendmail FEATURES: security, slamming                             ###
dnl #########################################################################
dnl #
dnl #  FEATURE(`accept_unresolvable_domains')
dnl #  FEATURE(`accept_unqualified_senders')
dnl #  FEATURE(`dnsbl')				use Realtime Blackhole List
dnl #  FEATURE(`mtamark')			detecting MTA marking
dnl #  FEATURE(`smrsh',`SENDMAILROOT/usr/bin/smrsh')sendmail Restricted shell
dnl #  FEATURE(`use_ct_file')			trusted-users
dnl #  FEATURE(`use_client_ptr')		$&{client_ptr} in Scheck_relay
dnl #  FEATURE(`greet_pause',`0')		< 5m; pause after smtp greeting.
dnl #  FEATURE(`ratecontrol')			control client connections.
dnl #  FEATURE(`conncontrol')			control simultaneous connections.
dnl #
FEATURE(`use_ct_file')
FEATURE(`smrsh',`SENDMAILROOT/usr/bin/smrsh')

dnl #########################################################################
dnl ### sendmail FEATURES,MACROS: uucp                                    ###
dnl #########################################################################
dnl #
dnl #  FEATURE(`nouucp',`reject')
dnl #  define(`UUCP_MAILER_MAX',`2000000')
dnl #
FEATURE(`nouucp',`reject')
undefine(`UUCP_RELAY')

dnl #########################################################################
dnl ### sendmail MACROS: arguments of delivery agent                      ###
dnl #########################################################################
dnl #
dnl #  defile(`DSMTP_MAILER_ARGS',`')
dnl #  defile(`DSMTP_MAILER_QGRP',`')
dnl #  defile(`ESMTP_MAILER_ARGS',`')
dnl #  defile(`ESMTP_MAILER_QGRP',`')
dnl #  defile(`LOCAL_MAILER_ARGS',`')
dnl #  defile(`LOCAL_MAILER_CHARSET',`')
dnl #  defile(`LOCAL_MAILER_DSN_DIAGNOSTIC_CODE',`')
dnl #  defile(`LOCAL_MAILER_EOL',`')
dnl #  defile(`LOCAL_MAILER_FLAGS',`')
dnl #  defile(`LOCAL_MAILER_MAX',`')
dnl #  defile(`LOCAL_MAILER_MAXMSGS',`')
dnl #  defile(`LOCAL_MAILER_MAXRCPTS',`')
dnl #  defile(`LOCAL_MAILER_PATH',`')
dnl #  defile(`LOCAL_MAILER_QGRP',`')
dnl #  defile(`LOCAL_SHELL_ARGS',`')
dnl #  defile(`LOCAL_SHELL_FLAGS',`')
dnl #  defile(`LOCAL_SHELL_DIR',`')
dnl #  defile(`LOCAL_SHELL_PATH',`')
dnl #  defile(`SMTP_MAILER_ARGS',`')
dnl #  defile(`SMTP_MAILER_CHARSET',`')
dnl #  defile(`SMTP_MAILER_FLAGS',`')
dnl #  defile(`SMTP_MAILER_MAX',`')
dnl #  defile(`SMTP_MAILER_MAXMSGS',`')
dnl #  defile(`SMTP_MAILER_MAXRCPTS',`')
dnl #  defile(`SMTP_MAILER_QGRP',`')
dnl #  defile(`SMTP8_MAILER_ARGS',`')
dnl #  defile(`SMTP8_MAILER_QGRP',`')

dnl #########################################################################
dnl ### V8.10 multiple queue directories                                  ###
dnl ### V8.12 queue group configuration                                   ###
dnl #########################################################################
dnl #
dnl #  QUEUE_GROUP(`hotmail',`P=/var/spool/queues/g.hotmail')
dnl #  QUEUE_GROUP(`docomo',`P=/var/spool/queues/g.docomo')
dnl #  QUEUE_GROUP(`ezweb',`P=/var/spool/queues/g.ezweb')
dnl #  QUEUE_GROUP(`vodafone',`P=/var/spool/queues/g.vodafone')
dnl #
dnl #  QUEUE_GROUP(`localqueue',`P=/var/spool/queues/g.local')
dnl #  define(`LOCAL_MAILER_QGRP',`localqueue')
dnl #
dnl #
dnl # * Queue Group Equate **************************************************
dnl #
dnl #  F(Flags)=f		-qf
dnl #  I(Interval)=n		-q30m
dnl #  J(Jobs)=n		-OMaxQueueRunSize
dnl #  N(Nice)=n		-ONiceQueueRun
dnl #  P(Path)=/path/to		-OQueueDirectory
dnl #  r(recipients)=n		-OMaxRecipientsPerMessage
dnl #  R(Runners)=n		-OMaxRunnersPerQueue
dnl #

dnl #########################################################################
dnl ### SASL: Simple Authentication and Security Layer SMTP-AUTH configu- ###
dnl ###       ration ( sendmail + cyrus-sasl )                            ###
dnl ###       see ftp://ftp.andrew.cmu.edu/pub/cyrus-mail/                ###
dnl #########################################################################
dnl #
dnl #
dnl #  | % vi ./devtools/Site/site.config.m4
dnl #  | APPENDDEF(`confENVDEF', `-DSASL')
dnl #  | APPENDDEF(`conf_sendmail_LIBS', `-lsasl')
dnl #  | APPENDDEF(`confLIBDIRS',`-L/path/to/sasl/lib')
dnl #  | APPENDDEF(`confINCDIRS',`-I/path/to/sasl/include')
dnl #
dnl #  | % ./Build -c
dnl #  | # ./Build install
dnl #
dnl #
dnl #  TRUST_AUTH_MECH(`LOGIN PLAIN CRAM-MD5 DIGEST-MD5')
dnl #  FEATURE(`authinfo')
dnl #  define(`confAUTH_OPTIONS',`A')
dnl #  define(`confDEF_AUTH_INFO',`CF/default-auth-info')
dnl #
dnl #

dnl #########################################################################
dnl ### MILTER configuration                                              ###
dnl #########################################################################
dnl #
dnl #  * INPUT_MAIL_FILTER requires following compile time macro
dnl #  | % vi ./devtools/Site/site.config.m4
dnl #  | APPENDDEF(`conf_libmilter_ENVDEF', `-DMILTER')dnl
dnl #  | APPENDDEF(`conf_sendmail_ENVDEF', `-DMILTER')dnl
dnl #
dnl #  | % ./Build -c
dnl #  | # ./Build install
dnl #
dnl #  * COMPILE MILTER programs
dnl #  | % ./Build UBINDIR=/usr/local/bin SBINDIR=/usr/local/sbin \
dnl #  |    MANROOT=/usr/local/share/man/man LIBDIR=/usr/local/lib/
dnl #  | % ./Build UBINDIR=/usr/local/bin SBINDIR=/usr/local/sbin \
dnl #  |    MANROOT=/usr/local/share/man/man LIBDIR=/usr/local/lib/ install
dnl #
dnl #  INPUT_MAIL_FILTER(`milter-amavis',`S=local:/var/log/amavis/amavis.sock, T=S:10m;R:10m;E:10m')
dnl #  INPUT_MAIL_FILTER(`sid-filter',`S=inet:8891@localhost')

dnl #########################################################################
dnl ### sendmail rulebook                                                 ###
dnl #########################################################################
dnl #
dnl #  HACK(`maildebug')
dnl #  FEATURE(`goodnight')
dnl #  FEATURE(`sendermt')
dnl #  FEATURE(`countryroads',`accept',`')
dnl #  FEATURE(`lhsbl',`use_wl')
dnl #  FEATURE(`rhsbl',`use_wl',`header')
dnl #  FEATURE(`localblackhole')
dnl #  FEATURE(`use_rulebook',`e')
dnl #

dnl #########################################################################
dnl ### sendmail MAILER:                                                  ###
dnl #########################################################################
dnl #
dnl #  MAILER(`procmail')
dnl #
MAILER(`local')
MAILER(`smtp')

dnl #########################################################################
dnl ### sendmail LOCAL_CONFIG: examples                                   ###
dnl #########################################################################
dnl #
dnl #  LOCAL_CONFIG
dnl #  FECF/visible.users
dnl #  Khostmap hash CF/hostmap
dnl #  F{RootName}0@text:-k2 -v0 -z: /etc/passwd
dnl #  H?l?X-Envelope-From: $f
dnl #  H?l?X-Envelope-To: $u
dnl #  H?l?X-Received-Host: $j
dnl #

dnl #########################################################################
dnl ### local network configuratiion/overwrite SMART_HOST macro           ###
dnl #########################################################################
dnl # 
dnl # LOCAL_NET_CONFIG
dnl # R $* < @ $+ .$m. > $*	$#smtp $@ $2.$m $: $1 < @ $2.$m > $3
dnl #

dnl #########################################################################
dnl ### local ruleset configuratiion/ruleset 0 (parse)                    ###
dnl #########################################################################
dnl # 
dnl #  LOCAL_RULE_0
dnl #  R$+ < @ lady.berkeley.edu. >	$#uucp $@ lady $: $1
dnl #

dnl #########################################################################
dnl ### local ruleset configuratiion/ruleset 1 (sender address)           ###
dnl #########################################################################
dnl # 
dnl #  LOCAL_RULE_1
dnl #

dnl #########################################################################
dnl ### local ruleset configuratiion/ruleset 2 (recipient)                ###
dnl #########################################################################
dnl #
dnl #  LOCAL_RULE_2
dnl #

dnl #########################################################################
dnl ### local ruleset configuratiion/ruleset 3 ( canonify )               ###
dnl #########################################################################
dnl # 
dnl #  LOCAL_RULE_3
dnl #  R$* < @ $+ > $*		$:$1<@ $(hostmap $2 $) >$3
dnl #

dnl #########################################################################
dnl ### local rule set configuratiion/policy rulesets.                    ###
dnl ### see sendmail 3rd Edition chapter 7.1, 19.9                        ###
dnl #########################################################################
dnl #
dnl #  Scheck_data		# nEnvelopeTo
dnl #  Scheck_eoh		# nHeaders $| total bytes
dnl #  Scheck_etrn		# host
dnl #  Scheck_expn		# after ETRN command(allow or deny)
dnl #  Scheck_vrfy		# <?vrfyuser@domian.tld>?
dnl #  SLocal_check_relay	# hostname $| IPnumber
dnl #  SLocal_check_mail	# <?sender-user@domain.tld>?
dnl #  SLocal_check_rcpt	# <?rcpt-user@domain.tld>?
dnl #

dnl #########################################################################
dnl ### DRAC: Dynamic Relay Authorization Control map, POP before SMTP,   ###
dnl ###       allow recent POP mail clients to relay.                     ###
dnl #########################################################################
dnl #
dnl #  LOCAL_CONFIG
dnl #  Kdrac btree CF/dracd
dnl #
dnl #  LOCAL_RULESETS
dnl #  SLocal_check_rcpt
dnl #  R$*	$: $&{client_addr}
dnl #  R$+	$: $(drac $1 $: ? $)
dnl #  R?	$@ ?
dnl #  R$+	$@ $#OK
dnl #

