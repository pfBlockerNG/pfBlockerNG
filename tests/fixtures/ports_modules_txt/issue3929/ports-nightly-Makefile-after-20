PORTNAME=	pfSense-pkg-pfBlockerNG-nightly
PORTVERSION=	20260804
CATEGORIES=	net

MAINTAINER=	coreteam@pfsense.org
COMMENT=	pfSense package pfBlockerNG

LICENSE=	APACHE20

RUN_DEPENDS=	${LOCALBASE}/bin/mmdblookup:net/libmaxminddb \
		${LOCALBASE}/bin/ggrep:textproc/gnugrep \
		${LOCALBASE}/bin/grepcidr:net-mgmt/grepcidr \
		${LOCALBASE}/bin/iprange:net-mgmt/iprange \
		${LOCALBASE}/bin/jq:textproc/jq \
		${LOCALBASE}/bin/rsync:net/rsync \
		${LOCALBASE}/sbin/lighttpd:www/lighttpd \
		${PYTHON_PKGNAMEPREFIX}sqlite3>0:databases/py-sqlite3@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}maxminddb>0:net/py-maxminddb@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}charset-normalizer>0:textproc/py-charset-normalizer@${PY_FLAVOR}

USES=		go:1.26+,modules,no_targets php python

NO_ARCH=	yes
# One static FreeBSD pfb-dns and pfb-core per architecture; dns_proxy/pfb_dns.sh and rc.d/pfb_core.sh pick this machine's.
NO_ARCH_IGNORE=	pfb-dns pfb-core

CONFLICTS=	pfSense-pkg-pfBlockerNG pfSense-pkg-pfBlockerNG-testing pfSense-pkg-pfBlockerNG-edge

USE_PHP=	intl
NO_MTREE=	yes
# Ship the bytes do-build checked (go already strips with -ldflags "-s -w").
STRIP=

USE_GITHUB=	yes
GH_ACCOUNT=	pfBlockerNG
GH_PROJECT=	pfBlockerNG
GH_TAGNAME=	v${PORTVERSION}
# go/pfb_dns_gateway's vendored modules (files/modules.txt), and pfBlockerNG/xxh3, which only go/pfb_core vendors;
# the modules sit beside src/ (= WRKSRC).
GH_TUPLE=	dustin:go-humanize:v1.1.0:dustin_go_humanize/../go/pfb_dns_gateway/vendor/github.com/dustin/go-humanize \
		golang:crypto:v0.54.0:golang_crypto/../go/pfb_dns_gateway/vendor/golang.org/x/crypto \
		golang:net:v0.56.0:golang_net/../go/pfb_dns_gateway/vendor/golang.org/x/net \
		golang:sys:v0.49.0:golang_sys/../go/pfb_dns_gateway/vendor/golang.org/x/sys \
		golang:text:v0.44.0:golang_text/../go/pfb_dns_gateway/vendor/golang.org/x/text \
		google:uuid:v1.6.0:google_uuid/../go/pfb_dns_gateway/vendor/github.com/google/uuid \
		mattn:go-isatty:v0.0.24:mattn_go_isatty/../go/pfb_dns_gateway/vendor/github.com/mattn/go-isatty \
		ncruces:go-strftime:v1.1.0:ncruces_go_strftime/../go/pfb_dns_gateway/vendor/github.com/ncruces/go-strftime \
		oschwald:maxminddb-golang:v2.9.0:oschwald_maxminddb_golang/../go/pfb_dns_gateway/vendor/github.com/oschwald/maxminddb-golang/v2 \
		pfBlockerNG:xxh3:v1.1.1-pfblockerng.1:pfblockerng_xxh3/../go/pfb_core/vendor/github.com/pfBlockerNG/xxh3 \
		pires:go-proxyproto:v0.15.0:pires_go_proxyproto/../go/pfb_dns_gateway/vendor/github.com/pires/go-proxyproto \
		quic-go:quic-go:v0.64.0:quic_go_quic_go/../go/pfb_dns_gateway/vendor/github.com/quic-go/quic-go \
		remyoudompheng:bigfft:24d4a6f8daec:remyoudompheng_bigfft/../go/pfb_dns_gateway/vendor/github.com/remyoudompheng/bigfft
USE_GITLAB=	nodefault
GL_TUPLE=	cznic:libc:612e8b0f2f1b1923d5c24c08bc233722500499cd:cznic_libc/../go/pfb_dns_gateway/vendor/modernc.org/libc \
		cznic:mathutil:28129eec384c30a304561c3c8779e4bb29cbff12:cznic_mathutil/../go/pfb_dns_gateway/vendor/modernc.org/mathutil \
		cznic:memory:bb3d99379ed7361ae4c08f11c2876aef046c2a18:cznic_memory/../go/pfb_dns_gateway/vendor/modernc.org/memory \
		cznic:sqlite:d04d243c4dfdb9f9fb19bd1c0c8c37d3923f0589:cznic_sqlite/../go/pfb_dns_gateway/vendor/modernc.org/sqlite
DIST_SUBDIR=	${PORTNAME}

# GitHub extracts to <project>-<version>/; production files live under src/
WRKSRC=		${WRKDIR}/${GH_PROJECT}-${PORTVERSION}/src

TEST_DEPENDS=	${PYTHON_PKGNAMEPREFIX}pytest>=0:devel/py-pytest@${PY_FLAVOR}

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}
PLIST_DIRS=	/var/unbound /etc/inc/priv /etc/inc

# The info.xml <name> is the pfSense package-REGISTRATION name, which rc.packages
# (install_package_xml -> get_package_id) looks up by the pfSense-pkg- PREFIX-STRIPPED
# name. So it MUST be the short name (pfBlockerNG-nightly), NOT the full ${PORTNAME}.
post-extract:
	@${SED} -i '' 's|%%PKGNAME%%|${PORTNAME:S/pfSense-pkg-//}|g' \
		${WRKSRC}/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml
	@${REINPLACE_CMD} -i '' -e 's|%%PYTHON_SUFFIX%%|${PYTHON_SUFFIX}|g' \
		${WRKSRC}/usr/local/pkg/pfblockerng/pfb_python.sh
	@mv ${WRKSRC}/usr/local/share/pfSense-pkg-pfBlockerNG \
		${WRKSRC}/usr/local/share/${PORTNAME}

do-build:
	(cd ${WRKSRC:H} && ${SETENVI} ${WRK_ENV} ${GO_ENV} ${PYTHON_CMD} scripts/build-pfb-dns.py \
		--source-root . --out-dir ${WRKDIR}/pfb-dns --go ${GO_CMD} --vendored \
		--modules-txt ${FILESDIR}/modules.txt --freebsd-major ${OSREL:R})

do-install:
	(cd ${WRKSRC} && ${COPYTREE_SHARE} . ${STAGEDIR})
	${MKDIR} ${STAGEDIR}/etc/inc/priv
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/firewall_aliases_edit/pre_write_config
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/pfblockerng/list_scripts
	${MKDIR} ${STAGEDIR}${PREFIX}/www/pfblockerng/www
	${MKDIR} ${STAGEDIR}${PREFIX}/www/widgets/widgets
	${MKDIR} ${STAGEDIR}${PREFIX}/www/widgets/include
	${MKDIR} ${STAGEDIR}${PREFIX}/www/widgets/javascript
	${MKDIR} ${STAGEDIR}${PREFIX}/www/wizards
	${MKDIR} ${STAGEDIR}${PREFIX}/www/shortcuts
	${MKDIR} ${STAGEDIR}/var/unbound
	${MKDIR} ${STAGEDIR}${DATADIR}
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/pfblockerng/dns_proxy/bin/freebsd-amd64 \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng/dns_proxy/bin/freebsd-arm64
	${INSTALL_PROGRAM} ${WRKDIR}/pfb-dns/freebsd-amd64/pfb-dns \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng/dns_proxy/bin/freebsd-amd64
	${INSTALL_PROGRAM} ${WRKDIR}/pfb-dns/freebsd-arm64/pfb-dns \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng/dns_proxy/bin/freebsd-arm64
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/pfblockerng/core/bin/freebsd-amd64 \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng/core/bin/freebsd-arm64
	${INSTALL_PROGRAM} ${WRKDIR}/pfb-dns/freebsd-amd64/pfb-core \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng/core/bin/freebsd-amd64
	${INSTALL_PROGRAM} ${WRKDIR}/pfb-dns/freebsd-arm64/pfb-core \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng/core/bin/freebsd-arm64
	${INSTALL_SCRIPT} ${WRKSRC}${PREFIX}/etc/rc.d/pfblockerng_repo_generate.sh \
		${STAGEDIR}${PREFIX}/etc/rc.d
	${INSTALL_SCRIPT} ${WRKSRC}${PREFIX}/pkg/pfblockerng/*.sh \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_SCRIPT} ${WRKSRC}${PREFIX}/pkg/pfblockerng/*.py \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_SCRIPT} ${WRKSRC}${PREFIX}/pkg/pfblockerng/list_scripts/*.sh \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng/list_scripts
	${INSTALL_SCRIPT} ${WRKSRC}${PREFIX}/pkg/pfblockerng/pfb_unbound_include.inc \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_SCRIPT} ${WRKSRC}${PREFIX}/www/pfblockerng/www/*.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng/www
	${INSTALL_DATA} -m 0644 ${WRKSRC}${PREFIX}/pkg/pfblockerng.xml \
		${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${WRKSRC}/etc/inc/priv/pfblockerng.priv.inc \
		${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/pfblockerng.inc \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/pfblockerng_apply.inc \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/pfblockerng_cron.inc \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/pfblockerng_geoip.inc \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/pfblockerng_install.inc \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/pfblockerng_extra.inc \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/firewall_aliases_edit/pre_write_config/pfblockerng.php \
		${STAGEDIR}${PREFIX}/pkg/firewall_aliases_edit/pre_write_config
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfBlockerNG.js \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_asn.txt \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/shortcuts/pkg_pfblockerng.inc \
		${STAGEDIR}${PREFIX}/www/shortcuts
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_alerts.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_blacklist.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_category.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_category_edit.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_dnsbl.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_feeds.json \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_feeds.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_general.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_hooks.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_ip.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_update.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_sync.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_safesearch.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_software.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_threats.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/pfblockerng/pfblockerng_log.php \
		${STAGEDIR}${PREFIX}/www/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/widgets/widgets/pfblockerng.widget.php \
		${STAGEDIR}${PREFIX}/www/widgets/widgets
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/widgets/include/widget-pfblockerng.inc \
		${STAGEDIR}${PREFIX}/www/widgets/include
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/widgets/javascript/pfblockerng.js \
		${STAGEDIR}${PREFIX}/www/widgets/javascript
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/wizards/pfblockerng_wizard.xml \
		${STAGEDIR}${PREFIX}/www/wizards
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/www/wizards/pfblockerng_wizard.inc \
		${STAGEDIR}${PREFIX}/www/wizards
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/dnsbl_* \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/shallalist_global_usage \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/ut1_global_usage \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/pfb_dnsbl.doh.conf \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/pfb_dnsbl.safesearch.conf \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/pfb_dnsbl.youtube_restrict.conf \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/pfb_dnsbl.youtube_restrictmoderate.conf \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${PREFIX}/pkg/pfblockerng/pfb_py_hsts.txt \
		${STAGEDIR}${PREFIX}/pkg/pfblockerng
	${INSTALL_DATA} ${WRKSRC}${DATADIR}/info.xml \
		${STAGEDIR}${DATADIR}
	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" \
		${STAGEDIR}${DATADIR}/info.xml

post-install:
	@${FIND} -s ${STAGEDIR}${PREFIX} -type f -print | \
		${SED} -e "s#${STAGEDIR}${PREFIX}/##g" >> ${TMPPLIST}
	@${FIND} -s ${STAGEDIR}/etc -type f -print | \
		${SED} -e "s#${STAGEDIR}##g" >> ${TMPPLIST}

do-test:
	cd ${WRKSRC:H} && \
		${SETENV} ${TEST_ENV} ${PYTHON_CMD} -m pytest -v

.include <bsd.port.mk>
