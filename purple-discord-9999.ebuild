# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit git-r3

DESCRIPTION="Pidgin/Purple PRotocol PLugin for Discord"
HOMEPAGE="https://github.com/EionRobb/purple-discord"
EGIT_REPO_URI="${HOMEPAGE}"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~alpha ~amd64 ~arm ~hppa ~ia64 ~ppc ~ppc64 ~s390 ~sh ~sparc ~x86"
IUSE=""

DEPEND="net-im/pidgin
dev-vcs/git
dev-libs/json-glib
>=dev-libs/glib-2.0"
RDEPEND="${DEPEND}"
