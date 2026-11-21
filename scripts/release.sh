#!/bin/sh
# Bygger, signerar och publicerar en release av rco-sso.
#
#   RCO_SSO_SIGNING_KEY=<fil med privata nyckeln> scripts/release.sh 0.6.1
#
# Versionen måste stå i rco-sso.php (Version: och RCO_SSO_VERSION), arbetsmappen
# vara ren och main pushad. Zip-filen byggs med git archive, så bara det som är
# committat följer med, och tests/ och scripts/ utesluts via .gitattributes.
set -eu

VERSION="${1:?Ange version, till exempel 0.6.1}"
KEY="${RCO_SSO_SIGNING_KEY:?Ange sökvägen till privata nyckeln i RCO_SSO_SIGNING_KEY}"
cd "$(dirname "$0")/.."

[ -z "$(git status --porcelain)" ] || { echo "Arbetsmappen är inte ren." >&2; exit 1; }
[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || { echo "Releaser görs från main." >&2; exit 1; }
git fetch -q origin
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "main är inte pushad, eller ligger efter origin." >&2; exit 1; }
grep -q "^ \* Version: $VERSION\$" rco-sso.php || { echo "Version: $VERSION saknas i rco-sso.php." >&2; exit 1; }
grep -q "const RCO_SSO_VERSION = '$VERSION';" rco-sso.php || { echo "RCO_SSO_VERSION är inte $VERSION." >&2; exit 1; }
if git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null; then echo "v$VERSION finns redan." >&2; exit 1; fi

php tests/test-token.php

DIST=$(mktemp -d)
git archive --format=zip --prefix=rco-sso/ -o "$DIST/rco-sso.zip" HEAD
php scripts/signera.php "$DIST/rco-sso.zip" "$KEY"

git tag -a "v$VERSION" -m "rco-sso $VERSION"
git push -q origin "v$VERSION"
gh release create "v$VERSION" "$DIST/rco-sso.zip" "$DIST/rco-sso.zip.sig" \
  --repo Reklam-Co-in-Sweden-AB/rco-sso --title "rco-sso $VERSION" --generate-notes
rm -r "$DIST"
echo "Release v$VERSION publicerad."
