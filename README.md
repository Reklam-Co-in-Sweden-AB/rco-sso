# Reklam & Co SSO 0.5.1

Plugin som låter Reklam & Co-personal logga in på kundsajter med Microsoft Entra ID, utan någon nyckel eller hemlighet på sajten. Microsoft signerar inloggningen, `sso.reklamco.se` (CoWeb) skickar den vidare och pluginet kontrollerar Microsofts signatur själv.

Bakgrund, beslut och designspec finns i det interna repot `rco-sso-docs`.

## Vad pluginet gör

| Del | Vad |
|---|---|
| Inloggning | Knappen "Logga in med Reklam & Co" på wp-login.php. Skickar till Microsoft med en nonce som är bunden till en cookie, tar emot token från `sso.reklamco.se` och kontrollerar den. |
| Kontroll av token | RS256-signatur mot Microsofts publika nycklar (cachade ett dygn), utfärdare, tenant, mottagare, giltighetstid, ålder högst 10 minuter, nonce och att token bara används en gång. |
| Vem släpps in | Inloggningsnamnet (UPN, `preferred_username`) slutar på `@reklamco.se` och token har approllen `wp.admin` eller `wp.editor`. Claimet `email` används inte. Åtkomst per kund avgörs i CoWeb. |
| Konton | Kopplas på Entras `oid`. Första gången kopplas ett befintligt konto vars e-post är samma som personens UPN, annars skapas ett nytt. Ett konto som redan är kopplat till ett annat `oid` tas aldrig över. |
| Roller | `wp.admin` ger administratör, `wp.editor` ger redaktör. Sätts vid varje inloggning. |
| Första kopplingen | Lösenordet slumpas om och alla öppna sessioner avslutas. |
| Lösenord | Personalkonton kan inte logga in med lösenord eller återställa lösenord. |
| API-åtkomst (MCP) | Applikationslösenord och andra kopplingar utan webbläsarsession gäller bara om kontot har loggat in via SSO de senaste 30 dagarna. |
| Beaver Builder AI | Molnkopplingens token (från `connect.wpbeaverbuilder.com`) godtas bara för konton som är kopplade till SSO och har loggat in de senaste 30 dagarna. Kontrollen ligger i `rest_pre_dispatch`, eftersom Beaver Builder sätter användaren på vägar som går förbi `determine_current_user`. Kundens konton och byråkontot kan inte användas med molnkopplingen. |
| Applikationslösenord | Personliga konton som är kopplade till SSO får bara använda applikationslösenord på sajter som är markerade som utvecklingssajt i CoWebs register (Inställningar → Sajter), eller när `WP_ENVIRONMENT_TYPE` är `local`. Domänen avgör inte (`hemsida.eu` delas av alla Oderlands kunder), och `development`/`staging` räcker inte eftersom konstanten följer med till produktion. Vid lansering byter sajten domän och stängs automatiskt. Utan lista gäller produktionsreglerna. Byråkontot och kundens konton påverkas inte. |
| Spärrlista | Personer som CoWeb har spärrat (`https://sso.reklamco.se/api/wp-sso/sparrade`) förlorar roll, applikationslösenord och sessioner vid nästa API-anrop, inloggning eller sidvisning, och kan inte logga in. Listan innehåller bara hashar av `oid` eller UPN, cachas i fem minuter och kan bara neka. Går den inte att hämta gäller den senast hämtade. Rollen kommer tillbaka vid nästa inloggning när spärren tagits bort. Gäller bara SSO-kopplade konton. |
| Sessioner | Personal loggas ut efter 10 timmar. |

Kundernas användare påverkas inte. Pluginet skriver aldrig ut något i sidinnehållet, så Beaver Builder och Gutenberg påverkas inte.

Pluginet är avstängt, och lösenordsinloggningen öppen, så länge tenant-id och client-id är nollor i `rco-sso.php` eller `RCO_SSO_DISABLE` är satt.

## Installation på en sajt

1. Ta en databasbackup.
2. Lägg in sajten i CoWebs register (`coweb.wp_sites`). Värdnamnet ska vara exakt det som står i sajtens `home_url`, med eller utan `www`.
3. Installera pluginet i `wp-content/plugins/rco-sso/` via WP Toolkit och aktivera det.
4. Skapa ett nödkonto med en adress utanför `@reklamco.se` och lägg lösenordet i byråns lösenordshanterare.
5. Logga in med knappen och kontrollera att rätt roll sätts.
6. Gå igenom sajtens användare. Gamla delade byråkonton tas bort eller får en `@reklamco.se`-adress. Konton med andra adresser går förbi SSO.
7. Kör testchecklistan nedan.

## Nödläge

- **Entra eller CoWeb ligger nere:** logga in med nödkontot eller med WP Toolkits inloggningsknapp.
- **Pluginet krånglar:** `define( 'RCO_SSO_DISABLE', true );` i `wp-config.php` stänger av allt och öppnar lösenordsinloggningen igen. Ta bort raden när felet är löst.

## Test

Tokenkontrollen testas utan WordPress:

```sh
php tests/test-token.php
```

Hela inloggningen testas mot en lokal WordPress (`tests/test-e2e.php`, 63 tester). En egen testnyckel läggs i transienten för Microsofts nycklar, så inget går mot Microsoft eller CoWeb. Uppsättning:

1. Ladda ner WordPress, WP-CLI och pluginet SQLite Database Integration, och lägg `db.copy` från pluginet som `wp-content/db.php`.
2. Länka in pluginet: `ln -s <rco-sso> wp-content/plugins/rco-sso`.
3. `wp config create` med `RCO_SSO_TENANT_ID` = `11111111-2222-3333-4444-555555555555`, `RCO_SSO_CLIENT_ID` = `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee` och `WP_ENVIRONMENT_TYPE` = `local`.
4. `wp core install --url=http://127.0.0.1:8099 --admin_user=kundadmin --admin_password=kundpass123 …`, `wp plugin activate rco-sso` och `wp user create byran byran@reklamco.se --role=administrator`.
5. Kopiera `tests/fixtures/bb-ai-simulator.php` till `wp-content/mu-plugins/`. Den gör det Beaver Builder AI gör med sina token och får aldrig ligga på en riktig sajt.
6. Spärrlistan serveras lokalt: `wp config set RCO_SSO_BLOCKLIST_URL 'http://127.0.0.1:8098/sparrade.json' --type=constant` och `php -S 127.0.0.1:8098 -t <tom mapp>`. Testet skriver listan i mappen.
7. `php -S 127.0.0.1:8099 -t <wordpress>` och sedan `BLOCKLIST_DIR=<tom mapp> php tests/test-e2e.php <wordpress>`.

Senast körd 2026-11-20 mot WordPress 7.1.5 och PHP 8.5: alla 63 gick igenom.

### Testchecklista på testsajten

- [ ] Inloggning i ett privat fönster: rätt roll sätts och man hamnar på rätt sida.
- [ ] Befintligt personalkonto kopplas ihop och inget dubbelkonto skapas. Gamla sessioner loggas ut.
- [ ] Andra inloggningen hittar kontot via `oid` även om e-postadressen ändrats.
- [ ] Rollbyte i Entra slår igenom vid nästa inloggning.
- [ ] Person utan tilldelning nekas hos Microsoft. Sajt som inte finns i registret nekas i CoWeb.
- [ ] Samma token postad två gånger nekas andra gången.
- [ ] Inloggning som tar mer än tio minuter ger meddelandet om att försöka igen.
- [ ] Personalkonto med korrekt lösenord på wp-login.php nekas.
- [ ] "Glömt lösenord" fungerar inte för personalkonto, inte heller i WooCommerce.
- [ ] Kundens redaktör loggar in med lösenord som vanligt. Nödkontot fungerar.
- [ ] MCP (Beaver Builder AI): revisionen står på det personliga kontot.
- [ ] 30-dagarsregeln: sätt `rco_sso_last_login` och `rco_sso_linked` 31 dagar bakåt och kontrollera att MCP nekas och fungerar igen efter en SSO-inloggning.
- [ ] Safari, Firefox med strikt spårningsskydd, Chrome och mobil.

## Kvar till v1.0

- Riktiga värden för tenant-id och client-id (när appregistreringen finns).
- Uppdaterare från GitHub med signerade releaser (steg 5 i specen).
- Om inloggningen visas i WordPress ruta för "logga in igen" i adminpanelen fungerar knappen troligen inte där, eftersom Microsoft inte kan visas i en ram. Behöver provas.
