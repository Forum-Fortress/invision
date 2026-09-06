# Local OAuth registration testing

The fixture in this directory exercises first-time social/OAuth registration
through IPS's native Custom OAuth 2 handler. It contains only synthetic identities
under `example.invalid` and must never be exposed to the public internet.

## Start and configure

```bash
FF_IPS_OAUTH_STATE=/tmp/ff_ips_oauth_fixture_state.json \
  php -S 0.0.0.0:18182 plugins/invision/tests/oauth_fixture.php

FF_IPS_ROOT=/var/www/html/ipb \
  php plugins/invision/tests/oauth_setup.php install
```

The IPS callback URL is
`http://192.168.50.203/ipb/oauth/callback/`. Open the community sign-in page and
choose **Continue with Local OAuth**. The provider offers allow, rejected-account
and delete-account identities. Before the latter two tests, select the matching
Forum Fortress blocked-registration action in AdminCP.

The provider requires OAuth state, authorization-code flow, HTTP Basic client
authentication and PKCE S256. Authorization codes are single-use and expire after
five minutes. Access tokens expire after ten minutes.

## Remove test data

```bash
FF_IPS_ROOT=/var/www/html/ipb \
  php plugins/invision/tests/oauth_setup.php cleanup
```

Cleanup removes only the handler with client ID `forumfortress-local-oauth`, its
login links, associated custom labels and synthetic members whose email matches
`ff.oauth.%@example.invalid`. It also removes synthetic account-creation metadata
identified through that handler if a deliberately deleted test member no longer
exists.
