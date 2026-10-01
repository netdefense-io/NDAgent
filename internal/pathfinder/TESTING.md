# Testing internal/pathfinder

## HandleStream tests and the context-cancellation false-pass trap

`HTTPProxy.HandleStream` (`httpproxy.go`) ties each request's `context.Context` to
the stream's lifetime: a goroutine calls `cancel()` the instant `stream.CloseChan()`
fires. Closing the stream is not neutral teardown — it actively aborts any request
still in flight via `forwardRequest`.

This matters for any `HandleStream`-level test asserting that a request was
**never** forwarded to the backend (e.g. a read-only bypass check). A test that
closes the stream immediately after capturing the expected response can falsely
pass even when the bypass bug is real: closing the stream cancels the context,
which aborts the in-flight (buggy) `forwardRequest` call before it reaches the
backend. The test then observes "backend never hit" and reports success — but
that's the cancellation racing the bug, not proof the bug doesn't exist.

**Fix:** hold the stream open through a bounded confirmation window before closing
it, and only close after that window elapses with no forwarded request observed.
That gives a real bypass enough time to actually complete and get caught.

See `assertSentinelNeverHitWithin` in `httpproxy_test.go` for the helper, and
`TestHandleStream_ReadOnlyBlocksServiceRestart_DoesNotForward` /
`TestHandleStream_ReadOnlyBlocksFlushStates_DoesNotForward` /
`TestHandleStream_ReadOnlyRefusesBypassVariants_DoesNotForward` for it in use: all
hold the stream open for a window before closing, and assert on the sentinel
backend's hit-count rather than just the HTTP status, so a forward that raced the
close can't hide behind an otherwise-correct refusal.

A refusal in a read-only session ends the exchange on its stream (the response
says `Connection: close` and the proxy reads nothing more as a request), so a test
that sends several refused requests gives each one a stream of its own;
`assertRefusedOnStreams` runs them side by side and shares one confirmation window.
It also checks that the proxy left the stream for the client to close: a CLOSE
frame right behind a reply can lose the reply in the client's tunnel. A request
whose target names a host is checked against a second backend as well: the
refusal must not have reached it either.

## Replies the proxy writes itself

The frame capture of these tests sees every byte the proxy wrote, whatever a real
client gets of them. What reaches a client depends on when the proxy sends CLOSE:
ndcli's tunnel queues the frames it receives and, when a CLOSE arrives, can drop
the ones it has not handed to its reader yet. `readonly_reply_delivery_test.go`
puts every kind of refusal, and a withheld response, through a relayed session to
`tunnelClient`, which delivers frames the way ndcli's tunnel does, over a real TCP
connection, many times in each connection mode (one client reads the response by
its length and closes, the other reads until the connection ends). A proxy that
sends CLOSE right behind its reply loses replies there, how many depends on
timing; the `closeSent` checks of the frame-capture tests are what catch it
deterministically.

## Request bodies the transport still holds

An upstream can answer before it has read a request's body. The transport then
returns the response and goes on reading the body from the stream's reader, and
closes it, after reading the rest, once the connection goes. Nothing else may read
the stream until that Close: `transportBody` reports it, and `endAfterReply`
starts discarding only after it. `readonly_withheld_body_test.go` answers a
scrubbed route before reading a large body and withholds the answer; a proxy that
reads the stream at once fails it under `-race`.
`TestEndAfterReply_ReadsNothingUntilTheBodyIsReleased` pins the same rule without
the race detector, and that a client that keeps sending meanwhile holds up neither
the session's frame loop nor another stream.

## Re-auditing the read-only route denylist

`readonly_routes.go` is a snapshot of what an audit of OPNsense found reachable
through the read-only group's ACL and acting without a `user-config-readonly`
check, or handing out private keys. Repeat the audit when a new OPNsense release
ships or `READONLY_PRIVS` changes. Against the core tree (`git archive <tag>
src/opnsense/mvc src/www`) of every supported release and `master`:

1. The `ACL.xml` patterns of every `READONLY_PRIVS` id, plus the two masks
   `ACL::urlMasks()` always yields (`index.php?logout`, `api/core/menu/*`).
2. Every public `*Action` of every `Api` controller and its bases, mapped to URLs
   with the router's rules (`Router::parsePath`: case and underscores ignored in
   the action, empty segments skipped, no percent-decoding).
3. For each reachable action, whether a state-changing configd action,
   `Config::save()` or a file or exec write happens before `throwReadOnly()` or a
   `user-config-readonly` check. Read the code for effects hidden behind other
   objects (voucher generation goes through `AuthenticationFactory`). A string
   mention of `user-config-readonly` is not a guard: `dismissStatusAction` asks
   `isPageAccessible(...) || !hasPrivilege('user-config-readonly')`, which lets
   through a group that holds the page. Only `SystemController` and
   `DashboardController` use the string outside the base classes; read both. Count
   file writes as well: `setrouteAction` and `VipSettings::setItemAction` write a
   `delete_*.todo` file, and they do it for a GET. A statement that follows a base
   helper (`delBase`, `setBase`) is reached whatever the helper answered unless the
   code tests the answer: `CaController::delAction` runs `system trust configure`
   after `delBase` with no test, and `delBase` does nothing on a GET.
4. Each reachable action run as the read-only user against a stubbed `Backend`,
   with GET and with POST, and with `$_POST` populated on a non-POST method:
   `ApiControllerBase::parseJsonBodyData` fills `$_POST` from any JSON body, so a
   handler that checks `hasPost()` and not `isPost()` acts on OPTIONS. Run it
   against a config that holds what the handler looks up (a route, an address, a
   CA, a user, a certificate): an action that finds nothing does nothing, and the
   first audit's empty config hid the GET-acting route and VIP edits. Back the run
   with a static pass over the bodies: every reachable action that reaches
   `configdRun`, `configdpRun`, `file_put_contents`, `touch`, `unlink` or an exec
   with no `isPost()`, `hasPost()` or `throwReadOnly()` in it is read by hand.
5. About a million spelling variants per release (case, underscores in every
   segment, repeated slashes, dot segments, percent-encoding, query, fragment,
   trailing segments) fed to the real `Router::parsePath`, `Dispatcher::canExecute`
   and `ACL::isPageAccessible` for the `netdefense-readonly` group, and through
   `http.ReadRequest` to `readOnlyRefusal` with each method, with and without a
   body: no variant that reaches a mutating handler may be forwarded.
6. Every reachable action that returns or exports private key material, which is
   refused outright (`handsOutPrivateMaterial`): read what each `generate_file`,
   `download` and `export` returns, and which script a configd-backed read runs
   (`ipsec get swanctl` reads `/usr/local/etc/swanctl/swanctl.conf`, whose
   `secrets` section holds the pre-shared keys; `trust/cert/generate_file` with
   `prv` or `pkcs12` returns the key).
7. The legacy pages in `src/www` that the group's patterns reach. They are not
   routed like the API: lighttpd percent-decodes the path and resolves dot segments
   before it picks the script, and the page authorises on the resulting
   `SCRIPT_NAME`. Check targets against a real lighttpd built with OPNsense's alias,
   rewrite and fastcgi settings (`src/etc/inc/plugins.inc.d/webgui.inc`) and
   php-cgi, not against a model of it. Read the pages for POST handlers that act
   outside `write_config()`, and for GET handlers that act
   (`status_wireless.php?rescanwifi=1` runs `ifconfig <if> scan`).

New routes go into `mutatingRoutes` (or `anyMethodRoutePattern` when the handler
acts on any method) and into `auditedMutatingRoutes` in `readonly_routes_test.go`,
which pins every route of the last audit as a literal path.

## Re-auditing the secret scrubber

`readonly_scrub.go` is a snapshot of what an audit found carrying a secret on
the routes the read-only group can GET or search. Repeat it with the route audit
above, against the same trees (and the plugins the group holds privileges of:
os-isc-dhcp, os-tailscale, os-qemu-guest-agent):

1. The fields that hold a secret, in every model XML under
   `src/opnsense/mvc/app/models`. Read the whole field list of every model a
   reachable controller binds (`$internalModelClass`), not only the names that
   look like a password: a field is a secret by what it stores
   (`UpdateOnlyTextField`, `ApiKeyField`, `Base64Field` keys, `prv`, pre-shared
   keys, the TSIG secrets of DHCP, RADIUS shared secrets, URLs that take
   credentials). List the leaf field names of each model with a short XML walk
   and diff the field sets of the releases.
2. How each one reaches a response. `searchBase` returns every flat field of a
   row as `getValue()` whatever columns the controller passes (`UIModelGrid::fetch`
   uses them only to match the search phrase), so a grid row carries an
   update-only password as its hash. `getBase` and the inherited `getAction`
   return `getNodes()`, which casts a field to a string: update-only and API-key
   fields arrive empty, plain text fields arrive whole, and a controller may add
   a computed copy (`auth/user/get` builds `otp_uri` from the seed). The
   dotted name of a nested field in a grid row (`wpa.passphrase`) is not the name
   in a form (`passphrase`): name both. The inherited `getAction` returns the
   whole model, so the keys of a model apply to every route of its controllers.
3. The non-model reads: for every reachable action that calls configd or reads
   a file, the script it runs and what it prints (`ipsec list sad` parses
   `setkey -D`, whose `E:` and `A:` lines are the SA keys; `wireguard show` leaves
   private and pre-shared keys out on purpose; `ipsec get swanctl` prints the
   config with its secrets, and is refused). CSV exports go through `asRecordSet`,
   which casts fields to strings.
4. The legacy pages: every `value="<?=$pconfig['...']?>"` (and textarea) whose
   field is a secret, and whether the page runs `legacy_html_escape_form_data`
   over what it renders: the scrubber reads a tag the way a browser does and
   relies on that escaping.
5. The request side of every grid a rule scrubs. A response with its secrets
   blanked does not hide them from a search of the rows: `UIModelGrid::fetch`
   matches the search phrase against every field it is given, secret included,
   and `searchBase(path)` with no columns gives it all of them, so which rows come
   back reads the secret. The proxy lets that search through (accepted, see "Left
   open on purpose" below), so for each scrubbed route that is a grid read the
   controller's `searchBase`/`searchRecordsetBase` call (columns named and free of
   secrets, or every field) and list a grid of the second kind among the routes of
   the residual in CLAUDE.md. Then read what else the request can be: whether the
   route answers a HEAD with the length of a body it does not send (refused by
   `readOnlyRefusal`), and whether any request variable other than the phrase
   names a secret field (`sort` only orders the rows).
6. Pin the result: a response of the right shape for each route goes into
   `scrubCases` (JSON) or `htmlCases` (a page), with a marker in every secret
   and the values that must stay. The tests then run each case through
   `scrubResponse` and through `HandleStream`, and fail on a rule no case
   exercises and on a route a rule selects twice. A case that POSTs to a
   `search*` action and plants a secret is also searched for that secret through
   `HandleStream` (`TestHandleStream_ReadOnlyForwardsASearchOfRowsThatHoldASecret`),
   which pins that the search is forwarded and the answer cleaned. The engine
   tests compare `scrubJSON` with an independent reference on random documents
   and fuzz both engines.

### Left open on purpose

Accepted by the operator (review of #104, 2026-09-30); an audit does not report
these again as findings:

- **A grid's search is forwarded.** The grid matches the phrase against the stored
  fields of a row, secret included, before the proxy blanks anything, so a patient
  read-only user can infer a hidden stored value (a password hash, an OTP seed, a
  pre-shared key, a private key) by guessing through the list search: which rows
  come back says whether the phrase occurs in one, and a phrase grown one character
  at a time reads all of it. The response itself never carries the secret. The
  routes are listed in CLAUDE.md;
  `TestHandleStream_ReadOnlyForwardsASearchOfRowsThatHoldASecret` pins both halves,
  that the search reaches OPNsense untouched and selects the row by its blanked
  secret, and that the answer is still cleaned.
- **Logs and free-text settings stay readable.** The logs (system, firewall,
  service) hold what a component wrote into them, and a credential typed into a
  free-text setting (an alias URL, a cron command, a service start command, a custom
  option and the like) is stored as text no rule can tell from any other. Nothing
  cleans them. The crash reporter, whose output is not cleaned either, stays
  excluded, and so does the packet capture (`READONLY_EXCLUDED_PRIVS`).

What the last audit did not cover, so nobody assumes it did: the routes of plugins
other than the three, and whatever a release added since.
