/*
 * memphis-connect.js — sign a user in from an app on ITS OWN domain.
 *
 *     <script src="./memphis-connect.js"></script>
 *
 *     const who = await memphis.connect({ app: "My App" });
 *     // who.token is an ORIGIN-SCOPED session token. Pass it to your contract.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY THIS EXISTS, AND WHY passkey.js CANNOT DO IT
 * ────────────────────────────────────────────────────────────────────────────
 * A WebAuthn credential is bound to a Relying Party ID, and a page may only
 * claim an RP ID that is a registrable-domain suffix of its own origin. Memphis
 * anchors live under one RP ID. So a page served from `my-app.com` physically
 * cannot run the Memphis passkey ceremony — the browser refuses before any of
 * our code runs. `passkey.js` works only on the Memphis origin itself.
 *
 * This module is the way across that wall. The ceremony happens in a window at
 * the Memphis origin; that window attenuates the master session into a token
 * minted for YOUR origin and hands back only that. Your app never sees a master
 * token, and nothing needs allowlisting — which is why this works for any number
 * of apps on any domain, including ones we have never heard of.
 *
 * This is the same shape as Internet Identity's per-frontend delegation and as
 * OAuth's `aud` claim (RFC 9068): a credential that names the audience it is for
 * and is refused everywhere else.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THE SECURITY PROPERTY, STATED SO IT CANNOT BE QUIETLY BROKEN
 * ────────────────────────────────────────────────────────────────────────────
 * A page may LIE about its origin in the request. It gains nothing, because the
 * answer is delivered ONLY to the origin it claimed:
 *
 *   • popup mode    — `postMessage(payload, RETURN_TO)`, never `"*"`. The
 *                     browser refuses delivery when the opener's real origin is
 *                     not RETURN_TO. The liar gets silence.
 *   • redirect mode — the browser is navigated to a return URL that must be
 *                     same-origin as the claimed origin. The credential lands on
 *                     the victim's own page, where the liar cannot read it.
 *
 * Both properties are the browser's to enforce, not ours, which is what makes
 * them worth relying on. If you ever find yourself widening the target origin to
 * `"*"`, or accepting a return URL on a different origin than the claimed one,
 * you have removed the only thing protecting every app on the chain.
 *
 * ⚠️ In redirect mode the token arrives in the URL FRAGMENT, never the query
 * string, so it is not sent to your server and does not appear in a `Referer`
 * header or an access log. If your app has an open redirect, it can bounce that
 * fragment to an attacker — the same failure OAuth deployments have had for
 * fifteen years. Validate your own return paths.
 */
(function (global) {
  "use strict";

  var CONNECT_URL = "https://memphis.mercaturaforum.com/connect/";
  var WIDTH = 420, HEIGHT = 620;
  var STORE_PREFIX = "memphis.connect.session.";
  var PENDING_KEY = "memphis.connect.pending";
  var FRAGMENT_KEY = "memphis=";

  // A scoped token can never outlive 30 real minutes (the contract clamps to
  // MAX_SCOPED_SESSION_TTL_NS, and to the parent session's remaining life). The
  // page is told the PARENT's expiry, which is an upper bound; we take the
  // tighter of the two so a locally-cached session is never optimistic.
  var MAX_SCOPED_MS = 30 * 60 * 1000;

  function storeKey(app) { return STORE_PREFIX + global.location.origin + "|" + app; }

  function nowMs() { return Date.now(); }

  function persist(app, who) {
    try { global.localStorage.setItem(storeKey(app), JSON.stringify(who)); } catch (_) {}
  }

  /**
   * The stored record for `app`, expired or not, or null if absent/unparseable.
   *
   * Separate from `loadSession` because an EXPIRED access token is exactly when
   * the refresh credential matters most: gating this read on the access expiry
   * would throw away the one thing that can get the person back in without a
   * passkey ceremony.
   */
  function readStored(app) {
    if (!app) return null;
    var raw;
    try { raw = global.localStorage.getItem(storeKey(app)); } catch (_) { return null; }
    if (!raw) return null;
    try {
      var who = JSON.parse(raw);
      return who && who.token ? who : null;
    } catch (_) { clearSession(app); return null; }
  }

  /** True while the refresh credential can still be exchanged. */
  function canRenew(who) {
    if (!who || !who.refreshToken) return false;
    var t = nowMs();
    if (who.refreshExpiresAtMs && who.refreshExpiresAtMs <= t) return false;
    if (who.refreshAbsoluteExpiresAtMs && who.refreshAbsoluteExpiresAtMs <= t) return false;
    return true;
  }

  /** The stored session for `app`, or null if absent, unparseable or expired. */
  function loadSession(app) {
    var who = readStored(app);
    if (!who) return null;
    if (!who.expiresAtMs || who.expiresAtMs <= nowMs()) {
      // Keep the record when it still carries a usable refresh credential:
      // `renew()` needs it. Only a record that can do nothing at all is cleared.
      if (!canRenew(who)) clearSession(app);
      return null;
    }
    return who;
  }

  /**
   * Trade the stored refresh credential for a fresh access token, silently.
   *
   * No window, no gesture, no passkey prompt — this is what "stay signed in for
   * a week" actually is. Returns the new session, or null when there is nothing
   * to renew from, in which case the caller should ask for a real sign-in.
   *
   * Requires `passkey.js`, which owns the Memphis transport. A page that only
   * loads this file can still sign in; it just cannot renew silently.
   *
   * ⚠️ The old refresh token is dead the moment the exchange returns, and
   * presenting it again revokes the entire chain. So the new pair is persisted
   * before this resolves, and a failed write is treated as a failed renewal
   * rather than being ignored — a chain we cannot record is a chain we have
   * already lost.
   */
  function renew(app) {
    var who = readStored(app);
    if (!canRenew(who)) {
      if (who && !who.expiresAtMs) clearSession(app);
      return Promise.resolve(null);
    }
    var pk = global.MemphisPasskey;
    if (!pk || typeof pk.exchangeRefresh !== "function") {
      return Promise.resolve(null);   // passkey.js absent; sign in the long way
    }
    return pk.exchangeRefresh(who.refreshToken, global.location.origin)
      .then(function (r) {
        var next = {
          app: app,
          name: who.name,
          anchorId: who.anchorId,
          token: r.scoped_token_hex,
          origin: global.location.origin,
          expiresAtMs: expiryMsFrom(r.expires_at_ns),
          refreshToken: r.refresh_token_hex,
          refreshExpiresAtMs: msFromNs(r.refresh_expires_at_ns),
          // The chain ceiling never moves, so it is carried, not re-read.
          refreshAbsoluteExpiresAtMs: who.refreshAbsoluteExpiresAtMs || 0,
        };
        persist(app, next);
        return next;
      })
      .catch(function () {
        // A refused exchange means the chain is gone — lapsed, revoked, or
        // revoked BECAUSE this token was replayed. Either way it will never
        // work again, so drop it rather than retrying into the same wall.
        clearSession(app);
        return null;
      });
  }

  function clearSession(app) {
    try { global.localStorage.removeItem(storeKey(app)); } catch (_) {}
  }

  /**
   * Local sign-out: forget the scoped token held by THIS app.
   *
   * It does not end the person's Memphis session — this app cannot, and should
   * not be able to. `end_session` is caller-scoped on Memphis, so ending the
   * underlying session is the Memphis origin's job, reached through the connect
   * window. Signing out here means "this app forgets you", which is what an app
   * is entitled to do.
   */
  function signOut(app) { clearSession(app); }

  /** Milliseconds from now until this credential must not be used again. */
  function expiryMsFrom(expiresAtNs) {
    var cap = nowMs() + MAX_SCOPED_MS;
    var parsed = Number(expiresAtNs);
    if (!expiresAtNs || !isFinite(parsed) || parsed <= 0) return cap;
    var parentMs = Math.floor(parsed / 1e6);          // ns -> ms
    return Math.min(cap, parentMs);
  }

  /** Nanoseconds on the wire to milliseconds locally; 0 when absent. */
  function msFromNs(ns) {
    var n = Number(ns);
    return (!ns || !isFinite(n) || n <= 0) ? 0 : Math.floor(n / 1e6);
  }

  function sessionFrom(app, d) {
    return {
      app: app,
      name: d.name,
      anchorId: d.anchor_id_hex,
      token: d.scoped_token_hex,
      origin: d.origin,
      expiresAtMs: expiryMsFrom(d.expires_at_ns),
      // Absent when Memphis predates P4, or when issuing the chain failed. The
      // session still works; it just cannot renew without another ceremony.
      refreshToken: d.refresh_token_hex || null,
      refreshExpiresAtMs: msFromNs(d.refresh_expires_at_ns),
      refreshAbsoluteExpiresAtMs: msFromNs(d.refresh_absolute_expires_at_ns)
    };
  }

  function buildUrl(connectUrl, app, opts, extra) {
    var url = connectUrl
      + "?app=" + encodeURIComponent(app)
      + "&origin=" + encodeURIComponent(global.location.origin);
    // `handle` is a PREFILL ONLY, for an app that already asked the customer for
    // one so they are not made to type it twice. The connect page still owns the
    // field and the person may change it. Nothing is authorised by it.
    if (opts.handle) url += "&handle=" + encodeURIComponent(String(opts.handle).trim());
    return url + (extra || "");
  }

  // ── Redirect mode ─────────────────────────────────────────────────────────

  /**
   * Navigate the top-level window to the connect page and come back.
   *
   * Used when a popup is blocked — the common case inside an in-app browser
   * (Instagram, LinkedIn, a WebView) and under iOS Safari's stricter gesture
   * rules. This call does not return: the page is being navigated away. Call
   * `memphis.resume()` on load to collect the answer.
   */
  function connectViaRedirect(app, opts) {
    var connectUrl = opts.connectUrl || CONNECT_URL;
    // Same-origin by construction: the return URL is built from this page's own
    // location, so it can never point somewhere the connect page would refuse.
    var returnTo = opts.returnTo
      ? new URL(opts.returnTo, global.location.href).href
      : global.location.href;
    if (new URL(returnTo).origin !== global.location.origin) {
      throw new Error("memphis.connect: returnTo must be on this app's own origin");
    }
    try { global.sessionStorage.setItem(PENDING_KEY, app); } catch (_) {}
    var url = buildUrl(connectUrl, app, opts,
      "&mode=redirect&return=" + encodeURIComponent(returnTo));
    global.location.assign(url);
    // Never resolves; the document is being replaced.
    return new Promise(function () {});
  }

  /**
   * Collect the answer after a redirect-mode sign-in. Safe to call on every
   * page load, and safe to call when there is nothing to collect.
   *
   * Returns the session, or null when this load is not a return from connect.
   * The fragment is stripped either way, so a token is never left sitting in the
   * address bar to be copied into a bug report or a shared link.
   */
  function resume() {
    var frag = global.location.hash || "";
    var at = frag.indexOf(FRAGMENT_KEY);
    if (at < 0) return null;

    var encoded = frag.slice(at + FRAGMENT_KEY.length);
    var amp = encoded.indexOf("&");
    if (amp >= 0) encoded = encoded.slice(0, amp);

    // Strip the fragment before anything can throw, so a malformed payload
    // cannot leave a credential in the URL bar.
    try {
      global.history.replaceState(null, "", global.location.pathname + global.location.search);
    } catch (_) { global.location.hash = ""; }

    var pending = null;
    try {
      pending = global.sessionStorage.getItem(PENDING_KEY);
      global.sessionStorage.removeItem(PENDING_KEY);
    } catch (_) {}

    var d;
    try { d = JSON.parse(decodeURIComponent(encoded)); } catch (_) { return null; }
    if (!d || d.__memphis !== 1) return null;
    // The app name we started with must be the one that came back. Without this
    // a stale fragment, or one pasted from another tab, would resolve as a
    // sign-in to a different app.
    if (pending && d.app !== pending) return null;
    if (!d.ok || !d.scoped_token_hex) return null;

    var who = sessionFrom(d.app, d);
    persist(d.app, who);
    return who;
  }

  // ── Popup mode ────────────────────────────────────────────────────────────

  function connectViaPopup(app, opts) {
    var connectUrl = opts.connectUrl || CONNECT_URL;
    var timeoutMs = opts.timeoutMs || 120000;

    // ── The popup is opened SYNCHRONOUSLY, right here ──────────────────────
    // Not after an await, not in a .then. iOS Safari only allows a popup that
    // opens inside the user gesture that triggered it, and an `await` before
    // this line ends the gesture. This is the single most common way a working
    // implementation of this pattern stops working on iPhone, and a later
    // refactor that "tidies" it into an async helper will silently break it.
    var left = Math.max(0, (global.screen.width - WIDTH) / 2);
    var top = Math.max(0, (global.screen.height - HEIGHT) / 2);
    // No `location=no`: the address bar is the anti-phishing control. A user
    // must be able to see they are on the Memphis origin before they present a
    // fingerprint.
    var win = global.open(buildUrl(connectUrl, app, opts), "memphis-connect",
      "width=" + WIDTH + ",height=" + HEIGHT + ",left=" + left + ",top=" + top +
      ",resizable=yes,scrollbars=yes");

    if (!win) {
      var blocked = new Error("The sign-in window was blocked.");
      blocked.code = "POPUP_BLOCKED";
      return Promise.reject(blocked);
    }

    return new Promise(function (resolve, reject) {
      var done = false;

      function finish(fn, arg) {
        if (done) return;
        done = true;
        global.removeEventListener("message", onMessage);
        clearInterval(poll);
        clearTimeout(timer);
        try { if (win && !win.closed) win.close(); } catch (_) {}
        fn(arg);
      }

      function onMessage(ev) {
        // Two checks, both exact. The origin must be the Memphis origin the
        // popup was opened at — never a prefix or suffix test — and the message
        // must carry our marker and our app name, so a stray message from
        // another Memphis tab cannot resolve this call.
        if (ev.origin !== new URL(connectUrl).origin) return;
        var d = ev.data;
        if (!d || d.__memphis !== 1 || d.app !== app) return;

        if (d.ok) {
          var who = sessionFrom(app, d);
          persist(app, who);
          finish(resolve, who);
        } else {
          var err = new Error(d.reason === "closed"
            ? "Sign-in was cancelled."
            : (d.reason || "Sign-in did not complete."));
          err.code = d.reason === "closed" ? "CANCELLED" : "FAILED";
          finish(reject, err);
        }
      }

      global.addEventListener("message", onMessage);

      // A user can close the window without it telling us, so poll for it.
      var poll = setInterval(function () {
        if (win.closed) {
          var cancelled = new Error("Sign-in was cancelled.");
          cancelled.code = "CANCELLED";
          finish(reject, cancelled);
        }
      }, 400);

      var timer = setTimeout(function () {
        var timedOut = new Error("Sign-in timed out.");
        timedOut.code = "TIMEOUT";
        finish(reject, timedOut);
      }, timeoutMs);
    });
  }

  // ── The one call an app makes ─────────────────────────────────────────────

  /**
   * Sign a user in and return an origin-scoped session for this app.
   *
   *   memphis.connect({ app: "My App" })
   *     -> { app, name, anchorId, token, origin, expiresAtMs }
   *
   * Options:
   *   app         (required) the name shown to the person in the connect window
   *   mode        "popup" (default) | "redirect" | "auto"
   *               "auto" opens a popup and falls back to a full-page redirect
   *               when the browser blocks it.
   *   handle      prefill for the handle field; authorises nothing
   *   returnTo    redirect mode only; must be on this app's own origin
   *   connectUrl  override the Memphis connect page (tests, staging)
   *   timeoutMs   popup mode only; default 120000
   *   reuse       false to force a fresh ceremony even if a live token is held
   *
   * MUST be called inside a user gesture (a click). A popup opened outside one
   * is blocked, and a redirect outside one is a navigation the person did not
   * ask for.
   */
  function connect(opts) {
    opts = opts || {};
    var app = String(opts.app || "").trim();
    if (!app) return Promise.reject(new Error("memphis.connect: an `app` name is required"));

    if (opts.reuse !== false) {
      var held = loadSession(app);
      if (held) return Promise.resolve(held);
    }

    var mode = opts.mode || "popup";
    if (mode === "redirect") {
      try { return connectViaRedirect(app, opts); }
      catch (e) { return Promise.reject(e); }
    }

    var attempt = connectViaPopup(app, opts);
    if (mode !== "auto") return attempt;

    return attempt.catch(function (e) {
      if (e && e.code === "POPUP_BLOCKED") return connectViaRedirect(app, opts);
      throw e;
    });
  }

  global.memphis = global.memphis || {};
  global.memphis.connect = connect;
  global.memphis.resume = resume;
  global.memphis.loadSession = loadSession;
  global.memphis.renew = renew;
  global.memphis.signOut = signOut;
})(typeof window !== "undefined" ? window : this);
