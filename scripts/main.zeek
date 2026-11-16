@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/http
@load base/frameworks/notice
@load base/utils/strings

module MuseDetector;

export {
    redef enum Log::ID += { LOG };
    redef enum Notice::Type += { Possible_Muse_Activity };

    type Evidence: enum { DNS_Query, TLS_Server_Name, HTTP_Request };
    type IndicatorStatus: enum { Experimental, Capture_Validated };
    # A label supplied by the rule author, never inferred from a shared endpoint.
    type AccessContext: enum { Unknown, Standalone_App, Facebook };

    type Indicator: record {
        domain: string;
        sources: set[Evidence];
        include_subdomains: bool &default=F;
        status: IndicatorStatus &default=Experimental;
        access_context: AccessContext &default=Unknown;
        # All configured HTTP conditions must match. They restrict HTTP only;
        # initialization rejects using them alongside DNS/TLS sources.
        http_path_prefix: string &optional;
        http_user_agent: string &optional;
    };

    # Intentionally empty: no verified Muse indicators are available yet.
    const indicators: table[string] of Indicator = {} &redef;
    const enable_notices = F &redef;
    const notice_suppression = 1hr &redef;

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        evidence: Evidence &log;
        hostname: string &log;
        indicator_id: string &log;
        indicator_status: IndicatorStatus &log;
        access_context: AccessContext &log;
        assessment: string &log &default="possible_muse_activity";
        # These distinguish lookup/handshake observations from success.
        dns_rcode: count &log &optional;
        tls_established: bool &log &optional;
        http_status_code: count &log &optional;
    };

    global log_muse: event(rec: Info);
}

# Only validated configuration is used. No address cache or per-host history.
global active_indicators: table[string] of Indicator = {};

function normalize_domain(value: string): string
    {
    return sub(to_lower(value), /\.$/, "");
    }

function valid_domain(value: string): bool
    {
    # ASCII DNS labels only. Wildcards, URLs, IP literals and ports are invalid.
    if ( |value| > 253 || ! (/\./ in value) || /^[0-9.]+$/ == value )
        return F;
    local labels = split_string(value, /\./);
    for ( i in labels )
        if ( |labels[i]| > 63 ||
             ! (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/ == labels[i]) )
            return F;
    return T;
    }

function domain_matches(hostname: string, rule: Indicator): bool
    {
    return hostname == rule$domain ||
           (rule$include_subdomains && ends_with(hostname, fmt(".%s", rule$domain)));
    }

function emit_match(rec: Info)
    {
    Log::write(LOG, rec);
    if ( enable_notices )
        NOTICE([$note=Possible_Muse_Activity,
                $msg=fmt("Possible Muse activity: %s matched %s (%s)",
                         rec$hostname, rec$indicator_id, rec$evidence),
                $uid=rec$uid, $id=rec$id,
                $identifier=fmt("%s|%s|%s", rec$id$orig_h,
                                rec$indicator_id, rec$evidence),
                $suppress_for=notice_suppression]);
    }

event zeek_init() &priority=5
    {
    Log::create_stream(LOG, [$columns=Info, $ev=log_muse, $path="muse"]);
    for ( key in indicators )
        {
        local rule = indicators[key];
        rule$domain = normalize_domain(rule$domain);
        if ( key == "" || ! valid_domain(rule$domain) || |rule$sources| == 0 ||
             (rule?$http_path_prefix &&
              (! starts_with(rule$http_path_prefix, "/") || /[?#]/ in rule$http_path_prefix)) ||
             (rule?$http_user_agent && rule$http_user_agent == "") ||
             ((rule?$http_path_prefix || rule?$http_user_agent) &&
              (DNS_Query in rule$sources || TLS_Server_Name in rule$sources)) )
            {
            Reporter::error(fmt("MuseDetector: invalid indicator configuration: %s", key));
            next;
            }
        active_indicators[key] = rule;
        }
    if ( |active_indicators| == 0 )
        Reporter::warning("MuseDetector: no active indicators; Muse detection is inactive pending validated configuration");
    }

event DNS::log_dns(rec: DNS::Info)
    {
    # Do not treat a reply seen without its query as a client lookup.
    if ( ! rec?$query || ! rec$saw_query )
        return;
    local hostname = normalize_domain(rec$query);
    for ( key in active_indicators )
        {
        local rule = active_indicators[key];
        if ( DNS_Query !in rule$sources || ! domain_matches(hostname, rule) )
            next;
        local result: Info = [$ts=rec$ts, $uid=rec$uid, $id=rec$id,
                              $evidence=DNS_Query, $hostname=hostname,
                              $indicator_id=key, $indicator_status=rule$status,
                              $access_context=rule$access_context];
        if ( rec?$rcode ) result$dns_rcode = rec$rcode;
        emit_match(result);
        }
    }

event SSL::log_ssl(rec: SSL::Info)
    {
    if ( ! rec?$server_name )
        return;
    local hostname = normalize_domain(rec$server_name);
    for ( key in active_indicators )
        {
        local rule = active_indicators[key];
        if ( TLS_Server_Name !in rule$sources || ! domain_matches(hostname, rule) )
            next;
        emit_match([$ts=rec$ts, $uid=rec$uid, $id=rec$id,
                    $evidence=TLS_Server_Name, $hostname=hostname,
                    $indicator_id=key, $indicator_status=rule$status,
                    $access_context=rule$access_context,
                    $tls_established=rec$established]);
        }
    }

event HTTP::log_http(rec: HTTP::Info)
    {
    if ( ! rec?$host )
        return;
    # Strip an optional decimal port; IPv6 literals will not match DNS rules.
    local hostname = normalize_domain(sub(rec$host, /:[0-9]+$/, ""));
    for ( key in active_indicators )
        {
        local rule = active_indicators[key];
        if ( HTTP_Request !in rule$sources || ! domain_matches(hostname, rule) )
            next;
        if ( rule?$http_path_prefix )
            {
            if ( ! rec?$uri ) next;
            # The raw path only: a query-string value must never satisfy a rule.
            local path = split_string1(rec$uri, /[?#]/)[0];
            if ( ! starts_with(path, rule$http_path_prefix) ) next;
            }
        if ( rule?$http_user_agent &&
             (! rec?$user_agent || rec$user_agent != rule$http_user_agent) )
            next;
        local result: Info = [$ts=rec$ts, $uid=rec$uid, $id=rec$id,
                              $evidence=HTTP_Request, $hostname=hostname,
                              $indicator_id=key, $indicator_status=rule$status,
                              $access_context=rule$access_context];
        if ( rec?$status_code ) result$http_status_code = rec$status_code;
        emit_match(result);
        }
    }
