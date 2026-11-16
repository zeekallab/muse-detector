# Muse detector for Zeek

**Experimental development baseline, awaiting real application captures. Version 0.1.0 ships with NO Muse indicators and does not identify Muse out of the box.**

This package is being developed to identify network evidence associated with Meta's Muse, including standalone-app and Facebook access if distinct indicators can be established. It provides tested DNS, TLS and HTTP matching, an auditable `muse.log`, and optional notices. Actual Muse endpoints, app behavior, and the ability to distinguish these access methods have **not** been validated. Neither path currently has detection coverage.

Ordinary Facebook, Instagram, Meta domains, shared IP addresses, browser fingerprints and connection timing are not bundled as Muse indicators. A network match does not establish an installed app, a human interaction, an autonomous action, compromise, or successful data transfer.

## What works today

| Evidence | Matching | Meaning |
| --- | --- | --- |
| DNS query | Exact configured name; optional label-bounded subdomains | Client asked for this name; includes failed lookups |
| TLS server name | Configured visible SNI | Client offered this name; handshake success logged separately |
| Visible HTTP request | Host plus any configured raw path prefix and exact User-Agent | Request matched all configured conditions; response status logged when available |

Every result retains its Zeek `uid`, connection endpoints, indicator ID, indicator status, evidence kind and configured access context. `assessment` is always `possible_muse_activity`. `Capture_Validated` describes the rule author's indicator validation, not confirmed agent use. `Standalone_App` and `Facebook` are author-supplied rule labels; the package does not infer an application from shared infrastructure. Default context is `Unknown`.

Matching uses the standard `DNS::log_dns`, `SSL::log_ssl`, and `HTTP::log_http` events. Results generally arrive when Zeek logs each transaction/session, possibly at connection expiry or end of replay. If a deployment disables a required analyzer or protocol log stream, verify these hooks still execute. DNS reply-only observations are excluded. DNS endpoints identify the observed client and resolver, not the application's eventual server; a recursive resolver seen as a client must not be attributed to an end user.

## Try the package

Requires **Zeek 9 or newer** and Python 3 for tests. Validated locally on Zeek 9.0.1 only; older Zeek versions, Corelight sensors, production load and cluster deployments have not been validated.

```sh
git clone https://github.com/zeekallab/muse-detector.git
cd muse-detector
python3 tests/test_detector.py
zeek -a ./scripts
```

For an offline capture, run from an output directory with the repository's absolute script path:

```sh
zeek -r /absolute/path/session.pcap /absolute/path/muse-detector/scripts /absolute/path/site-muse.zeek
```

Without configured indicators, startup emits a warning explaining that detection is inactive. The synthetic configuration in `examples/lab-indicators.zeek` uses reserved `.invalid` names; **these are not real service endpoints** and the file is never loaded automatically.

## Configure indicators after investigation

Create `site-muse.zeek`, loaded after this package. This example is intentionally synthetic:

```zeek
redef MuseDetector::indicators += {
    ["lab-endpoint"] = [$domain="agent.example.invalid",
        $sources=set(MuseDetector::DNS_Query, MuseDetector::TLS_Server_Name)],
    ["lab-http"] = [$domain="shared.example.invalid",
        $sources=set(MuseDetector::HTTP_Request),
        $http_path_prefix="/lab-agent/",
        $http_user_agent="SyntheticAgent/1.0"]
};
```

Names are compared case-insensitively, with one terminal DNS dot and an HTTP Host port removed. Exact name matching is the default. `$include_subdomains=T` also matches names ending in `.` plus that domain; it does not match deceptive concatenations or suffixes. No IP-based attribution is performed.

HTTP path matching is a literal, case-sensitive prefix against the raw origin-form path, excluding query strings and fragments, with no URL decoding. Use a trailing `/` when a path-segment boundary is required: `/agent/` will not match `/agents/`. User-Agent matching is exact and case-sensitive; a User-Agent can be spoofed. No UA-only rules are supported. A rule containing HTTP conditions must use only `HTTP_Request`; startup rejects mixed DNS/TLS rules that could bypass those conditions. Invalid rules are reported as configuration errors and excluded.

Rules default to `$status=MuseDetector::Experimental` and `$access_context=MuseDetector::Unknown`. Set `Capture_Validated` and an access-context label only after documenting the supporting captures and negative controls in [the indicator ledger](docs/INDICATORS.md).

Optional notices:

```zeek
redef MuseDetector::enable_notices = T;
redef MuseDetector::notice_suppression = 1hr;
```

Notices are disabled by default. When enabled, the standard Notice framework suppresses repetitions for the same originator IP, indicator ID and evidence kind; matching `muse.log` rows remain available. The detector takes no containment action and does not set an external notification destination. Existing site Notice policies govern any handling of notices.

## Encryption and visibility

HTTPS hides HTTP paths, headers and content unless the sensor receives readable/decrypted traffic. This script does not decrypt traffic. DNS-over-HTTPS/TLS, encrypted ClientHello, VPNs and proxies can hide or change the relevant metadata. HTTP/2, HTTP/3/QUIC, HTTP CONNECT tunnels and absolute-form proxy path matching are not specifically implemented or validated. No direct QUIC event handling is included; do not assume TLS-over-TCP tests establish QUIC coverage.

`muse.log` does not copy URLs, query values, User-Agent strings, prompts, bodies, cookies or authorization headers. It does contain matched hostnames, endpoints and connection IDs. Standard Zeek logs retain their own normal fields and may contain sensitive data. Rules themselves should contain only stable, nonsensitive indicators.

## Corelight packaging

The repository includes `zkg.meta` and `scripts/__load__.zeek` for packaging with `zkg`. Review the sensor's embedded Zeek version and validate a package in a lab before deployment. No sensor configuration is changed by this repository or its tests.

Corelight's historical guide, *Installing Scripts on the Corelight Sensor*, describes preparing packages on a workstation and uploading a bundle for sensor validation; it references [Using the Bro Package Manager](https://support.corelight.com/hc/en-us/articles/115014814167-Using-the-Bro-Package-Manager). It uses historical Bro command names; use the commands documented for your installed Corelight release. It also explains that a new bundle replaces the previous bundle, so include all packages that must remain installed. This repository has not been validated on a sensor.

## Validation and next steps

`python3 tests/test_detector.py` generates temporary packet captures using the Python standard library and replays them through the installed Zeek executable. Tests cover DNS results and reply-only traffic, segmented TLS ClientHello and missing SNI, exact versus subdomain matching, deceptive names, source scoping, HTTP conditions, sensitive-field omission, malformed configuration, notice suppression, default inactivity, and explicit access-context labeling. Normal Meta-domain traffic is a negative control against the synthetic rules, not proof of real-world specificity.

See [capture instructions](docs/CAPTURES.md) for the samples needed next. No customer/user capture files, HAR files or application credentials belong in either GitHub repository. Development is maintained in `abousteif/muse-detector`; the distribution repository is `zeekallab/muse-detector`.

License: BSD-3-Clause. This project is not affiliated with or endorsed by Meta or Corelight.
