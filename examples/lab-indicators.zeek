# SYNTHETIC EXAMPLE ONLY. These reserved .invalid names are NOT Muse indicators.
# Loading this file is optional and only useful for laboratory testing.
@load ../scripts

redef MuseDetector::indicators += {
    ["lab-endpoint"] = [$domain="agent.example.invalid",
        $sources=set(MuseDetector::DNS_Query, MuseDetector::TLS_Server_Name),
        $include_subdomains=F],
    ["lab-http"] = [$domain="shared.example.invalid",
        $sources=set(MuseDetector::HTTP_Request),
        $http_path_prefix="/lab-agent/", $http_user_agent="SyntheticAgent/1.0"]
};
