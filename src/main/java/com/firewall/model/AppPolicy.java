package com.firewall.model;

import java.util.ArrayList; // <<< ADDED THIS IMPORT
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AppPolicy {
    private final String appName;
    private final Set<String> allowedDomains; // Supports wildcards like *.example.com
    private final Set<String> allowedProtocols;
    private final Set<String> allowedIPs;
    private final Action defaultAction;

    public enum Action { ALLOW, DENY }

    public AppPolicy(String appName, Action defaultAction) {
        this.appName = appName;
        this.allowedDomains = new HashSet<>();
        this.allowedProtocols = new HashSet<>();
        this.allowedIPs = new HashSet<>();
        this.defaultAction = defaultAction;
    }

    public void addAllowedDomains(List<String> domains) {
        if (domains != null) {
            for (String domain : domains) {
                this.allowedDomains.add(domain.trim()); // Trim whitespace
            }
        }
    }

    public void addAllowedProtocols(List<String> protocols) {
        if (protocols != null) {
            for (String protocol : protocols) {
                this.allowedProtocols.add(protocol.trim().toUpperCase()); // Trim and uppercase
            }
        }
    }

    public void addAllowedIPs(List<String> ips) {
        if (ips != null) {
            for (String ip : ips) {
                this.allowedIPs.add(ip.trim()); // Trim whitespace
            }
        }
    }

    public String getAppName() {
        return appName;
    }

    public Action getDefaultAction() {
        return defaultAction;
    }

    public boolean isDomainAllowed(String domain) {
        if (allowedDomains.isEmpty()) { // If no specific domains are listed, consider it based on defaultAction later.
            return true; // Or false, depending on how you interpret "empty means allow all vs deny all until matched"
                         // Let's assume for now: if list empty, it doesn't restrict by domain here.
                         // The FirewallAgent will use defaultAction if no positive match.
                         // For a more strict interpretation, return false if allowedDomains.isEmpty()
        }
        if (allowedDomains.contains(domain)) {
            return true;
        }
        // Wildcard check: *.example.com matches sub.example.com
        for (String pattern : allowedDomains) {
            if (pattern.startsWith("*.")) {
                String suffix = pattern.substring(1); // e.g., .example.com
                if (domain.endsWith(suffix) && domain.length() > suffix.length()) { // ensure it's a subdomain
                    return true;
                }
            }
        }
        return false;
    }

    public boolean isProtocolAllowed(String protocol) {
        if (allowedProtocols.isEmpty()) { // If no specific protocols, it doesn't restrict by protocol here.
            return true;
        }
        return allowedProtocols.contains(protocol.trim().toUpperCase());
    }

    public boolean isIpAllowed(String ip) {
        if (allowedIPs.isEmpty()) { // If no specific IPs, it doesn't restrict by IP here.
            return true;
        }
        return allowedIPs.contains(ip.trim());
    }

    // --- START OF ADDED GETTERS (SELF-CORRECTION) ---
    public List<String> getAllowedDomainsList() {
        return new ArrayList<>(this.allowedDomains);
    }

    public List<String> getAllowedProtocolsList() {
        return new ArrayList<>(this.allowedProtocols);
    }

    public List<String> getAllowedIPsList() {
        return new ArrayList<>(this.allowedIPs);
    }
    // --- END OF ADDED GETTERS ---

    @Override
    public String toString() {
        return "AppPolicy{" +
               "appName='" + appName + '\'' +
               ", allowedDomains=" + allowedDomains +
               ", allowedProtocols=" + allowedProtocols +
               ", allowedIPs=" + allowedIPs +
               ", defaultAction=" + defaultAction +
               '}';
    }
}