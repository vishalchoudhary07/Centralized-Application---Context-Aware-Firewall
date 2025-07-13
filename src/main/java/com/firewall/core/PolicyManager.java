package com.firewall.core;

import com.firewall.model.AppPolicy;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class PolicyManager {
    private final Map<String, AppPolicy> policies = new HashMap<>();
    private final String policyFilePath;
    private AppPolicy.Action globalDefaultAction = AppPolicy.Action.DENY;

    public PolicyManager(String policyFilePath) {
        this.policyFilePath = policyFilePath;
        loadPolicies(); // Renamed from loadPoliciesRefined for simplicity, this is the active one
    }

    private void loadPolicies() { // This is the refined version
        policies.clear();
        try (BufferedReader reader = new BufferedReader(new FileReader(policyFilePath))) {
            String line;
            Map<String, String> currentAppAttributes = new HashMap<>();
            String currentAppName = null;

            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                if (line.equals("---")) {
                    if (currentAppName != null && !currentAppAttributes.isEmpty()) {
                        createAndStorePolicy(currentAppName, currentAppAttributes);
                        currentAppName = null;
                        currentAppAttributes.clear();
                    }
                    continue;
                }

                if (line.startsWith("appName=")) {
                    if (currentAppName != null && !currentAppAttributes.isEmpty()) {
                        createAndStorePolicy(currentAppName, currentAppAttributes); // Process previous before starting new
                        currentAppAttributes.clear();
                    }
                    currentAppName = line.substring("appName=".length()).trim();
                } else if (currentAppName != null) {
                    String[] parts = line.split("=", 2);
                    if (parts.length == 2) {
                        currentAppAttributes.put(parts[0].trim(), parts[1].trim());
                    } else {
                        System.err.println("Warning: Malformed policy line for app '" + currentAppName + "': " + line);
                    }
                } else if (!line.isEmpty()){
                    System.err.println("Warning: Policy line found outside of an app block: " + line);
                }
            }
            // Process the last app block if the file doesn't end with '---'
            if (currentAppName != null && !currentAppAttributes.isEmpty()) {
                createAndStorePolicy(currentAppName, currentAppAttributes);
            }

        } catch (IOException e) {
            System.err.println("CRITICAL: Error loading policies from " + policyFilePath + ": " + e.getMessage());
            // Depending on requirements, might throw a RuntimeException to halt startup
        }
        System.out.println("Policies loaded: " + policies.size());
    }

    private void createAndStorePolicy(String appName, Map<String, String> attributes) {
        AppPolicy.Action defaultAction;
        try {
            defaultAction = AppPolicy.Action.valueOf(
                attributes.getOrDefault("defaultAction", "DENY").trim().toUpperCase()
            );
        } catch (IllegalArgumentException e) {
            System.err.println("Warning: Invalid defaultAction value for app '" + appName + "'. Using DENY.");
            defaultAction = AppPolicy.Action.DENY;
        }

        AppPolicy policy = new AppPolicy(appName, defaultAction);

        if (attributes.containsKey("allowedDomains")) {
            String domainsStr = attributes.get("allowedDomains");
            if (domainsStr != null && !domainsStr.trim().isEmpty()) {
                policy.addAllowedDomains(
                    Arrays.stream(domainsStr.split(","))
                          .map(String::trim) // Trim each domain
                          .filter(s -> !s.isEmpty()) // Filter out empty strings if any (e.g. "domain1,,domain2")
                          .collect(Collectors.toList())
                );
            }
        }
        if (attributes.containsKey("allowedProtocols")) {
            String protocolsStr = attributes.get("allowedProtocols");
            if(protocolsStr != null && !protocolsStr.trim().isEmpty()){
                policy.addAllowedProtocols(
                    Arrays.stream(protocolsStr.split(","))
                          .map(String::trim)
                          .map(String::toUpperCase)
                          .filter(s -> !s.isEmpty())
                          .collect(Collectors.toList())
                );
            }
        }
        if (attributes.containsKey("allowedIPs")) {
            String ipsStr = attributes.get("allowedIPs");
            if(ipsStr != null && !ipsStr.trim().isEmpty()){
                policy.addAllowedIPs(
                    Arrays.stream(ipsStr.split(","))
                          .map(String::trim)
                          .filter(s -> !s.isEmpty())
                          .collect(Collectors.toList())
                );
            }
        }
        policies.put(appName, policy);
        System.out.println("Loaded policy for: " + appName + " -> " + policy.toString());
    }

    public AppPolicy getPolicyForApp(String appName) {
        return policies.get(appName);
    }

    public AppPolicy.Action getGlobalDefaultAction() {
        return globalDefaultAction;
    }

    public void setGlobalDefaultAction(AppPolicy.Action action) {
        this.globalDefaultAction = action;
    }
    
    public static void main(String[] args) {
        // Create a dummy policies.txt for testing with some edge cases
        // appName=BrowserApp
        // allowedDomains=*.google.com, wikipedia.org , 
        // allowedProtocols=HTTP, HTTPS
        // defaultAction=ALLOW
        // ---
        // appName=MailClient
        // allowedDomains=smtp.example.com, imap.example.com
        // allowedProtocols=SMTP, IMAPS,HTTPS
        // #defaultAction=DENY
        // ---
        // appName=NoDefaultApp
        // allowedDomains=specific.com
        // ---
        // appName=EmptyApp
        // defaultAction=ALLOW

        System.out.println("Testing PolicyManager...");
        // Ensure policies.txt exists in the project root with content for testing
        // Example content for policies.txt:
        /*
        appName=BrowserApp
        allowedDomains=*.google.com, wikipedia.org
        allowedProtocols=HTTP,HTTPS
        defaultAction=ALLOW
        ---
        appName=MailClient
        allowedDomains=smtp.example.com, imap.example.com
        allowedProtocols=SMTP,IMAPS,HTTPS
        defaultAction=DENY
        ---
        appName=TestApp
        allowedDomains=
        allowedProtocols=TCP
        defaultAction=DENY
        */
        PolicyManager pm = new PolicyManager("policies.txt");
        
        AppPolicy browserPolicy = pm.getPolicyForApp("BrowserApp");
        if (browserPolicy != null) {
            System.out.println("\nBrowserApp Policy: " + browserPolicy);
            System.out.println("BrowserApp access to sub.google.com (HTTPS): " +
                    (browserPolicy.isDomainAllowed("sub.google.com") && browserPolicy.isProtocolAllowed("HTTPS")));
            System.out.println("BrowserApp access to other.com (HTTP): " +
                    (browserPolicy.isDomainAllowed("other.com") && browserPolicy.isProtocolAllowed("HTTP")));
             System.out.println("BrowserApp Default Action: " + browserPolicy.getDefaultAction());
        } else {
            System.out.println("No policy found for BrowserApp.");
        }

        AppPolicy mailPolicy = pm.getPolicyForApp("MailClient");
        if (mailPolicy != null) {
            System.out.println("\nMailClient Policy: " + mailPolicy);
            System.out.println("MailClient Default Action: " + mailPolicy.getDefaultAction());
        } else {
             System.out.println("No policy found for MailClient.");
        }
        
        AppPolicy testAppPolicy = pm.getPolicyForApp("TestApp");
        if (testAppPolicy != null) {
            System.out.println("\nTestApp Policy: " + testAppPolicy);
            System.out.println("TestApp Default Action: " + testAppPolicy.getDefaultAction());
            System.out.println("TestApp domains: " + testAppPolicy.getAllowedDomainsList());
        } else {
             System.out.println("No policy found for TestApp.");
        }
    }
}