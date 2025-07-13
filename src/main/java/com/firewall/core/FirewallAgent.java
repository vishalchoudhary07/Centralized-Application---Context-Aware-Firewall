package com.firewall.core;

import com.firewall.model.AppPolicy;
import com.firewall.model.NetworkRequest;
import com.firewall.model.DecisionResult;

public class FirewallAgent {
    private final PolicyManager policyManager;
    private final ActivityLogger activityLogger;
    private final AlertEngine alertEngine;

    public FirewallAgent(PolicyManager policyManager, ActivityLogger activityLogger, AlertEngine alertEngine) {
        this.policyManager = policyManager;
        this.activityLogger = activityLogger;
        this.alertEngine = alertEngine;
    }

    public DecisionResult processRequest(NetworkRequest request) {
        String appName = request.getApplicationName();
        AppPolicy policy = policyManager.getPolicyForApp(appName);

        String decision;
        String reason;

        if (policy == null) {
            // No specific policy for this app, apply global default action
            AppPolicy.Action effectiveGlobalDefault = policyManager.getGlobalDefaultAction();
            decision = (effectiveGlobalDefault == AppPolicy.Action.ALLOW) ? "ALLOW" : "DENY";
            reason = "No policy defined for app '" + appName + "'. Applying global default: " + effectiveGlobalDefault;
        } else {
            // Policy exists for the app. Check specific rules.
            // AppPolicy.isDomainAllowed() now returns true if allowedDomains list is empty.
            // Same for protocol and IP.
            // So, a request is allowed if:
            // 1. Domain matches allowedDomains (or allowedDomains is empty) AND
            // 2. Protocol matches allowedProtocols (or allowedProtocols is empty) AND
            // 3. IP matches allowedIPs (or allowedIPs is empty)
            // If all these conditions effectively pass (either by match or by list being empty),
            // then the request is considered "potentially allowed by specific rules".
            // However, if the app's defaultAction is DENY, it means "deny unless explicitly allowed".
            // If the app's defaultAction is ALLOW, it means "allow unless explicitly denied by a specific rule"
            // (we don't have explicit deny rules yet, only allow lists).

            // Let's simplify: A request is ALLOWED if it matches *all* specified restrictions in the policy.
            // If any specified restriction is violated, it's a DENY candidate.
            // If it passes all specified restrictions, then it's ALLOWED.
            // If no restrictions are violated (e.g., all lists are empty or all criteria match non-empty lists),
            // the app's defaultAction doesn't strictly come into play unless interpreted as "allow if not explicitly denied".

            // More straightforward interpretation for a rule-based allow-list system:
            // To be ALLOWED, the request must satisfy ALL conditions for which there are rules.
            // If a rule category (e.g. domains) is specified (list not empty), it MUST match.
            // If a rule category is NOT specified (list is empty), it's considered a pass for that category.

            boolean domainCheckPassed = policy.getAllowedDomainsList().isEmpty() || policy.isDomainAllowed(request.getTargetDomain());
            boolean protocolCheckPassed = policy.getAllowedProtocolsList().isEmpty() || policy.isProtocolAllowed(request.getProtocol());
            boolean ipCheckPassed = policy.getAllowedIPsList().isEmpty() || policy.isIpAllowed(request.getTargetIP());

            if (domainCheckPassed && protocolCheckPassed && ipCheckPassed) {
                // All specified criteria are met (or not specified, thus not restrictive)
                decision = "ALLOW";
                reason = "Request by '" + appName + "' to '" + request.getTargetDomain() + 
                         "' via '" + request.getProtocol() + "' matches app policy.";
                if (!policy.getAllowedDomainsList().isEmpty()) reason += " Domain rule matched.";
                if (!policy.getAllowedProtocolsList().isEmpty()) reason += " Protocol rule matched.";
                // Add IP if relevant
            } else {
                // At least one specified criterion was not met.
                // The app's defaultAction will determine the outcome.
                // If default is ALLOW, this state (failed specific check) should still be DENY.
                // If default is DENY, this state is definitely DENY.
                // So, if any specific rule check fails, it should be DENY regardless of defaultAction for an allow-list firewall.
                decision = "DENY";
                reason = "Request by '" + appName + "' to '" + request.getTargetDomain() +
                         "' via '" + request.getProtocol() + "' violated app policy. ";
                if (!domainCheckPassed && !policy.getAllowedDomainsList().isEmpty()) reason += "Domain not allowed. ";
                if (!protocolCheckPassed && !policy.getAllowedProtocolsList().isEmpty()) reason += "Protocol not allowed. ";
                if (!ipCheckPassed && !policy.getAllowedIPsList().isEmpty()) reason += "IP not allowed. ";
                
                // The role of defaultAction in an allow-list system:
                // If a request matches NO specific allow rules, THEN the defaultAction applies.
                // My logic above for ALLOW is: if it matches all *existing* specific rules for the app.
                // What if an app has NO rules (all lists empty)?
                // Then domainCheckPassed, protocolCheckPassed, ipCheckPassed are all true.
                // The request would be ALLOWED by the logic above. THEN the app's defaultAction matters.
                
                // Let's refine the decision:
                // 1. Check against specific rules.
                // 2. If all specific rules pass (or no specific rules exist for a category),
                //    AND the app's defaultAction is ALLOW, then ALLOW.
                // 3. If any specific rule fails, then DENY.
                // 4. If all specific rules pass (or no specific rules exist for a category),
                //    BUT the app's defaultAction is DENY, then DENY (because it wasn't *explicitly*
                //    allowed by matching specific criteria, it just didn't violate anything).
                //    This is classic "default deny".

                // Revised Logic:
                boolean specificallyAllowed = true;
                StringBuilder violationReason = new StringBuilder();

                if (!policy.getAllowedDomainsList().isEmpty() && !policy.isDomainAllowed(request.getTargetDomain())) {
                    specificallyAllowed = false;
                    violationReason.append("Domain '").append(request.getTargetDomain()).append("' not in allowed list. ");
                }
                if (!policy.getAllowedProtocolsList().isEmpty() && !policy.isProtocolAllowed(request.getProtocol())) {
                    specificallyAllowed = false;
                    violationReason.append("Protocol '").append(request.getProtocol()).append("' not in allowed list. ");
                }
                if (!policy.getAllowedIPsList().isEmpty() && !policy.isIpAllowed(request.getTargetIP())) {
                    specificallyAllowed = false;
                    violationReason.append("IP '").append(request.getTargetIP()).append("' not in allowed list. ");
                }

                if (specificallyAllowed) {
                    // It passed all specific restrictions (if any were defined).
                    // If NO rules were defined at all for this app (all lists empty), it also falls here.
                    // In this case, the app's defaultAction should decide.
                    // Or, if it *matched* specific rules, it should be allowed regardless of defaultAction
                    // IF the defaultAction is only for "unmatched" traffic.

                    // Simpler: If it passes all defined filters, it's a candidate for ALLOW.
                    // If any defined filter is violated, it's a DENY.
                    // If no filters are defined for an app, app's defaultAction applies.

                    boolean hasAnySpecificRules = !policy.getAllowedDomainsList().isEmpty() ||
                                                  !policy.getAllowedProtocolsList().isEmpty() ||
                                                  !policy.getAllowedIPsList().isEmpty();
                    
                    if (hasAnySpecificRules) { // If there are specific rules, and it passed them all.
                        decision = "ALLOW";
                        reason = "Request matches defined policy rules for " + appName + ".";
                    } else { // No specific rules defined for this app (all allow lists are empty).
                        decision = (policy.getDefaultAction() == AppPolicy.Action.ALLOW) ? "ALLOW" : "DENY";
                        reason = "No specific rules for app '" + appName + "'. Applying app default: " + policy.getDefaultAction();
                    }

                } else { // Violated at least one specific rule
                    decision = "DENY";
                    reason = "Request by '" + appName + "' violated specific policy rules: " + violationReason.toString().trim();
                }
            }
        }

        activityLogger.log(
                "DENY".equals(decision) ? "WARN" : "INFO",
                appName,
                request.getTargetDomain(),
                request.getTargetIP(),
                request.getProtocol(),
                request.getPort(),
                decision,
                reason
        );

        alertEngine.processEvent(request, decision, reason);
        return new DecisionResult(decision, reason, request);
    }
}