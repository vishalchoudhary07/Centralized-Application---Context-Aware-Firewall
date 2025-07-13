package com.firewall.model;

public class DecisionResult {
    public final String decision; // "ALLOW" or "DENY"
    public final String reason;
    public final NetworkRequest request; // The original request for context

    public DecisionResult(String decision, String reason, NetworkRequest request) {
        this.decision = decision;
        this.reason = reason;
        this.request = request;
    }

    @Override
    public String toString() {
        return "Decision: " + decision + ", Reason: " + reason;
    }
}