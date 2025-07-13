package com.firewall.model;

public class NetworkRequest {
    private final String applicationName;
    private final String targetDomain;
    private final String targetIP;
    private final String protocol;
    private final int port; // Optional, can be 0 if not specified
    private final long timestamp;

    public NetworkRequest(String applicationName, String targetDomain, String targetIP, String protocol, int port) {
        this.applicationName = applicationName;
        this.targetDomain = targetDomain;
        this.targetIP = targetIP;
        this.protocol = protocol;
        this.port = port;
        this.timestamp = System.currentTimeMillis();
    }

    public String getApplicationName() {
        return applicationName;
    }

    public String getTargetDomain() {
        return targetDomain;
    }

    public String getTargetIP() {
        return targetIP;
    }

    public String getProtocol() {
        return protocol;
    }

    public int getPort() {
        return port;
    }

    public long getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return "NetworkRequest{" +
               "appName='" + applicationName + '\'' +
               ", domain='" + targetDomain + '\'' +
               ", ip='" + targetIP + '\'' +
               ", proto='" + protocol + '\'' +
               ", port=" + port +
               '}';
    }
}