package com.firewall.simulation;

import com.firewall.core.FirewallAgent;
import com.firewall.model.NetworkRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class ApplicationSimulator {
    private final FirewallAgent firewallAgent;
    private final Random random = new Random();

    public ApplicationSimulator(FirewallAgent firewallAgent) {
        this.firewallAgent = firewallAgent;
    }

    public void runSimulation(int numRequests) {
        System.out.println("\n--- Starting Simulation (" + numRequests + " requests) ---");
        List<NetworkRequest> requests = generateSampleRequests(numRequests);
        for (NetworkRequest request : requests) {
            System.out.println("Simulating: " + request.getApplicationName() + " -> " + request.getTargetDomain() + " (" + request.getProtocol() + ")");
            firewallAgent.processRequest(request);
            try {
                Thread.sleep(random.nextInt(500) + 100); // Simulate some delay
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                System.err.println("Simulation interrupted.");
                break;
            }
        }
        System.out.println("--- Simulation Finished ---");
    }

    private List<NetworkRequest> generateSampleRequests(int count) {
        List<NetworkRequest> requests = new ArrayList<>();
        String[] appNames = {"BrowserApp", "MailClient", "UpdaterService", "GameClient", "UnknownApp"};
        String[] domains = {
            "google.com", "facebook.com", "wikipedia.org", "mybank.com",
            "smtp.example.com", "imap.example.com", "updates.vendor.com",
            "gaming-server.net", "malicious-site.com", "random-domain.xyz",
            "news.google.com", "api.vendor.com"
        };
        String[] protocols = {"HTTP", "HTTPS", "FTP", "SMTP", "IMAPS", "DNS"};
        String[] ips = {"8.8.8.8", "1.1.1.1", "192.168.1.100", "10.0.0.5", "203.0.113.45"};
        int[] ports = {80, 443, 21, 25, 993, 53};

        for (int i = 0; i < count; i++) {
            String app = appNames[random.nextInt(appNames.length)];
            String domain = domains[random.nextInt(domains.length)];
            String protocol = protocols[random.nextInt(protocols.length)];
            String ip = ips[random.nextInt(ips.length)];
            int port = ports[random.nextInt(ports.length)];

            // Make some requests more policy-relevant
            if (app.equals("BrowserApp") && random.nextBoolean()) {
                protocol = random.nextBoolean() ? "HTTPS" : "HTTP";
                domain = random.nextBoolean() ? "news.google.com" : "wikipedia.org";
            } else if (app.equals("MailClient") && random.nextBoolean()) {
                protocol = random.nextBoolean() ? "IMAPS" : "SMTP";
                domain = random.nextBoolean() ? "imap.example.com" : "smtp.example.com";
            } else if (app.equals("UpdaterService") && random.nextBoolean()) {
                protocol = "HTTPS";
                domain = "updates.vendor.com";
            }


            requests.add(new NetworkRequest(app, domain, ip, protocol, port));
        }
        return requests;
    }
     public void simulateSingleRequest(String appName, String domain, String ip, String protocol, int port) {
        NetworkRequest request = new NetworkRequest(appName, domain, ip, protocol, port);
        System.out.println("Simulating single request: " + request);
        firewallAgent.processRequest(request);
    }
}