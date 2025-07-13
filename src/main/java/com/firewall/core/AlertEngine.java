package com.firewall.core;

import com.firewall.model.NetworkRequest;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;

public class AlertEngine {
    private final String alertFilePath;
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

    // Heuristic 1: Denied requests per app
    private final int MAX_DENIED_REQUESTS_PER_APP = 5;
    private final long DENIED_REQUESTS_WINDOW_MS = 60 * 1000; // 1 minute
    private final Map<String, Queue<Long>> appDeniedTimestamps = new HashMap<>();

    public AlertEngine(String alertFilePath) {
        this.alertFilePath = alertFilePath;
         try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(alertFilePath, true)))) {
            if (new java.io.File(alertFilePath).length() == 0) {
                out.println("TIMESTAMP | LEVEL | TYPE | APPLICATION | DETAILS");
            }
        } catch (IOException e) {
            System.err.println("Error initializing alert logger: " + e.getMessage());
        }
    }

    public void processEvent(NetworkRequest request, String decision, String reason) {
        if ("DENY".equals(decision)) {
            checkDeniedRequestThreshold(request);
            if (reason.contains("protocol not allowed")) {
                 generateAlert("MEDIUM", "UNEXPECTED_PROTOCOL", request.getApplicationName(),
                        "App tried to use " + request.getProtocol() + " to " + request.getTargetDomain() + ", which is not in its allowed protocols.");
            }
        }
        // Add more heuristics here if needed
    }

    private void checkDeniedRequestThreshold(NetworkRequest request) {
        String appName = request.getApplicationName();
        appDeniedTimestamps.putIfAbsent(appName, new LinkedList<>());
        Queue<Long> timestamps = appDeniedTimestamps.get(appName);

        long currentTime = request.getTimestamp();
        timestamps.add(currentTime);

        // Remove old timestamps outside the window
        while (!timestamps.isEmpty() && currentTime - timestamps.peek() > DENIED_REQUESTS_WINDOW_MS) {
            timestamps.poll();
        }

        if (timestamps.size() >= MAX_DENIED_REQUESTS_PER_APP) {
            generateAlert("HIGH", "EXCESSIVE_DENIES", appName,
                    "Application '" + appName + "' has " + timestamps.size() +
                    " denied requests in the last " + (DENIED_REQUESTS_WINDOW_MS / 1000) + " seconds.");
            // Optional: Clear queue after alert to avoid repeated alerts for the same burst
            // timestamps.clear(); // Or implement a cooldown period
        }
    }

    private void generateAlert(String level, String type, String application, String details) {
        String timestamp = dateFormat.format(new Date());
        String alertEntry = String.join(" | ", timestamp, level, type, application, details);

        System.err.println("ALERT: " + alertEntry); // Print to console (stderr for alerts)

        try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(alertFilePath, true)))) {
            out.println(alertEntry);
        } catch (IOException e) {
            System.err.println("Error writing to alert log: " + e.getMessage());
        }
    }
}