package com.firewall.core;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ActivityLogger {
    private final String logFilePath;
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

    public ActivityLogger(String logFilePath) {
        this.logFilePath = logFilePath;
        // Initialize log file with header if it's new/empty
        try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(logFilePath, true)))) {
            if (new java.io.File(logFilePath).length() == 0) {
                out.println("TIMESTAMP | LEVEL | APP_NAME | TARGET_DOMAIN | TARGET_IP | PROTOCOL | PORT | DECISION | REASON");
            }
        } catch (IOException e) {
            System.err.println("Error initializing activity logger: " + e.getMessage());
        }
    }

    public void log(String level, String appName, String targetDomain, String targetIP,
                    String protocol, int port, String decision, String reason) {
        String timestamp = dateFormat.format(new Date());
        String logEntry = String.join(" | ",
                timestamp, level, appName, targetDomain, targetIP, protocol, String.valueOf(port), decision, reason);

        System.out.println("LOG: " + logEntry); // Also print to console for immediate feedback

        try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(logFilePath, true)))) {
            out.println(logEntry);
        } catch (IOException e) {
            System.err.println("Error writing to activity log: " + e.getMessage());
        }
    }
}