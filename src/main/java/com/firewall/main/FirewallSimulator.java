package com.firewall.main;

import com.firewall.core.ActivityLogger;
import com.firewall.core.AlertEngine;
import com.firewall.core.FirewallAgent;
import com.firewall.core.PolicyManager;
import com.firewall.gui.SimpleFirewallGUI;
import com.firewall.model.DecisionResult;
import com.firewall.model.NetworkRequest;
import com.firewall.simulation.ApplicationSimulator;

import javax.swing.SwingUtilities;
// REMOVE Scanner if no longer needed after interface selection moves to GUI
// import java.util.Scanner; 

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import java.net.InetAddress;
import java.io.IOException; // Still needed if Pcaps.findAllDevs() were here, but it's moved
import java.util.List;

public class FirewallSimulator {
    private static final String POLICY_FILE = "policies.txt";
    private static final String ACTIVITY_LOG_FILE = "firewall_activity.log";
    private static final String ALERT_LOG_FILE = "alerts.log";

    private static FirewallAgent staticFirewallAgent;
    private static SimpleFirewallGUI staticGuiInstance;
    private static PcapHandle staticCaptureHandle;

    public static void main(String[] args) {
        System.out.println("Initializing Context-Aware Application Firewall Prototype...");

        PolicyManager policyManager = new PolicyManager(POLICY_FILE);
        ActivityLogger activityLogger = new ActivityLogger(ACTIVITY_LOG_FILE);
        AlertEngine alertEngine = new AlertEngine(ALERT_LOG_FILE);
        staticFirewallAgent = new FirewallAgent(policyManager, activityLogger, alertEngine);
        ApplicationSimulator appSimulator = new ApplicationSimulator(staticFirewallAgent);

        if (args.length > 0 && args[0].equalsIgnoreCase("--gui")) {
            System.out.println("Starting GUI mode...");
            SwingUtilities.invokeLater(() -> {
                staticGuiInstance = new SimpleFirewallGUI(appSimulator, ACTIVITY_LOG_FILE, ALERT_LOG_FILE);
                staticGuiInstance.setVisible(true);
                // GUI's "Start Real-Time Capture" button will now handle starting the capture
            });
        } else if (args.length > 0 && args[0].equalsIgnoreCase("--realtime")) {
            System.out.println("Starting REAL-TIME packet processing mode (CLI)...");
            // For CLI real-time, we still need to select interface via console here
            // OR make startRealTimePacketProcessing do it if no GUI is present.
            // For now, let's assume CLI real-time still needs console selection.
            // This part would need to call Pcaps.findAllDevs() itself if staticGuiInstance is null.
            // This demonstrates the GUI path more clearly.
            // To keep it simple, the GUI path is now the primary way to select an interface for real-time.
            // If you want CLI --realtime to select an interface, that logic needs to be here.
            System.out.println("For CLI real-time, please use the GUI to start capture with interface selection.");
            System.out.println("Alternatively, modify main() to handle console-based interface selection for --realtime flag without --gui.");

        } else {
            System.out.println("Starting CLI simulation mode...");
            if (appSimulator != null) {
                 appSimulator.runSimulation(25);
                 System.out.println("\n--- Simulating Specific Test Cases ---");
                 appSimulator.simulateSingleRequest("BrowserApp", "news.google.com", "8.8.8.8", "HTTPS", 443);
                 // ... other simulation calls
            }
            System.out.println("\nFirewall simulation finished.");
        }

        if (!(args.length > 0 && args[0].equalsIgnoreCase("--gui"))) {
            System.out.println("\nFirewall tasks complete. Check '" + ACTIVITY_LOG_FILE + "' and '" + ALERT_LOG_FILE + "'.");
        }
    }

    public static void stopRealTimePacketCapture() {
        if (staticCaptureHandle != null && staticCaptureHandle.isOpen()) {
            try {
                System.out.println("Attempting to stop packet capture via stopRealTimePacketCapture().");
                if(staticGuiInstance != null) staticGuiInstance.logMessage("INFO: Stop capture requested.");
                staticCaptureHandle.breakLoop();
            } catch (NotOpenException e) {
                String errorMsg = "Error trying to break Pcap loop: " + e.getMessage();
                System.err.println(errorMsg);
                if(staticGuiInstance != null) staticGuiInstance.logMessage("ERROR: Could not break pcap loop: " + e.getMessage());
            }
        }
    }

    // --- MODIFIED startRealTimePacketProcessing ---
    // Now accepts the selectedNif from the GUI
    public static void startRealTimePacketProcessing(PcapNetworkInterface selectedNif) {
        if (selectedNif == null) {
            String msg = "ERROR: No network interface provided for capture.";
            System.err.println(msg);
            if (staticGuiInstance != null) staticGuiInstance.logMessage(msg);
            // Re-enable start button in GUI if this fails early
            if (staticGuiInstance != null) {
                SwingUtilities.invokeLater(() -> {
                   // You'll need methods in GUI to get these buttons or call a method that does this
                   // e.g., staticGuiInstance.enableStartCaptureButton();
                });
            }
            return;
        }

        PcapNetworkInterface nifToUse = selectedNif; // Use the interface passed from GUI

        // The console-based interface selection logic (Pcaps.findAllDevs(), Scanner)
        // has been MOVED to SimpleFirewallGUI.java's startRealTimeButton ActionListener.

        String listenMsg = "Listening on: " + nifToUse.getName() + " (" + (nifToUse.getDescription() != null ? nifToUse.getDescription() : "No description") + ")";
        System.out.println("\n" + listenMsg); // Good for console confirmation even if GUI is active
        if (staticGuiInstance != null) staticGuiInstance.logMessage(listenMsg);

        int snapLen = 65536;
        PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
        int timeoutMillis = 10;
        
        try {
            // Assign to the static field so stopRealTimePacketCapture() and shutdown hook can access it
            staticCaptureHandle = nifToUse.openLive(snapLen, mode, timeoutMillis);
        } catch (PcapNativeException e) {
            e.printStackTrace();
            String errorMsg = "Error opening live capture on " + nifToUse.getName() + ": " + e.getMessage();
            System.err.println(errorMsg);
            if (staticGuiInstance != null) staticGuiInstance.logMessage(errorMsg);
            // Re-enable start button in GUI
            if (staticGuiInstance != null) {
                SwingUtilities.invokeLater(() -> { /* staticGuiInstance.enableStartCaptureButton(); */ });
            }
            return;
        }

        // Optional filter setup can remain here if you want to add a GUI field for it later
        // For now, we assume no filter or a hardcoded one if you uncomment it.

        System.out.println("Starting packet capture loop...");
        if (staticGuiInstance != null) staticGuiInstance.logMessage("INFO: Packet capture started.");

        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                String sourceIp = "N/A";
                String destIp = "N/A";
                int sourcePort = 0;
                int destPort = 0;
                String protocol = "N/A";
                String appName = "UnknownApp";
                String targetDomainForRequest = "N/A";

                IpPacket ipPacket = packet.get(IpPacket.class);
                if (ipPacket != null) {
                    sourceIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
                    destIp = ipPacket.getHeader().getDstAddr().getHostAddress();
                    protocol = ipPacket.getHeader().getProtocol().name().toUpperCase();
                    targetDomainForRequest = destIp; 

                    if (packet.contains(TcpPacket.class)) {
                        TcpPacket tcpPacket = packet.get(TcpPacket.class);
                        sourcePort = tcpPacket.getHeader().getSrcPort().valueAsInt();
                        destPort = tcpPacket.getHeader().getDstPort().valueAsInt();
                        appName = getApplicationNameFromPort(destPort, "TCP", packet);
                    } else if (packet.contains(UdpPacket.class)) {
                        UdpPacket udpPacket = packet.get(UdpPacket.class);
                        sourcePort = udpPacket.getHeader().getSrcPort().valueAsInt();
                        destPort = udpPacket.getHeader().getDstPort().valueAsInt();
                        appName = getApplicationNameFromPort(destPort, "UDP", packet);
                    } else if (protocol.startsWith("ICMP")) {
                        appName = protocol;
                    }
                } else {
                    return; 
                }

                NetworkRequest realNetworkRequest = new NetworkRequest(
                        appName, targetDomainForRequest, destIp, protocol, destPort);
                
                DecisionResult decisionResult = staticFirewallAgent.processRequest(realNetworkRequest);

                String consoleLog = String.format("PROCESSED: %s -> %s (Reason: %s)",
                    realNetworkRequest.toString(), decisionResult.decision, decisionResult.reason);
                System.out.println(consoleLog);

                if (staticGuiInstance != null) {
                    final String fSrcIp = sourceIp; 
                    final int fSrcPort = sourcePort;   
                    final DecisionResult fDecisionResult = decisionResult; 
                    
                    SwingUtilities.invokeLater(() -> {
                        staticGuiInstance.addPacketToLiveLogTable(
                            fDecisionResult, 
                            fSrcIp,          
                            fSrcPort         
                        );
                        staticGuiInstance.updateStatistics(fDecisionResult.decision);
                    });
                }
            }
        };
        
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (staticCaptureHandle != null && staticCaptureHandle.isOpen()) {
                System.out.println("Shutdown hook: Closing PcapHandle.");
                staticCaptureHandle.close();
            }
        }));

        try {
            if (staticCaptureHandle != null) {
                staticCaptureHandle.loop(-1, listener);
            }
        } catch (PcapNativeException | InterruptedException | NotOpenException e) {
            if (!(e instanceof InterruptedException) && 
                !(e.getMessage() != null && 
                  (e.getMessage().toLowerCase().contains("interrupted by breakloop") || 
                   e.getMessage().toLowerCase().contains("wsacancelblockingcall")))) { // More robust check
                String errorMsg = "Packet capture loop error: " + e.getMessage();
                System.err.println(errorMsg);
                if (staticGuiInstance != null) staticGuiInstance.logMessage("ERROR: " + errorMsg);
                e.printStackTrace();
            }
        } finally {
            if (staticCaptureHandle != null && staticCaptureHandle.isOpen()) {
                System.out.println("Exiting capture loop. Closing PcapHandle.");
                if (staticGuiInstance != null) staticGuiInstance.logMessage("INFO: Packet capture stopped.");
                staticCaptureHandle.close();
            }
            // No scanner to close here anymore
            
            // Re-enable start button and disable stop button in GUI
            if (staticGuiInstance != null) {
                SwingUtilities.invokeLater(() -> {
                    // You need to add methods to SimpleFirewallGUI to control button states
                    // e.g., staticGuiInstance.setCaptureButtonsState(true); // true for start enabled, stop disabled
                    // For now, let's assume this would be handled by the stop button's action listener itself.
                    // The start button is re-enabled by the stop button's action listener.
                });
            }
        }
        System.out.println("Real-time packet processing method finished.");
        if (staticGuiInstance != null) staticGuiInstance.logMessage("INFO: Real-time processing method finished.");
    }

    private static String getApplicationNameFromPort(int port, String protocol, Packet packet) {
        if ("TCP".equalsIgnoreCase(protocol)) {
            switch (port) {
                case 80: return "HTTP";
                case 443: return "HTTPS";
                case 21: return "FTP";
                case 22: return "SSH";
                case 25: return "SMTP";
                case 53: return "DNS_TCP";
                default: return "GenericTCP";
            }
        } else if ("UDP".equalsIgnoreCase(protocol)) {
            switch (port) {
                case 53: return "DNS"; // Often DNS_UDP is more specific if you use that
                case 67: return "DHCP_Server";
                case 68: return "DHCP_Client";
                case 161: return "SNMP";
                case 123: return "NTP";
                default: return "GenericUDP";
            }
        }
        return "UnknownApp";
    }
}