package com.firewall.gui;

import com.firewall.main.FirewallSimulator; // To call start/stop methods
import com.firewall.model.DecisionResult;
import com.firewall.model.NetworkRequest;
import com.firewall.simulation.ApplicationSimulator;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;
// --- NEW IMPORTS FOR INTERFACE SELECTION ---
import java.util.List;
import java.util.ArrayList;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapAddress; // To display IP addresses in dialog
import org.pcap4j.core.PcapNativeException;
import java.io.IOException;
// --- END NEW IMPORTS ---


public class SimpleFirewallGUI extends JFrame {

    private JTextArea generalLogTextArea;
    private DefaultTableModel liveLogTableModel;
    private JTable liveLogTable;

    private JLabel totalPacketsLabel, allowedPacketsLabel, deniedPacketsLabel;
    private long totalPacketCount = 0;
    private long allowedPacketCount = 0;
    private long deniedPacketCount = 0;

    private JButton startRealTimeButton, stopRealTimeButton;
    private JButton runSimulationButton;

    private ApplicationSimulator appSimulator;

    // --- NEW FIELD to store available interfaces ---
    private List<PcapNetworkInterface> availableInterfaces;
    // --- END NEW FIELD ---

    public SimpleFirewallGUI(ApplicationSimulator appSimulator, String activityLogFile, String alertLogFile) {
        this.appSimulator = appSimulator;

        setTitle("Context-Aware Firewall Dashboard");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1000, 700);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(5, 5));

        JPanel topPanel = new JPanel(new BorderLayout());
        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statsPanel.setBorder(BorderFactory.createTitledBorder("Real-Time Statistics"));
        totalPacketsLabel = new JLabel("Total: 0");
        allowedPacketsLabel = new JLabel("Allowed: 0");
        deniedPacketsLabel = new JLabel("Denied: 0");
        statsPanel.add(totalPacketsLabel);
        statsPanel.add(new JSeparator(SwingConstants.VERTICAL));
        statsPanel.add(allowedPacketsLabel);
        statsPanel.add(new JSeparator(SwingConstants.VERTICAL));
        statsPanel.add(deniedPacketsLabel);
        topPanel.add(statsPanel, BorderLayout.CENTER);

        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        startRealTimeButton = new JButton("Start Real-Time Capture");
        stopRealTimeButton = new JButton("Stop Real-Time Capture");
        runSimulationButton = new JButton("Run Sim Batch (10)");
        stopRealTimeButton.setEnabled(false);

        controlPanel.add(runSimulationButton);
        controlPanel.add(startRealTimeButton);
        controlPanel.add(stopRealTimeButton);
        topPanel.add(controlPanel, BorderLayout.EAST);
        add(topPanel, BorderLayout.NORTH);

        JTabbedPane tabbedPane = new JTabbedPane();
        liveLogTableModel = new DefaultTableModel(
            new String[]{"Time", "Proto", "Src IP", "Src Port", "Dst IP", "Dst Port", "App", "Decision", "Reason"}, 0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        liveLogTable = new JTable(liveLogTableModel);
        liveLogTable.setDefaultRenderer(Object.class, new TrafficLogTableCellRenderer());
        liveLogTable.getColumnModel().getColumn(0).setPreferredWidth(70);
        liveLogTable.getColumnModel().getColumn(1).setPreferredWidth(40);
        liveLogTable.getColumnModel().getColumn(8).setPreferredWidth(250);
        JScrollPane liveLogScrollPane = new JScrollPane(liveLogTable);
        tabbedPane.addTab("Real-Time Traffic Log", liveLogScrollPane);

        generalLogTextArea = new JTextArea(15, 70);
        generalLogTextArea.setEditable(false);
        generalLogTextArea.setLineWrap(true);
        generalLogTextArea.setWrapStyleWord(true);
        JScrollPane generalLogScrollPane = new JScrollPane(generalLogTextArea);
        tabbedPane.addTab("General & Simulation Log", generalLogScrollPane);
        add(tabbedPane, BorderLayout.CENTER);

        runSimulationButton.addActionListener(e -> {
            logMessage("Starting batch simulation...");
            if (this.appSimulator != null) {
                new Thread(() -> this.appSimulator.runSimulation(10)).start();
            }
        });

        // --- MODIFIED ActionListener for startRealTimeButton ---
        startRealTimeButton.addActionListener(e -> {
            try {
                availableInterfaces = Pcaps.findAllDevs(); // Populate the class field
                if (availableInterfaces == null || availableInterfaces.isEmpty()) {
                    logMessage("ERROR: No network interfaces found. Npcap installed? Admin rights?");
                    JOptionPane.showMessageDialog(SimpleFirewallGUI.this,
                            "No network interfaces found.\nEnsure Npcap is installed and you have administrator privileges.",
                            "Interface Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            } catch (PcapNativeException ex) { // Handle exceptions from findAllDevs
                logMessage("ERROR: Could not retrieve network interfaces: " + ex.getMessage());
                 JOptionPane.showMessageDialog(SimpleFirewallGUI.this,
                        "Error retrieving network interfaces: " + ex.getMessage(),
                        "Interface Error", JOptionPane.ERROR_MESSAGE);
                ex.printStackTrace(); // Also print stack trace for debugging
                return;
            }

            PcapNetworkInterface selectedInterface = showInterfaceSelectionDialog(); // Call new method

            if (selectedInterface != null) {
                logMessage("INFO: Real-time capture starting on: " + selectedInterface.getName());
                final PcapNetworkInterface finalSelectedInterface = selectedInterface;
                new Thread(() -> FirewallSimulator.startRealTimePacketProcessing(finalSelectedInterface)).start();
                startRealTimeButton.setEnabled(false);
                stopRealTimeButton.setEnabled(true);
            } else {
                logMessage("INFO: Real-time capture cancelled or no interface selected.");
            }
        });
        // --- END MODIFIED ActionListener ---

        stopRealTimeButton.addActionListener(e -> {
            logMessage("INFO: Attempting to stop real-time capture...");
            FirewallSimulator.stopRealTimePacketCapture();
            startRealTimeButton.setEnabled(true);
            stopRealTimeButton.setEnabled(false);
        });

        logMessage("GUI Initialized. Activity Log: " + activityLogFile + ", Alert Log: " + alertLogFile);
    }

    // --- NEW METHOD to show interface selection dialog ---
    private PcapNetworkInterface showInterfaceSelectionDialog() {
        // Uses the class field 'availableInterfaces' which was populated by startRealTimeButton's action
        if (availableInterfaces == null || availableInterfaces.isEmpty()) {
            logMessage("ERROR: showInterfaceSelectionDialog called but no interfaces available.");
            return null;
        }

        List<String> interfaceDescriptions = new ArrayList<>();
        for (PcapNetworkInterface nif : availableInterfaces) {
            StringBuilder descBuilder = new StringBuilder();
            descBuilder.append(nif.getName());
            if (nif.getDescription() != null && !nif.getDescription().isEmpty()) {
                descBuilder.append(" (").append(nif.getDescription()).append(")");
            }
            // Add first non-loopback IPv4 address for easier identification
            for (PcapAddress addr : nif.getAddresses()) {
                if (addr.getAddress() != null && !addr.getAddress().isLoopbackAddress() && addr.getAddress() instanceof java.net.Inet4Address) {
                    descBuilder.append(" - IP: ").append(addr.getAddress().getHostAddress());
                    break; // Show only one IP for brevity
                }
            }
            interfaceDescriptions.add(descBuilder.toString());
        }

        // Create a JComboBox for selection
        JComboBox<String> interfaceComboBox = new JComboBox<>(interfaceDescriptions.toArray(new String[0]));
        
        // Show dialog with JComboBox
        int result = JOptionPane.showConfirmDialog(
                this, // Parent component
                interfaceComboBox, // Component to display
                "Select Network Interface", // Dialog title
                JOptionPane.OK_CANCEL_OPTION, // Button types
                JOptionPane.PLAIN_MESSAGE // Message type
        );

        if (result == JOptionPane.OK_OPTION) {
            int selectedIndex = interfaceComboBox.getSelectedIndex();
            if (selectedIndex >= 0 && selectedIndex < availableInterfaces.size()) {
                return availableInterfaces.get(selectedIndex); // Return the actual PcapNetworkInterface object
            }
        }
        return null; // User cancelled or error
    }
    // --- END NEW METHOD ---

    public void logMessage(String message) {
        SwingUtilities.invokeLater(() -> {
            if (generalLogTextArea != null) {
                generalLogTextArea.append(message + "\n");
                generalLogTextArea.setCaretPosition(generalLogTextArea.getDocument().getLength());
            } else {
                System.err.println("GUI generalLogTextArea is null! Message: " + message);
            }
        });
    }

    public void addPacketToLiveLogTable(DecisionResult decisionResult, String sourceIp, int sourcePort) {
        SwingUtilities.invokeLater(() -> {
            if (liveLogTableModel != null) {
                NetworkRequest request = decisionResult.request;
                String timeStr = new SimpleDateFormat("HH:mm:ss.SSS").format(new Date(request.getTimestamp()));
                liveLogTableModel.addRow(new Object[]{
                        timeStr,
                        request.getProtocol(),
                        sourceIp,
                        sourcePort,
                        request.getTargetIP(),
                        request.getPort(),
                        request.getApplicationName(),
                        decisionResult.decision,
                        decisionResult.reason
                });
                if (liveLogTable.getRowCount() > 0) {
                    liveLogTable.scrollRectToVisible(liveLogTable.getCellRect(liveLogTable.getRowCount() - 1, 0, true));
                }
                if (liveLogTableModel.getRowCount() > 2000) {
                    liveLogTableModel.removeRow(0);
                }
            }
        });
    }

    public void updateStatistics(String decision) {
        SwingUtilities.invokeLater(() -> {
            totalPacketCount++;
            if ("ALLOW".equalsIgnoreCase(decision)) {
                allowedPacketCount++;
            } else if ("DENY".equalsIgnoreCase(decision)) {
                deniedPacketCount++;
            }
            totalPacketsLabel.setText("Total: " + totalPacketCount);
            allowedPacketsLabel.setText("Allowed: " + allowedPacketCount);
            deniedPacketsLabel.setText("Denied: " + deniedPacketCount);
        });
    }
}

// Custom TableCellRenderer (Keep this class as it was)
class TrafficLogTableCellRenderer extends DefaultTableCellRenderer {
    // ... (your existing implementation for coloring rows) ...
    private static final Color ALLOW_COLOR = new Color(220, 255, 220);
    private static final Color DENY_COLOR = new Color(255, 220, 220);

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                 boolean hasFocus, int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        
        if (!isSelected) { // Only apply custom background if not selected
            if (row < table.getModel().getRowCount()) {
                Object decisionObj = table.getModel().getValueAt(row, 7); // Decision is column 7
                if (decisionObj != null) {
                    String decision = decisionObj.toString();
                    if ("ALLOW".equalsIgnoreCase(decision)) {
                        c.setBackground(ALLOW_COLOR);
                    } else if ("DENY".equalsIgnoreCase(decision)) {
                        c.setBackground(DENY_COLOR);
                    } else {
                        c.setBackground(table.getBackground());
                    }
                } else {
                     c.setBackground(table.getBackground());
                }
            }
        } else {
            // Use default selection colors
            c.setBackground(table.getSelectionBackground());
            c.setForeground(table.getSelectionForeground());
        }
        return c;
    }
}