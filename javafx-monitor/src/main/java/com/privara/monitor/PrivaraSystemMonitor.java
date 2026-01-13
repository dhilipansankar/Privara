package com.privara.monitor;

import com.google.gson.Gson;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.stage.Stage;
import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.GlobalMemory;
import oshi.hardware.HWDiskStore;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.hardware.NetworkIF;
import oshi.software.os.OperatingSystem;
import oshi.software.os.OSProcess;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class PrivaraSystemMonitor extends Application {

    private static final String BACKEND_URL = "http://localhost:8000/api/system-update";
    private static final int UPDATE_INTERVAL_SECONDS = 5;

    private final SystemInfo systemInfo = new SystemInfo();
    private final HardwareAbstractionLayer hal = systemInfo.getHardware();
    private final OperatingSystem os = systemInfo.getOperatingSystem();
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final Gson gson = new Gson();
    
    private ScheduledExecutorService scheduler;
    private long[] prevTicks;
    private long prevReadBytes = 0;
    private long prevWriteBytes = 0;

    @Override
    public void start(Stage primaryStage) {
        System.out.println("[*] Privara System Monitor started (headless mode)");
        System.out.println("[*] Target backend: " + BACKEND_URL);
        System.out.println("[*] Update interval: " + UPDATE_INTERVAL_SECONDS + "s");
        
        // Initialize CPU ticks for accurate CPU usage calculation
        CentralProcessor processor = hal.getProcessor();
        prevTicks = processor.getSystemCpuLoadTicks();
        
        // Initialize disk I/O counters
        for (HWDiskStore disk : hal.getDiskStores()) {
            prevReadBytes += disk.getReadBytes();
            prevWriteBytes += disk.getWriteBytes();
        }
        
        // Start background monitoring
        startMonitoring();
        
        // Keep JavaFX runtime alive (headless)
        primaryStage.setTitle("Privara System Monitor");
        primaryStage.setWidth(1);
        primaryStage.setHeight(1);
        primaryStage.setOpacity(0);
        primaryStage.show();
    }

    private void startMonitoring() {
        scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleAtFixedRate(() -> {
            try {
                Map<String, Object> metrics = collectSystemMetrics();
                sendMetricsToBackend(metrics);
            } catch (Exception e) {
                System.err.println("[ERROR] Monitoring cycle failed: " + e.getMessage());
            }
        }, 0, UPDATE_INTERVAL_SECONDS, TimeUnit.SECONDS);
    }

    private Map<String, Object> collectSystemMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        // OS Information
        metrics.put("os_name", os.getFamily());
        metrics.put("os_version", os.getVersionInfo().toString());
        metrics.put("os_manufacturer", os.getManufacturer());
        
        // CPU Metrics
        CentralProcessor processor = hal.getProcessor();
        long[] ticks = processor.getSystemCpuLoadTicks();
        double cpuLoad = processor.getSystemCpuLoadBetweenTicks(prevTicks) * 100;
        prevTicks = ticks;
        
        metrics.put("cpu_model", processor.getProcessorIdentifier().getName());
        metrics.put("cpu_cores_physical", processor.getPhysicalProcessorCount());
        metrics.put("cpu_cores_logical", processor.getLogicalProcessorCount());
        metrics.put("cpu_percent", Math.round(cpuLoad * 100.0) / 100.0);
        metrics.put("cpu_frequency_mhz", processor.getMaxFreq() / 1_000_000);
        
        // Memory Metrics
        GlobalMemory memory = hal.getMemory();
        long totalMemory = memory.getTotal();
        long availableMemory = memory.getAvailable();
        long usedMemory = totalMemory - availableMemory;
        
        metrics.put("memory_total_gb", totalMemory / (1024.0 * 1024 * 1024));
        metrics.put("memory_available_gb", availableMemory / (1024.0 * 1024 * 1024));
        metrics.put("memory_used_gb", usedMemory / (1024.0 * 1024 * 1024));
        metrics.put("memory_percent", Math.round((usedMemory * 100.0 / totalMemory) * 100.0) / 100.0);
        
        // Disk I/O Metrics
        long currentReadBytes = 0;
        long currentWriteBytes = 0;
        for (HWDiskStore disk : hal.getDiskStores()) {
            currentReadBytes += disk.getReadBytes();
            currentWriteBytes += disk.getWriteBytes();
        }
        
        double readMBps = (currentReadBytes - prevReadBytes) / (1024.0 * 1024 * UPDATE_INTERVAL_SECONDS);
        double writeMBps = (currentWriteBytes - prevWriteBytes) / (1024.0 * 1024 * UPDATE_INTERVAL_SECONDS);
        
        metrics.put("disk_read_mbps", Math.round(readMBps * 100.0) / 100.0);
        metrics.put("disk_write_mbps", Math.round(writeMBps * 100.0) / 100.0);
        metrics.put("disk_io_total_mbps", Math.round((readMBps + writeMBps) * 100.0) / 100.0);
        
        prevReadBytes = currentReadBytes;
        prevWriteBytes = currentWriteBytes;
        
        // Network Metrics
        List<Map<String, Object>> networkInterfaces = new ArrayList<>();
        for (NetworkIF net : hal.getNetworkIFs()) {
            if (!net.getName().startsWith("lo")) { // Skip loopback
                Map<String, Object> netInfo = new HashMap<>();
                netInfo.put("name", net.getName());
                netInfo.put("display_name", net.getDisplayName());
                netInfo.put("bytes_sent", net.getBytesSent());
                netInfo.put("bytes_recv", net.getBytesRecv());
                netInfo.put("packets_sent", net.getPacketsSent());
                netInfo.put("packets_recv", net.getPacketsRecv());
                networkInterfaces.add(netInfo);
            }
        }
        metrics.put("network_interfaces", networkInterfaces);
        
        // Process Count
        metrics.put("process_count", os.getProcessCount());
        metrics.put("thread_count", os.getThreadCount());
        
        // Top Processes by CPU
        List<Map<String, Object>> topProcesses = new ArrayList<>();
        List<OSProcess> processes = os.getProcesses(null, OperatingSystem.ProcessSorting.CPU_DESC, 10);
        for (OSProcess proc : processes) {
            Map<String, Object> procInfo = new HashMap<>();
            procInfo.put("pid", proc.getProcessID());
            procInfo.put("name", proc.getName());
            procInfo.put("cpu_percent", proc.getProcessCpuLoadCumulative() * 100);
            procInfo.put("memory_bytes", proc.getResidentSetSize());
            procInfo.put("state", proc.getState().name());
            topProcesses.add(procInfo);
        }
        metrics.put("top_processes", topProcesses);
        
        // Timestamp
        metrics.put("timestamp", System.currentTimeMillis());
        
        return metrics;
    }

    private void sendMetricsToBackend(Map<String, Object> metrics) {
        try {
            String jsonPayload = gson.toJson(metrics);
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BACKEND_URL))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                System.out.println("[OK] Metrics sent successfully (CPU: " + metrics.get("cpu_percent") + "%)");
            } else {
                System.err.println("[WARN] Backend returned status: " + response.statusCode());
            }
        } catch (IOException | InterruptedException e) {
            System.err.println("[ERROR] Failed to send metrics: " + e.getMessage());
        }
    }

    @Override
    public void stop() {
        System.out.println("[*] Shutting down system monitor...");
        if (scheduler != null) {
            scheduler.shutdown();
        }
        Platform.exit();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
