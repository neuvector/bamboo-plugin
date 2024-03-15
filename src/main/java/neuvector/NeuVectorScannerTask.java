package neuvector;

import com.atlassian.bamboo.build.logger.BuildLogger;
import com.atlassian.bamboo.task.TaskContext;
import com.atlassian.bamboo.task.TaskException;
import com.atlassian.bamboo.task.TaskResult;
import com.atlassian.bamboo.task.TaskResultBuilder;
import com.atlassian.bamboo.task.TaskType;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.File;
import java.util.HashSet;
import java.util.Set;
import java.util.LinkedHashMap;

import neuvector.report.*;
import neuvector.scanner.*;

public class NeuVectorScannerTask implements TaskType {
    private BuildLogger buildLogger;
    private ScanConfig scanConfig;

    private StandaloneScanner standaloneScanner;
    private ControllerScanner controllerScanner;

    @Override
    public TaskResult execute(final TaskContext taskContext) throws TaskException {
        final TaskResultBuilder builder = TaskResultBuilder.newBuilder(taskContext).success();
        ProcessResult processResult = new ProcessResult();

        buildLogger = taskContext.getBuildLogger();
        scanConfig = new ScanConfig(taskContext, processResult);

        if (scanConfig.isEnableStandalone()) {
            buildLogger.addBuildLogEntry("Scan By StandaloneScanner....");
            try {
                standaloneScanner = new StandaloneScanner(taskContext, processResult, scanConfig);
                standaloneScanner.scan();
            } catch (IOException e) {
                buildLogger.addErrorLogEntry("IOException: " + e.getMessage());
            }
        } else {
            buildLogger.addBuildLogEntry("Scan By ControllerAPI....");
            controllerScanner = new ControllerScanner(taskContext, processResult, scanConfig);
            controllerScanner.scan();
        }

        if (processResult.getScanResultString() != null && processResult.getScanResultString().length() > 0) {
            processScanReport(processResult);
        }

        try {
            writeReport(taskContext, processResult);
        } catch (IOException e) {
            buildLogger.addErrorLogEntry("IOExceptionJava: " + e.getMessage());
        } catch ( InterruptedException e) {
            buildLogger.addErrorLogEntry("InterruptedException: " + e.getMessage());
        }

        makeIfFailDecision(processResult);

        if (processResult.isSuccess()) {
            return builder.build();
        } else {
            return builder.failed().build();
        }
    }

    private void processScanReport(ProcessResult processResult) throws TaskException {
        String serverMessageFromScan = processResult.getScanResultString();
        ScanResult scanResult = processResult.getScanResult();

        int totalVulnerabilityNumber = 0;
        int totalHighSeverity = 0;
        int totalMediumSeverity = 0;

        boolean hasBlackListVuls = false;
        boolean hasWhiteListVuls = false;
        Set<String> existedBlackListVulSet = new HashSet<>();
        Set<String> existedWhiteListVulSet = new HashSet<>();
        Set<Vulnerability> highVulnerabilitySet = new HashSet<>();
        Set<Vulnerability> mediumVulnerabilitySet = new HashSet<>();

        JsonElement reportElement = JsonParser.parseString(serverMessageFromScan);
        if (!reportElement.isJsonObject()) {
            throw new TaskException("Scan report is not a valid JSON object.");
        }

        JsonObject reportObject = reportElement.getAsJsonObject();
        JsonObject reportJson = reportObject.getAsJsonObject("report");
        processResult.setScanResultJson(reportObject);

        JsonArray vulnerabilityArray = reportJson.getAsJsonArray("vulnerabilities");

        if (vulnerabilityArray == null || vulnerabilityArray.size() == 0) {
            scanResult.setTotalVulnerabilityNumber(totalVulnerabilityNumber);
            buildLogger.addErrorLogEntry("Scanned. No vulnerabilities found.");
        } else {
            for (int i = 0; i < vulnerabilityArray.size(); i++) {
                JsonObject vulnerabilityObject = vulnerabilityArray.get(i).getAsJsonObject();
                String name = vulnerabilityObject.get("name").getAsString().toLowerCase();
                String severity = vulnerabilityObject.get("severity").getAsString();
                if (!scanConfig.getVulBlackListSet().isEmpty() && scanConfig.getVulBlackListSet().contains(name)) {
                    hasBlackListVuls = true;
                    existedBlackListVulSet.add(name.toUpperCase());
                }

                if ( scanConfig.getVulWhiteListSet().isEmpty() || !scanConfig.getVulWhiteListSet().contains(name) ) {
                    totalVulnerabilityNumber = totalVulnerabilityNumber + 1;
                    Vulnerability vulnerability = new Vulnerability();

                    vulnerability.setName(name);
                    vulnerability.setLink(vulnerabilityObject.get("link").getAsString());
                    vulnerability.setScore(Float.valueOf(vulnerabilityObject.get("score").getAsString()));
                    vulnerability.setPackage_name(vulnerabilityObject.get("package_name").getAsString());
                    vulnerability.setPackage_version(vulnerabilityObject.get("package_version").getAsString());
                    vulnerability.setFixed_version(vulnerabilityObject.get("fixed_version").getAsString());
                    vulnerability.setVectors(vulnerabilityObject.get("vectors").getAsString());
                    vulnerability.setDescription(vulnerabilityObject.get("description").getAsString());
                    vulnerability.setFeed_rating(vulnerabilityObject.get("feed_rating").getAsString());

                    if (severity.equalsIgnoreCase("High")) {
                        totalHighSeverity = totalHighSeverity + 1;
                        vulnerability.setSeverity("High");
                        highVulnerabilitySet.add(vulnerability);
                    } else if (severity.equalsIgnoreCase("Medium")) {
                        totalMediumSeverity = totalMediumSeverity + 1;
                        vulnerability.setSeverity("Medium");
                        mediumVulnerabilitySet.add(vulnerability);
                    }

                } else {
                    hasWhiteListVuls = true;
                    existedWhiteListVulSet.add(name.toUpperCase());
                }
            }
        }
        // initial the scanResult with found blackListSet, whiteListSet,
        // total Vul number, total high severity number, total medium severity number
        // all high severity vul set and all medium severity vul set
        scanResult.setBlackListVulExisted(hasBlackListVuls);
        scanResult.setWhiteListVulExisted(hasWhiteListVuls);
        scanResult.setExistedBlackListVulSet(existedBlackListVulSet);
        scanResult.setExistedWhiteListVulSet(existedWhiteListVulSet);
        scanResult.setTotalVulnerabilityNumber(totalVulnerabilityNumber);
        scanResult.setHighSeverityNumber(totalHighSeverity);
        scanResult.setMediumSeverityNumber(totalMediumSeverity);
        scanResult.setHighVulnerabilitySet(highVulnerabilitySet);
        scanResult.setMediumVulnerabilitySet(mediumVulnerabilitySet);

        if (scanConfig.isScanLayers()) {
            if (reportJson.has("layers")) {
                JsonArray layerArray = reportJson.getAsJsonArray("layers");
                LinkedHashMap<String, Set<Vulnerability>> layeredVulnerabilityMap = new LinkedHashMap<String, Set<Vulnerability>>();
                for (int i = 0; i < layerArray.size(); i++) {
                    JsonObject layerObject = layerArray.get(i).getAsJsonObject();
                    int subStringLen = 12;
                    if( layerObject.get("digest").getAsString().length() < 12 ){
                        subStringLen = layerObject.get("digest").getAsString().length();
                    }
                    String layerDigest = layerObject.get("digest").getAsString().substring(0, subStringLen);
                    JsonArray layerVulnerabilityArray = layerObject.getAsJsonArray("vulnerabilities");
                    Set<Vulnerability> layeredVulnerabilitySet = new HashSet<>();

                    for (int j = 0; j < layerVulnerabilityArray.size(); j++) {
                        JsonObject layerVulnerabilityObject = layerVulnerabilityArray.get(j).getAsJsonObject();

                        String vulnerabilityName = layerVulnerabilityObject.get("name").getAsString().toLowerCase();
                        if(! (hasWhiteListVuls && scanConfig.getVulWhiteListSet().contains(vulnerabilityName))){
                            Vulnerability vulnerability = new Vulnerability();
                            vulnerability.setName(vulnerabilityName);
                            vulnerability.setScore(Float.valueOf(layerVulnerabilityObject.get("score").getAsString()));
                            vulnerability.setPackage_name(layerVulnerabilityObject.get("package_name").getAsString());
                            vulnerability.setPackage_version(layerVulnerabilityObject.get("package_version").getAsString());
                            vulnerability.setFixed_version(layerVulnerabilityObject.get("fixed_version").getAsString());
                            vulnerability.setLink(layerVulnerabilityObject.get("link").getAsString());
                            vulnerability.setFeed_rating(layerVulnerabilityObject.get("feed_rating").getAsString());
                            layeredVulnerabilitySet.add(vulnerability);
                        }
                        layeredVulnerabilityMap.put(layerDigest, layeredVulnerabilitySet);
                    }
                    scanResult.setLayeredVulsMap(layeredVulnerabilityMap);
                }
            } else {
                scanResult.setScanLayerSupported(false);
            }
        } else {
            scanResult.setScanLayerSupported(false);
        }
    }

    private void makeIfFailDecision(ProcessResult processResult) {
        int totalHighSeverity = processResult.getScanResult().getHighSeverityNumber();
        int totalMediumSeverity = processResult.getScanResult().getMediumSeverityNumber();
        boolean foundNameInBlackList = processResult.getScanResult().isBlackListVulExisted();
        Set<String> blackListToPresent = processResult.getScanResult().getExistedBlackListVulSet();

        boolean numberExceed = false;
        StringBuilder statementBuilder = new StringBuilder();

        if (scanConfig.getHighVul() != null && !scanConfig.getHighVul().trim().isEmpty()) {
            int configNumberOfHigh = Integer.parseInt(scanConfig.getHighVul().trim());
            if (configNumberOfHigh != 0 && configNumberOfHigh <= totalHighSeverity) {
                numberExceed = true;
                statementBuilder.append(totalHighSeverity).append(" High severity vulnerabilities");
            }
        }

        if (scanConfig.getMediumVul() != null && !scanConfig.getMediumVul().trim().isEmpty()) {
            int configNumberOfMedium = Integer.parseInt(scanConfig.getMediumVul().trim());
            if (configNumberOfMedium != 0 && configNumberOfMedium <= totalMediumSeverity) {
                if (numberExceed) {
                    statementBuilder.append(", ");
                }
                numberExceed = true;
                statementBuilder.append(totalMediumSeverity).append(" Medium severity vulnerabilities");
            }
        }

        if (foundNameInBlackList) {
            if (numberExceed) {
                statementBuilder.append(", and ");
            }
            numberExceed = true;
            statementBuilder.append("vulnerabilities: ").append(blackListToPresent.toString());
        }

        if (numberExceed) {
            statementBuilder.append(" are present.");
            buildLogger.addErrorLogEntry("Build failed because " + statementBuilder.toString());
            processResult.setSuccess(false);
        }
    }

    private void writeReport(final TaskContext taskContext, ProcessResult processResult) throws IOException, InterruptedException {
        writeHTMLReport(taskContext, processResult);
        writeJsonReport(taskContext, processResult);
    }

    public void writeJsonReport(final TaskContext taskContext, ProcessResult processResult) throws IOException {
        File reportJson = new File(taskContext.getWorkingDirectory(), "neuvector-report.json");
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(reportJson))) {
            JsonObject jsonContent = processResult.getScanResultJson();
            String prettyJsonString = new GsonBuilder().setPrettyPrinting().create().toJson(jsonContent);
            writer.write(prettyJsonString);
        } catch (IOException e) {
            buildLogger.addErrorLogEntry("IOException: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void writeHTMLReport(final TaskContext taskContext, ProcessResult processResult) throws IOException {
        ScanResult scanResult = processResult.getScanResult();
        File reportFile = new File(taskContext.getWorkingDirectory(), "neuvector-report.html");

        // Basic CSS styles. Replace with your actual CSS if needed.
        String cssStyles = "<style>" +
            "body { font-family: Arial, sans-serif; }" +
            "table { border-collapse: collapse; width: 100%; }" +
            "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }" +
            "th { background-color: #f2f2f2; }" +
            "</style>";

        // The HTML content should be well-formed. Close all opened tags.
        String htmlContent = "<!DOCTYPE html>\n" +
            "<html lang=\"en\">\n" +
            "<head>\n" +
            "<meta charset=\"UTF-8\">\n" +
            "<title>NeuVector Scan Report</title>\n" +
            cssStyles + // Include the CSS styles.
            "</head>\n" +
            "<body>\n" +
            "<h1>Scan Report</h1>\n" +
            "<h3>Summary</h3>\n" +
            "<table>\n" +
            "<tr>\n" +
            "<th>Registry URL</th>\n" +
            "<th>Repository</th>\n" +
            "<th>Tag</th>\n" +
            "<th>High severity VULs</th>\n" +
            "<th>High severity threshold</th>\n" +
            "<th>Medium severity VULs</th>\n" +
            "<th>Medium severity threshold</th>\n" +
            "<th>VULs to fail the build</th>\n" +
            "<th>Total VULs</th>\n" +
            "</tr>\n" +
            "<tr>\n" +
            "<td>" + escapeHtml(scanResult.getRegistry()) + "</td>\n" +
            "<td>" + escapeHtml(scanResult.getRepository()) + "</td>\n" +
            "<td>" + escapeHtml(scanResult.getTag()) + "</td>\n" +
            "<td>" + scanResult.getHighVulnerabilitySet().size() + "</td>\n" +
            "<td>" + (scanResult.getHighSeverityThreshold() != 0 ? scanResult.getHighSeverityThreshold() : "No Limit") + "</td>\n" +
            "<td>" + scanResult.getMediumVulnerabilitySet().size() + "</td>\n" +
            "<td>" + (scanResult.getMediumSeverityThreshold() != 0 ? scanResult.getMediumSeverityThreshold() : "No Limit") + "</td>\n" +
            "<td>" + escapeHtml(String.join(", ", scanResult.getExistedBlackListVulSet())) + "</td>\n" +
            "<td>" + scanResult.getTotalVulnerabilityNumber() + "</td>\n" +
            "</tr>\n" +
            "</table>\n" +
            "<h3>Vulnerabilities</h3>\n";

        // If no vulnerabilities found, display a message
        if (scanResult.getTotalVulnerabilityNumber() == 0) {
            htmlContent += "<p>Scanned. No vulnerabilities found.</p>\n";
        } else {
            htmlContent += "<table>\n" +
                "<tr>\n" +
                "<th>Name</th>\n" +
                "<th>Severity</th>\n" +
                "<th>Score</th>\n" +
                "<th>Package</th>\n" +
                "<th>Fixed_version</th>\n" +
                "<th>Vectors</th>\n" +
                "<th>Description</th>\n" +
                "<th>Feed_rating</th>\n" +
                "</tr>\n";

            // Add rows for high vulnerabilities
            for (Vulnerability vulnerability : scanResult.getHighVulnerabilitySet()) {
                htmlContent += getVulnerabilityRowHtml(vulnerability, "High");
            }

            // Add rows for medium vulnerabilities
            for (Vulnerability vulnerability : scanResult.getMediumVulnerabilitySet()) {
                htmlContent += getVulnerabilityRowHtml(vulnerability, "Medium");
            }

            htmlContent += "</table>\n";
        }

        // Closing tags for HTML document
        htmlContent += "</body>\n" +
            "</html>";

        // Writing the file with UTF-8 encoding.
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(reportFile))) {
            writer.write(htmlContent);
        }
        // No need for catch block here if you're just throwing the exceptions
    }

    private String getVulnerabilityRowHtml(Vulnerability vulnerability, String severity) {
        return "<tr>\n" +
            "<td><a target=\"_blank\" href=\"" + escapeHtml(vulnerability.getLink()) + "\">" +
            escapeHtml(vulnerability.getName()).toUpperCase() + "</a></td>\n" +
            "<td>" + severity + "</td>\n" +
            "<td>" + vulnerability.getScore() + "</td>\n" +
            "<td>" + escapeHtml(vulnerability.getPackage_name() + ":" + vulnerability.getPackage_version()) + "</td>\n" +
            "<td>" + escapeHtml(vulnerability.getFixed_version()) + "</td>\n" +
            "<td>" + escapeHtml(vulnerability.getVectors()) + "</td>\n" +
            "<td>" + escapeHtml(vulnerability.getDescription()) + "</td>\n" +
            "<td>" + escapeHtml(vulnerability.getFeed_rating()) + "</td>\n" +
            "</tr>\n";
    }

    private String escapeHtml(String text) {
        if (text == null) {
            return null; // Return null if the input string is null
        }
        
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#039;");
    }    
}
