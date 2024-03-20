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
import java.util.stream.Collectors;

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
                    vulnerability.setFile_name(vulnerabilityObject.get("file_name").getAsString());
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
                scanResult.setScanLayerSupported(true);
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
                            vulnerability.setFile_name(layerVulnerabilityObject.get("file_name").getAsString());
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
        writeJsonReport(taskContext, processResult);
        writeTxtReport(taskContext, processResult);
        writeHTMLReport(taskContext, processResult);
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

    public void writeTxtReport(final TaskContext taskContext, ProcessResult processResult) throws IOException {
        ScanResult scanResult = processResult.getScanResult();
        File reportFile = new File(taskContext.getWorkingDirectory(), "neuvector-report.txt");

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(reportFile))) {
            // Report header
            writer.write("************************ Scan Report ************************\n");
            if (!scanResult.isLocalScan()) {
                writer.write("Registry URL: " + scanResult.getRegistry() + "\n");
            }
            writer.write("Repository: " + scanResult.getRepository() + "\n");
            writer.write("Tag: " + scanResult.getTag() + "\n");
            writer.write("High severity vulnerabilities: " + scanResult.getHighSeverityNumber() + "\n");
            writer.write("Medium severity vulnerabilities: " + scanResult.getMediumSeverityNumber() + "\n");
            writer.write("Total vulnerabilities: " + scanResult.getTotalVulnerabilityNumber() + "\n");
            writer.write("********************** Vulnerabilities **********************\n\n");

            // Handling if no vulnerabilities are found
            if (scanResult.getTotalVulnerabilityNumber() == 0) {
                writer.write("Scanned. No vulnerabilities found.\n");
            } else {
                // Detailed vulnerabilities
                for (Vulnerability vulnerability : scanResult.getHighVulnerabilitySet()) {
                    writeTxtReportVulnerabilityDetails(writer, vulnerability, "High");
                }
                for (Vulnerability vulnerability : scanResult.getMediumVulnerabilitySet()) {
                    writeTxtReportVulnerabilityDetails(writer, vulnerability, "Medium");
                }
            }

            // Layer Vulnerability History
            if(scanResult.isScanLayerSupported()) {
                writer.write("\n**************** Layer Vulnerability History ****************\n");
                Set<String> keys = scanResult.getLayeredVulsMap().keySet();
                for(String key : keys){
                    Set<Vulnerability> vulSet = scanResult.getLayeredVulsMap().get(key);
                    writer.write("Layer digest " + key + " contains " + vulSet.size() + " vulnerabilities.\n");
                    for(Vulnerability vulnerability: vulSet){
                        writeTxtReportVulnerabilityDetails(writer, vulnerability, vulnerability.getSeverity()); // Assuming getSeverity() method exists
                    }
                }
            } else if (scanResult.isScanLayerConfigured()) {
                writer.write("\n*** Your Controller Does Not Support Layer Vulnerability Scan ***\n");
            }

            // Exempted Vulnerabilities
            if(scanResult.isWhiteListVulExisted()) {
                writer.write("\n********************** Exempt Vulnerability **********************\n");
                for(String exemptedVul : scanResult.getExistedWhiteListVulSet()){
                    writer.write("The vulnerability " + exemptedVul.toUpperCase() + " is exempt.\n");
                }
            }

        } catch (IOException e) {
            System.err.println("IOException: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Helper method to write vulnerability details
    private void writeTxtReportVulnerabilityDetails(BufferedWriter writer, Vulnerability vulnerability, String severity) throws IOException {
        writer.write("Name: " + vulnerability.getName().toUpperCase() + "\n");
        writer.write("Severity: " + severity + "\n");
        writer.write("Score: " + vulnerability.getScore() + "\n");
        writer.write("Package: " + vulnerability.getPackage_name() + ":" + vulnerability.getPackage_version() + "\n");
        writer.write("Filename: " + vulnerability.getFile_name() + "\n");
        writer.write("Fixed version: " + vulnerability.getFixed_version() + "\n");
        writer.write("Vectors: " + vulnerability.getVectors() + "\n");
        writer.write("Description: " + vulnerability.getDescription() + "\n");
        writer.write("Link: " + vulnerability.getLink() + "\n\n");
    }

    public void writeHTMLReport(final TaskContext taskContext, ProcessResult processResult) throws IOException {
        ScanResult scanResult = processResult.getScanResult();
        File reportFile = new File(taskContext.getWorkingDirectory(), "neuvector-report.html");
    
        StringBuilder htmlContent = new StringBuilder();
    
        // Basic CSS styles
        String cssStyles = "<style>" +
            "body { font-family: Arial, sans-serif; }" +
            "table { border-collapse: collapse; width: 100%; }" +
            "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }" +
            "th { background-color: #f2f2f2; }" +
            "</style>";
    
        // Start building the HTML content
        htmlContent.append("<!DOCTYPE html>\n")
            .append("<html lang=\"en\">\n")
            .append("<head>\n")
            .append("<meta charset=\"UTF-8\">\n")
            .append("<title>NeuVector Scan Report</title>\n")
            .append(cssStyles)
            .append("</head>\n")
            .append("<body>\n")
            .append("<h1>Scan Report</h1>\n")
            .append("<h3>Summary</h3>\n")
            .append("<table>\n")
            .append("<tr>\n")
            .append("<th>Registry URL</th>\n")
            .append("<th>Repository</th>\n")
            .append("<th>Tag</th>\n")
            .append("<th>High severity VULs</th>\n")
            .append("<th>High severity threshold</th>\n")
            .append("<th>Medium severity VULs</th>\n")
            .append("<th>Medium severity threshold</th>\n")
            .append("<th>VULs to fail the build</th>\n")
            .append("<th>Total VULs</th>\n")
            .append("</tr>\n")
            .append("<tr>\n")
            .append("<td>").append(escapeHtml(scanResult.getRegistry())).append("</td>\n")
            .append("<td>").append(escapeHtml(scanResult.getRepository())).append("</td>\n")
            .append("<td>").append(escapeHtml(scanResult.getTag())).append("</td>\n")
            .append("<td>").append(Integer.toString(scanResult.getHighVulnerabilitySet().size())).append("</td>\n")
            .append("<td>").append(scanResult.getHighSeverityThreshold() != 0 ? Integer.toString(scanResult.getHighSeverityThreshold()) : "No Limit").append("</td>\n")
            .append("<td>").append(Integer.toString(scanResult.getMediumVulnerabilitySet().size())).append("</td>\n")
            .append("<td>").append(scanResult.getMediumSeverityThreshold() != 0 ? Integer.toString(scanResult.getMediumSeverityThreshold()) : "No Limit").append("</td>\n")
            .append("<td>").append(escapeHtml(String.join(", ", scanResult.getExistedBlackListVulSet()))).append("</td>\n")
            .append("<td>").append(Integer.toString(scanResult.getTotalVulnerabilityNumber())).append("</td>\n")
            .append("</tr>\n")
            .append("</table>\n");
    
        // Append vulnerabilities section
        if (scanResult.getTotalVulnerabilityNumber() > 0) {
            htmlContent.append("<h3>Vulnerabilities</h3>\n")
                .append("<table>\n")
                .append("<tr>\n")
                .append("<th>Name</th>\n")
                .append("<th>Severity</th>\n")
                .append("<th>Score</th>\n")
                .append("<th>Package</th>\n")
                .append("<th>Filename</th>\n")
                .append("<th>Fixed_version</th>\n")
                .append("<th>Vectors</th>\n")
                .append("<th>Description</th>\n")
                .append("<th>Feed_rating</th>\n")
                .append("</tr>\n");
            // High vulnerabilities
            for (Vulnerability vulnerability : scanResult.getHighVulnerabilitySet()) {
                htmlContent.append(getVulnerabilityRowHtml(vulnerability, "High"));
            }
            // Medium vulnerabilities
            for (Vulnerability vulnerability : scanResult.getMediumVulnerabilitySet()) {
                htmlContent.append(getVulnerabilityRowHtml(vulnerability, "Medium"));
            }
            htmlContent.append("</table>\n");
        } else {
            htmlContent.append("<p>No vulnerabilities found.</p>\n");
        }
    
        if(scanResult.isScanLayerSupported()){
            htmlContent.append("<h3> Layer Vulnerability History </h3>\n");
            Set<String> keys = scanResult.getLayeredVulsMap().keySet();
            for(String key : keys){
                Set<Vulnerability> vulSet = scanResult.getLayeredVulsMap().get(key);
                htmlContent.append("<p>Layer digest ").append(key).append(" contains ").append(vulSet.size()).append(" vulnerabilities.</p>\n");
                if(!vulSet.isEmpty()){
                    htmlContent.append("<table>\n")
                        .append("    <tr>\n")
                        .append("        <th>Name</th>\n")
                        .append("        <th>Score</th>\n")
                        .append("        <th>Package</th>\n")
                        .append("        <th>Filename</th>\n")
                        .append("        <th>Fixed_version</th>\n")
                        .append("        <th>Link</th>\n")
                        .append("        <th>Feed_rating</th>\n")
                        .append("    </tr>\n");
    
                    for (Vulnerability vulnerability : vulSet) {
                        htmlContent.append("<tr>\n")
                            .append("<td><a target=\"_parent\" href=\"").append(escapeHtml(vulnerability.getLink())).append("\">").append(escapeHtml(vulnerability.getName())).append("</a></td>\n")
                            .append("<td>").append(vulnerability.getScore()).append("</td>\n")
                            .append("<td>").append(escapeHtml(vulnerability.getPackage_name())).append(":").append(escapeHtml(vulnerability.getPackage_version())).append("</td>\n")
                            .append("<td>").append(escapeHtml(vulnerability.getFile_name())).append("</td>\n")
                            .append("<td>").append(escapeHtml(vulnerability.getFixed_version())).append("</td>\n")
                            .append("<td><a href=\"").append(escapeHtml(vulnerability.getLink())).append("\" target=\"_blank\">Link</a></td>\n")
                            .append("<td>").append(escapeHtml(vulnerability.getFeed_rating())).append("</td>\n")
                            .append("</tr>\n");
                    }
                    htmlContent.append("</table>\n");
                }
            }
        }else{
            htmlContent.append("<p> Your Controller Does Not Support Layer Vulnerability Scan </p>\n");
        }
        
        // Output the found exempted vulnerabilities
        if(scanResult.isWhiteListVulExisted()){
            htmlContent.append("<h3>Exempted Vulnerabilities</h3>\n");
            if(scanResult.getExistedWhiteListVulSet().size() == 1){
                htmlContent.append("<p> ").append(escapeHtml(scanResult.getExistedWhiteListVulSet().iterator().next().toUpperCase())).append(" </p>\n");
            }else{
                htmlContent.append("<p> ").append(String.join(", ", scanResult.getExistedWhiteListVulSet().stream().map(this::escapeHtml).collect(Collectors.toList()))).append(" </p>\n");
            }
        }
        
        // Close the HTML content
        htmlContent.append("</body>\n</html>");
    
        // Write the HTML content to file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(reportFile))) {
            writer.write(htmlContent.toString());
        }
    }
    
    private String getVulnerabilityRowHtml(Vulnerability vulnerability, String severity) {
        return "<tr>\n" +
            "<td><a target=\"_blank\" href=\"" + escapeHtml(vulnerability.getLink()) + "\">" +
            escapeHtml(vulnerability.getName()).toUpperCase() + "</a></td>\n" +
            "<td>" + severity + "</td>\n" +
            "<td>" + vulnerability.getScore() + "</td>\n" +
            "<td>" + escapeHtml(vulnerability.getPackage_name()) + ":" + escapeHtml(vulnerability.getPackage_version()) + "</td>\n" +
            "<td>" + escapeHtml(vulnerability.getFile_name()) + "</td>\n" +
            "<td>" + escapeHtml(vulnerability.getFixed_version()) + "</td>\n" +
            "<td>" + escapeHtml(vulnerability.getVectors()) + "</td>\n" +
            "<td>" + escapeHtml(vulnerability.getDescription()) + "</td>\n" +
            "<td>" + escapeHtml(vulnerability.getFeed_rating()) + "</td>\n" +
            "</tr>\n";
    }
    
    private String escapeHtml(String text) {
        if (text == null) {
            return ""; // Return an empty string if the input string is null
        }
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#039;");
    }
}   