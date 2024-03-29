package neuvector.report;


import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Set;

public class ScanResult {
    String errorMessage;
    String scanSummary;
    boolean isLocalScan;
    String registry;
    String repository;
    String tag;
    boolean blackListVulExisted;
    boolean whiteListVulExisted;
    Set<String> blackListVulSet = new HashSet<>();
    Set<String> whiteListVulSet = new HashSet<>();
    Set<String> existedBlackListVulSet = new HashSet<>();
    Set<String> existedWhiteListVulSet = new HashSet<>();
    boolean isSeverityScaleCustomized;
    double customizedHighSeverityScale;
    double customizedMediumSeverityScale;
    int highSeverityThreshold;
    int mediumSeverityThreshold;
    int highSeverityNumber; // total found high severity vuls number
    int mediumSeverityNumber; // total found medium severity vuls number
    int totalVulnerabilityNumber; // total vuls number
    Set<Vulnerability> highVulnerabilitySet = new HashSet<>();
    Set<Vulnerability> mediumVulnerabilitySet = new HashSet<>();
    boolean scanLayerConfigured;
    boolean scanLayerSupported;
    int numberOfLayers;
    LinkedHashMap<String, Set<Vulnerability>> layeredVulsMap = new LinkedHashMap<>();


    public String getScanSummary() {
        return scanSummary;
    }

    public void setScanSummary(String scanSummary) {
        this.scanSummary = scanSummary;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public int getHighSeverityNumber() {
        return highSeverityNumber;
    }

    public void setHighSeverityNumber(int highSeverityNumber) {
        this.highSeverityNumber = highSeverityNumber;
    }

    public int getMediumSeverityNumber() {
        return mediumSeverityNumber;
    }

    public void setMediumSeverityNumber(int mediumSeverityNumber) {
        this.mediumSeverityNumber = mediumSeverityNumber;
    }

    public boolean isLocalScan() {
        return isLocalScan;
    }

    public void setLocalScan(boolean localScan) {
        isLocalScan = localScan;
    }

    public String getRegistry() {
        return registry;
    }

    public void setRegistry(String registry) {
        this.registry = registry;
    }

    public String getRepository() {
        return repository;
    }

    public void setRepository(String repository) {
        this.repository = repository;
    }

    public String getTag() {
        return tag;
    }

    public void setTag(String tag) {
        this.tag = tag;
    }

    public boolean isBlackListVulExisted() {
        return blackListVulExisted;
    }

    public void setBlackListVulExisted(boolean blackListVulExisted) {
        this.blackListVulExisted = blackListVulExisted;
    }

    public boolean isWhiteListVulExisted() {
        return whiteListVulExisted;
    }

    public void setWhiteListVulExisted(boolean whiteListVulExisted) {
        this.whiteListVulExisted = whiteListVulExisted;
    }

    public Set<String> getBlackListVulSet() {
        return blackListVulSet;
    }

    public void setBlackListVulSet(Set<String> blackListVulSet) {
        this.blackListVulSet = blackListVulSet;
    }

    public Set<String> getWhiteListVulSet() {
        return whiteListVulSet;
    }

    public void setWhiteListVulSet(Set<String> whiteListVulSet) {
        this.whiteListVulSet = whiteListVulSet;
    }

    public Set<String> getExistedBlackListVulSet() {
        return existedBlackListVulSet;
    }

    public void setExistedBlackListVulSet(Set<String> existedBlackListVulSet) {
        this.existedBlackListVulSet = existedBlackListVulSet;
    }

    public Set<String> getExistedWhiteListVulSet() {
        return existedWhiteListVulSet;
    }

    public void setExistedWhiteListVulSet(Set<String> existedWhiteListVulSet) {
        this.existedWhiteListVulSet = existedWhiteListVulSet;
    }

    public boolean isSeverityScaleCustomized() {
        return isSeverityScaleCustomized;
    }

    public void setSeverityScaleCustomized(boolean severityScaleCustomized) {
        isSeverityScaleCustomized = severityScaleCustomized;
    }

    public double getCustomizedHighSeverityScale() {
        return customizedHighSeverityScale;
    }

    public void setCustomizedHighSeverityScale(double customizedHighSeverityScale) {
        this.customizedHighSeverityScale = customizedHighSeverityScale;
    }

    public double getCustomizedMediumSeverityScale() {
        return customizedMediumSeverityScale;
    }

    public void setCustomizedMediumSeverityScale(double customizedMediumSeverityScale) {
        this.customizedMediumSeverityScale = customizedMediumSeverityScale;
    }

    public int getHighSeverityThreshold() {
        return highSeverityThreshold;
    }

    public void setHighSeverityThreshold(int highSeverityThreshold) {
        this.highSeverityThreshold = highSeverityThreshold;
    }

    public int getMediumSeverityThreshold() {
        return mediumSeverityThreshold;
    }

    public void setMediumSeverityThreshold(int mediumSeverityThreshold) {
        this.mediumSeverityThreshold = mediumSeverityThreshold;
    }

    public int getTotalVulnerabilityNumber() {
        return totalVulnerabilityNumber;
    }

    public void setTotalVulnerabilityNumber(int totalVulnerabilityNumber) {
        this.totalVulnerabilityNumber = totalVulnerabilityNumber;
    }

    public Set<Vulnerability> getHighVulnerabilitySet() {
        return highVulnerabilitySet;
    }

    public void setHighVulnerabilitySet(Set<Vulnerability> highVulnerabilitySet) {
        this.highVulnerabilitySet = highVulnerabilitySet;
    }

    public Set<Vulnerability> getMediumVulnerabilitySet() {
        return mediumVulnerabilitySet;
    }

    public void setMediumVulnerabilitySet(Set<Vulnerability> mediumVulnerabilitySet) {
        this.mediumVulnerabilitySet = mediumVulnerabilitySet;
    }

    public boolean isScanLayerConfigured() {
        return scanLayerConfigured;
    }

    public void setScanLayerConfigured(boolean scanLayerConfigured) {
        this.scanLayerConfigured = scanLayerConfigured;
    }

    public boolean isScanLayerSupported() {
        return scanLayerSupported;
    }

    public void setScanLayerSupported(boolean scanLayerSupported) {
        this.scanLayerSupported = scanLayerSupported;
    }

    public int getNumberOfLayers() {
        return numberOfLayers;
    }

    public void setNumberOfLayers(int numberOfLayers) {
        this.numberOfLayers = numberOfLayers;
    }

    public LinkedHashMap<String, Set<Vulnerability>> getLayeredVulsMap() {
        return layeredVulsMap;
    }

    public void setLayeredVulsMap(LinkedHashMap<String, Set<Vulnerability>> layeredVulsMap) {
        this.layeredVulsMap = layeredVulsMap;
    }
}
