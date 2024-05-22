package neuvector;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import com.atlassian.bamboo.task.TaskContext;
import neuvector.report.*;

public class ScanConfig {
    private String token;
    private String registryType;
    private String repository;
    private String tag;
    private boolean scanLayers;
    private boolean enableStandalone;
    private boolean sendReportToController;
    private String highVul;
    private String mediumVul;
    private String controllerIP;
    private String controllerPortString;
    private int controllerPort;
    private String nvUsername;
    private String nvPassword;
    private String registryURL;
    private String registryUsername;
    private String registryPassword;
    private String scannerRegistryURL;
    private String scannerImageRepository;
    private String scannerRegistryUsername;
    private String scannerRegistryPassword;

    private Set<String> vulBlackListSet;
    private Set<String> vulWhiteListSet;

    public ScanConfig(final TaskContext taskContext, ProcessResult processResult) {
        enableStandalone = Boolean.valueOf((String)taskContext.getConfigurationMap().get("enableStandalone"));
        sendReportToController = Boolean.valueOf((String)taskContext.getConfigurationMap().get("sendReportToController"));

        repository = (String)taskContext.getConfigurationMap().get("repository");
        scanLayers = Boolean.valueOf((String)taskContext.getConfigurationMap().get("scanLayers"));
        highVul = (String)taskContext.getConfigurationMap().get("highVul");
        mediumVul = (String)taskContext.getConfigurationMap().get("mediumVul");
        tag = (String)taskContext.getConfigurationMap().get("tag");
        
        registryType = (String)taskContext.getConfigurationMap().get("registryType");
        if (registryType != null && registryType.equals("custom")) {
            registryURL = (String)taskContext.getConfigurationMap().get("customRegistryURL");
            registryUsername = (String)taskContext.getConfigurationMap().get("customRegistryUsername");
            registryPassword = (String)taskContext.getConfigurationMap().get("customRegistryPassword");
        } else {
            registryURL = AdminConfigUtil.getAdminConfig("registryURL");
            registryUsername = AdminConfigUtil.getAdminConfig("registryUsername");
            registryPassword = AdminConfigUtil.getAdminConfig("registryPassword");
        }
        
        ScanResult scanResult = processResult.getScanResult();

        scanResult.setRepository(repository);
        scanResult.setTag(tag);

        int highSeverityThreshold = 0;
        if(!highVul.isEmpty()){
            try {
                highSeverityThreshold = Integer.parseInt(highVul);
            } finally {
                scanResult.setHighSeverityThreshold(highSeverityThreshold);
            }
        }

        int mediumSeverityThreshold = 0;
        if(!mediumVul.isEmpty()){
            try {
                mediumSeverityThreshold = Integer.parseInt(mediumVul);
            } finally {
                scanResult.setMediumSeverityThreshold(mediumSeverityThreshold);
            }
        }

        String storedVulnsToFail = (String)taskContext.getConfigurationMap().get("vulnerabilitiesToFail").toLowerCase();
        String storedVulnsToExempt = (String)taskContext.getConfigurationMap().get("vulnerabilitiesToExempt").toLowerCase();

        // Convert comma-separated strings to lists
        List<String>  vulnerabilitiesToFail = StringUtils.isNotBlank(storedVulnsToFail) ? 
                                Arrays.asList(storedVulnsToFail.split(",")) : 
                                new ArrayList<>();

        List<String>  vulnerabilitiesToExempt = StringUtils.isNotBlank(storedVulnsToExempt) ? 
                                    Arrays.asList(storedVulnsToExempt.split(",")) : 
                                    new ArrayList<>();

        vulBlackListSet = new HashSet<>(vulnerabilitiesToFail);
        vulWhiteListSet = new HashSet<>(vulnerabilitiesToExempt);
        scanResult.setBlackListVulSet(vulBlackListSet);
        scanResult.setWhiteListVulSet(vulWhiteListSet);

        controllerIP = AdminConfigUtil.getAdminConfig("controllerIP");
        controllerPortString = AdminConfigUtil.getAdminConfig("controllerPort");
        nvUsername = AdminConfigUtil.getAdminConfig("nvUsername");
        nvPassword = AdminConfigUtil.getAdminConfig("nvPassword");

        scannerRegistryURL = AdminConfigUtil.getAdminConfig("scannerRegistryURL");
        scannerImageRepository = AdminConfigUtil.getAdminConfig("scannerImageRepository");
        scannerRegistryUsername = AdminConfigUtil.getAdminConfig("scannerRegistryUsername");
        scannerRegistryPassword = AdminConfigUtil.getAdminConfig("scannerRegistryPassword");
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getRegistryType() {
        return registryType;
    }

    public void setRegistryType(String registryType) {
        this.registryType = registryType;
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

    public boolean isScanLayers() {
        return scanLayers;
    }

    public void setScanLayers(boolean scanLayers) {
        this.scanLayers = scanLayers;
    }

    public boolean isEnableStandalone() {
        return enableStandalone;
    }

    public void setEnableStandalone(boolean enableStandalone) {
        this.enableStandalone = enableStandalone;
    }

    public boolean isSendReportToController() {
        return sendReportToController;
    }

    public void setSendReportToController(boolean sendReportToController) {
        this.sendReportToController = sendReportToController;
    }

    public String getHighVul() {
        return highVul;
    }

    public void setHighVul(String highVul) {
        this.highVul = highVul;
    }

    public String getMediumVul() {
        return mediumVul;
    }

    public void setMediumVul(String mediumVul) {
        this.mediumVul = mediumVul;
    }

    public String getControllerIP() {
        return controllerIP;
    }

    public void setControllerIP(String controllerIP) {
        this.controllerIP = controllerIP;
    }

    public String getControllerPortString() {
        return controllerPortString;
    }

    public void setControllerPortString(String controllerPortString) {
        this.controllerPortString = controllerPortString;
    }

    public int getControllerPort() {
        return controllerPort;
    }

    public void setControllerPort(int controllerPort) {
        this.controllerPort = controllerPort;
    }

    public String getNvUsername() {
        return nvUsername;
    }

    public void setNvUsername(String nvUsername) {
        this.nvUsername = nvUsername;
    }

    public String getNvPassword() {
        return nvPassword;
    }

    public void setNvPassword(String nvPassword) {
        this.nvPassword = nvPassword;
    }

    public String getRegistryURL() {
        return registryURL;
    }

    public void setRegistryURL(String registryURL) {
        this.registryURL = registryURL;
    }

    public String getRegistryUsername() {
        return registryUsername;
    }

    public void setRegistryUsername(String registryUsername) {
        this.registryUsername = registryUsername;
    }

    public String getRegistryPassword() {
        return registryPassword;
    }

    public void setRegistryPassword(String registryPassword) {
        this.registryPassword = registryPassword;
    }

    public String getScannerRegistryURL() {
        return scannerRegistryURL;
    }

    public void setScannerRegistryURL(String scannerRegistryURL) {
        this.scannerRegistryURL = scannerRegistryURL;
    }

    public String getScannerImageRepository() {
        return scannerImageRepository;
    }

    public void setScannerImageRepository(String scannerImageRepository) {
        this.scannerImageRepository = scannerImageRepository;
    }

    public String getScannerRegistryUsername() {
        return scannerRegistryUsername;
    }

    public void setScannerRegistryUsername(String scannerRegistryUsername) {
        this.scannerRegistryUsername = scannerRegistryUsername;
    }

    public String getScannerRegistryPassword() {
        return scannerRegistryPassword;
    }

    public void setScannerRegistryPassword(String scannerRegistryPassword) {
        this.scannerRegistryPassword = scannerRegistryPassword;
    }

    public Set<String> getVulBlackListSet() {
        return vulBlackListSet;
    }

    public void setVulBlackListSet(Set<String> vulBlackListSet) {
        this.vulBlackListSet = vulBlackListSet;
    }

    public Set<String> getVulWhiteListSet() {
        return vulWhiteListSet;
    }

    public void setVulWhiteListSet(Set<String> vulWhiteListSet) {
        this.vulWhiteListSet = vulWhiteListSet;
    }
}
