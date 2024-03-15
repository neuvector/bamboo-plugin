package neuvector;

import com.atlassian.bamboo.configuration.AdministrationConfiguration;
import com.atlassian.bamboo.configuration.AdministrationConfigurationPersister;
import com.atlassian.bamboo.configuration.GlobalAdminAction;
import com.atlassian.spring.container.ContainerManager;

import java.net.InetAddress;

public class NeuVectorGlobalConfigurator extends GlobalAdminAction {
    private String controllerIP;
    private String controllerPort;
    private String nvUsername;
    private String nvPassword;
    private String registryURL;
    private String registryUsername;
    private String registryPassword;
    private String scannerRegistryURL;
    private String scannerImageRepository;
    private String scannerRegistryUsername;
    private String scannerRegistryPassword;

    public String execute() throws Exception {
        final AdministrationConfiguration adminConfig = (AdministrationConfiguration) ContainerManager.getComponent("administrationConfiguration");
        this.controllerIP = adminConfig.getSystemProperty("controllerIP");
        this.controllerPort = adminConfig.getSystemProperty("controllerPort");
        this.nvUsername = adminConfig.getSystemProperty("nvUsername");
        this.nvPassword = adminConfig.getSystemProperty("nvPassword");
        this.registryURL = adminConfig.getSystemProperty("registryURL");
        this.registryUsername = adminConfig.getSystemProperty("registryUsername");
        this.registryPassword = adminConfig.getSystemProperty("registryPassword");
        this.scannerRegistryURL = adminConfig.getSystemProperty("scannerRegistryURL");
        this.scannerImageRepository = adminConfig.getSystemProperty("scannerImageRepository");
        this.scannerRegistryUsername = adminConfig.getSystemProperty("scannerRegistryUsername");
        this.scannerRegistryPassword = adminConfig.getSystemProperty("scannerRegistryPassword");
        return "input";
    }

    public String save() {
        final AdministrationConfiguration adminConfig = (AdministrationConfiguration) ContainerManager.getComponent("administrationConfiguration");
        adminConfig.setSystemProperty("controllerIP", this.controllerIP);
        adminConfig.setSystemProperty("controllerPort", this.controllerPort);
        adminConfig.setSystemProperty("nvUsername", this.nvUsername);
        adminConfig.setSystemProperty("nvPassword", this.nvPassword);
        adminConfig.setSystemProperty("registryURL", this.registryURL);
        adminConfig.setSystemProperty("registryUsername", this.registryUsername);
        adminConfig.setSystemProperty("registryPassword", this.registryPassword);
        adminConfig.setSystemProperty("scannerRegistryURL", this.scannerRegistryURL);
        adminConfig.setSystemProperty("scannerImageRepository", this.scannerImageRepository);
        adminConfig.setSystemProperty("scannerRegistryUsername", this.scannerRegistryUsername);
        adminConfig.setSystemProperty("scannerRegistryPassword", this.scannerRegistryPassword);

        ((AdministrationConfigurationPersister) ContainerManager.getComponent("administrationConfigurationPersister")).saveAdministrationConfiguration(adminConfig);
        this.addActionMessage("NeuVector Global Configuration Successfully Saved");
        return "success";
    }

    public boolean checkControllerIP(final String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
        } catch (Exception e) {
            this.addActionError("Please enter a valid IP without http:// or https:// for Controller IP");
            return false;
        }
        return true;
    }

    public boolean checkControllerPort(final String value) {
        try {
            if (value == null || Integer.parseInt(value.trim()) < 0) {
                this.addActionError("Please enter a number for Controller Port");
                return false;
            }
            return true;
        } catch (NumberFormatException e) {
            this.addActionError("Please enter a number for Controller Port");
            return false;
        }
    }

    public String getControllerIP() {
        return this.controllerIP;
    }

    public void setControllerIP(String controllerIP) {
        this.controllerIP = controllerIP;
    }

    public String getControllerPort() {
        return this.controllerPort;
    }

    public void setControllerPort(String controllerPort) {
        this.controllerPort = controllerPort;
    }

    public String getNvUsername() {
        return this.nvUsername;
    }

    public void setNvUsername(String nvUsername) {
        this.nvUsername = nvUsername;
    }

    public String getNvPassword() {
        return this.nvPassword;
    }

    public void setNvPassword(String nvPassword) {
        this.nvPassword = nvPassword;
    }

    public String getRegistryURL() {
        return this.registryURL;
    }

    public void setRegistryURL(String registryURL) {
        this.registryURL = registryURL;
    }

    public String getRegistryUsername() {
        return this.registryUsername;
    }

    public void setRegistryUsername(String registryUsername) {
        this.registryUsername = registryUsername;
    }

    public String getRegistryPassword() {
        return this.registryPassword;
    }

    public void setRegistryPassword(String registryPassword) {
        this.registryPassword = registryPassword;
    }

    public String getScannerRegistryURL() {
        return this.scannerRegistryURL;
    }

    public void setScannerRegistryURL(String scannerRegistryURL) {
        this.scannerRegistryURL = scannerRegistryURL;
    }

    public String getScannerImageRepository() {
        return this.scannerImageRepository;
    }

    public void setScannerImageRepository(String scannerImageRepository) {
        this.scannerImageRepository = scannerImageRepository;
    }

    public String getScannerRegistryUsername() {
        return this.scannerRegistryUsername;
    }

    public void setScannerRegistryUsername(String scannerRegistryUsername) {
        this.scannerRegistryUsername = scannerRegistryUsername;
    }

    public String getScannerRegistryPassword() {
        return this.scannerRegistryPassword;
    }

    public void setScannerRegistryPassword(String scannerRegistryPassword) {
        this.scannerRegistryPassword = scannerRegistryPassword;
    } 
}