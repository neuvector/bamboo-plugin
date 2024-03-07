package neuvector;

import com.atlassian.bamboo.configuration.AdministrationConfiguration;
import com.atlassian.bamboo.configuration.AdministrationConfigurationPersister;
import com.atlassian.bamboo.configuration.GlobalAdminAction;
import com.atlassian.spring.container.ContainerManager;
import java.net.URL;
import org.apache.commons.lang.StringUtils;

public class NeuVectorGlobalConfigurator extends GlobalAdminAction {
    private String controllerIP;
    private String controllerPort;
    private String nvUsername;
    private String nvPassword;
    private String registryURL;
    private String registryUsername;
    private String registryPassword;

    public String execute() throws Exception {
        final AdministrationConfiguration adminConfig = (AdministrationConfiguration) ContainerManager.getComponent("administrationConfiguration");
        this.controllerIP = adminConfig.getSystemProperty("controllerIP");
        this.controllerPort = adminConfig.getSystemProperty("controllerPort");
        this.nvUsername = adminConfig.getSystemProperty("nvUsername");
        this.nvPassword = adminConfig.getSystemProperty("nvPassword");
        this.registryURL = adminConfig.getSystemProperty("registryURL");
        this.registryUsername = adminConfig.getSystemProperty("registryUsername");
        this.registryPassword = adminConfig.getSystemProperty("registryPassword");
        return "input";
    }

    public String save() {
        final boolean isValidIP = checkControllerIP(this.controllerIP);
        final boolean isValidPort = checkControllerPort(this.controllerPort);
        final boolean isValidUsername = checkUser(this.nvUsername);
        final boolean isValidPassword = checkPassword(this.nvPassword);
        if (!isValidIP || !isValidPort || !isValidUsername || !isValidPassword) {
            return "error";
        }
        final AdministrationConfiguration adminConfig = (AdministrationConfiguration) ContainerManager.getComponent("administrationConfiguration");
        adminConfig.setSystemProperty("controllerIP", this.controllerIP);
        adminConfig.setSystemProperty("controllerPort", this.controllerPort);
        adminConfig.setSystemProperty("nvUsername", this.nvUsername);
        adminConfig.setSystemProperty("nvPassword", this.nvPassword);
        adminConfig.setSystemProperty("registryURL", this.registryURL);
        adminConfig.setSystemProperty("registryUsername", this.registryUsername);
        adminConfig.setSystemProperty("registryPassword", this.registryPassword);
        ((AdministrationConfigurationPersister) ContainerManager.getComponent("administrationConfigurationPersister")).saveAdministrationConfiguration(adminConfig);
        this.addActionMessage("NeuVector Global Configuration Successfully Saved");
        return "success";
    }

    private boolean checkControllerIP(final String value) {
        if (value == null || value.trim().isEmpty() || value.trim().matches("^(http|https)://.*$")) {
            this.addActionError("Please enter a valid IP without http:// or https:// for Controller IP");
            return false;
        }
        return true;
    }

    private boolean checkControllerPort(final String value) {
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

    private boolean checkUser(final String value) {
        if (value == null || value.trim().isEmpty()) {
            this.addActionError("Please enter a valid NeuVector Username");
            return false;
        }
        return true;
    }

    private boolean checkPassword(final String value) {
        if (value == null || value.trim().isEmpty()) {
            this.addActionError("Please enter a valid NeuVector Password");
            return false;
        }
        return true;
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
}
