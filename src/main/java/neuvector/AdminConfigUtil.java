package neuvector;

import com.atlassian.spring.container.ContainerManager;
import com.atlassian.bamboo.configuration.AdministrationConfiguration;
import org.apache.commons.lang.StringUtils;

public abstract class AdminConfigUtil
{
    private static AdministrationConfiguration adminConfig;
    
    public static String getAdminConfig(final String key) {
        if (AdminConfigUtil.adminConfig == null) {
            AdminConfigUtil.adminConfig = (AdministrationConfiguration) ContainerManager.getComponent("administrationConfiguration");
        }
        return StringUtils.defaultString(AdminConfigUtil.adminConfig.getSystemProperty(key));
    }
}