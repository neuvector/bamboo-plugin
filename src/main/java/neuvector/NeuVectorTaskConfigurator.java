package neuvector;

import com.atlassian.bamboo.collections.ActionParametersMap;
import com.atlassian.bamboo.task.AbstractTaskConfigurator;
import com.atlassian.bamboo.task.TaskDefinition;
import com.atlassian.bamboo.utils.error.ErrorCollection;
import com.google.common.collect.ImmutableMap;
import org.apache.commons.lang.StringUtils;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.NotNull;
import java.util.Map;

public class NeuVectorTaskConfigurator extends AbstractTaskConfigurator {    
    private Map<String, String> registryMap;

    public NeuVectorTaskConfigurator() {
        this.registryMap = ImmutableMap.of("global", "Use NeuVector Global Registry Configuration", "custom", "Use Custom Registry Configuration");
    }

    @NotNull
    public Map<String, String> generateTaskConfigMap(@NotNull final ActionParametersMap params, @Nullable final TaskDefinition previousTaskDefinition) {
        final Map<String, String> config = super.generateTaskConfigMap(params, previousTaskDefinition);
        String registryType = params.getString("registryType");
        config.put("registryType", registryType);
        config.put("repository", params.getString("repository"));
        config.put("tag", params.getString("tag"));
        config.put("scanLayers", params.getString("scanLayers"));
        config.put("highVul", params.getString("highVul"));
        config.put("mediumVul", params.getString("mediumVul"));
        if (registryType != null && registryType.equals("custom")) {
            config.put("customRegistryURL", params.getString("customRegistryURL"));
            config.put("customRegistryUsername", params.getString("customRegistryUsername"));
            config.put("customRegistryPassword", params.getString("customRegistryPassword"));
        }
        return config;
    }

    public void populateContextForCreate(@NotNull final Map<String, Object> context) {
        super.populateContextForCreate(context);
        context.put("registryType", "global");
        context.put("registryMap", this.registryMap);
    }

    public void populateContextForEdit(@NotNull final Map<String, Object> context, @NotNull final TaskDefinition taskDefinition) {
        super.populateContextForEdit(context, taskDefinition);
        String registryType = taskDefinition.getConfiguration().get("registryType");
        context.put("registryMap", this.registryMap);
        context.put("registryType", registryType);
        context.put("repository", taskDefinition.getConfiguration().get("repository"));
        context.put("tag", taskDefinition.getConfiguration().get("tag"));
        context.put("scanLayers", taskDefinition.getConfiguration().get("scanLayers"));
        context.put("highVul", taskDefinition.getConfiguration().get("highVul"));
        context.put("mediumVul", taskDefinition.getConfiguration().get("mediumVul"));
        if (registryType != null && registryType.equals("custom")) {
            context.put("customRegistryURL", taskDefinition.getConfiguration().get("customRegistryURL"));
            context.put("customRegistryUsername", taskDefinition.getConfiguration().get("customRegistryUsername"));
            context.put("customRegistryPassword", taskDefinition.getConfiguration().get("customRegistryPassword"));
        }
    }

    public void validate(@NotNull final ActionParametersMap params, @NotNull final ErrorCollection errorCollection) {
        super.validate(params, errorCollection);
        if (StringUtils.isBlank(params.getString("repository"))) {
            errorCollection.addError("repository", "Image repository is required");
        }
        if (StringUtils.isBlank(params.getString("tag"))) {
            errorCollection.addError("tag", "Image tag is required");
        }
    }
}
