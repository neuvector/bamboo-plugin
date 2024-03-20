package neuvector;

import com.atlassian.bamboo.collections.ActionParametersMap;
import com.atlassian.bamboo.task.AbstractTaskConfigurator;
import com.atlassian.bamboo.task.TaskDefinition;
import com.atlassian.bamboo.utils.error.ErrorCollection;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.NotNull;

import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;
import java.util.stream.Collectors;

import com.opensymphony.xwork2.ActionContext;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.ImmutableMap;
import com.google.gson.Gson;

public class NeuVectorTaskConfigurator extends AbstractTaskConfigurator {    
    private Map<String, String> registryMap;
    private List<String> vulnerabilitiesToFail = new ArrayList<>();
    private List<String> vulnerabilitiesToExempt = new ArrayList<>();

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

        boolean enableStandaloneValue = params.getBoolean("enableStandalone");
        config.put("enableStandalone", Boolean.toString(enableStandaloneValue));

        try {
            HttpServletRequest request = getServletRequest();
            if (request != null) {
                Map<String, String[]> parameterMap = request.getParameterMap();
                config.put("vulnerabilitiesToFail", getJoinedParameterValues(parameterMap, "failVul"));
                config.put("vulnerabilitiesToExempt", getJoinedParameterValues(parameterMap, "exemptVul"));
            }
        } catch (Exception e) {
            System.out.println("Error processing dynamic form data: " + e.getMessage());
        }

        return config;
    }

    private String getJoinedParameterValues(Map<String, String[]> parameterMap, String paramNameStart) {
        return parameterMap.entrySet().stream()
                .filter(entry -> entry.getKey().startsWith(paramNameStart))
                .flatMap(entry -> Arrays.stream(entry.getValue()))
                .filter(StringUtils::isNotBlank)
                .collect(Collectors.joining(","));
    }

    public void populateContextForCreate(@NotNull final Map<String, Object> context) {
        super.populateContextForCreate(context);
        context.put("registryType", "global");
        context.put("registryMap", this.registryMap);
        context.put("enableStandalone", false);
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
        String enableStandaloneValue = taskDefinition.getConfiguration().get("enableStandalone");
        context.put("enableStandalone", Boolean.parseBoolean(enableStandaloneValue));

        String storedVulnsToFail = taskDefinition.getConfiguration().get("vulnerabilitiesToFail");
        String storedVulnsToExempt = taskDefinition.getConfiguration().get("vulnerabilitiesToExempt");

        // Convert comma-separated strings to lists
        vulnerabilitiesToFail = StringUtils.isNotBlank(storedVulnsToFail) ? 
                                Arrays.asList(storedVulnsToFail.split(",")) : 
                                new ArrayList<>();
        vulnerabilitiesToExempt = StringUtils.isNotBlank(storedVulnsToExempt) ? 
                                    Arrays.asList(storedVulnsToExempt.split(",")) : 
                                    new ArrayList<>();

        Gson gson = new Gson();
        String vulnerabilitiesToFailJson = gson.toJson(vulnerabilitiesToFail);
        String vulnerabilitiesToExemptJson = gson.toJson(vulnerabilitiesToExempt);

        context.put("vulnerabilitiesToFailJson", vulnerabilitiesToFailJson);
        context.put("vulnerabilitiesToExemptJson", vulnerabilitiesToExemptJson);
        
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

    private HttpServletRequest getServletRequest() {
        return (HttpServletRequest) ActionContext.getContext().get(org.apache.struts2.StrutsStatics.HTTP_REQUEST);
    }
}
