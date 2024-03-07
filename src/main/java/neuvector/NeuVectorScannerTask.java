package neuvector;

import com.atlassian.bamboo.build.logger.BuildLogger;
import com.atlassian.bamboo.task.TaskContext;
import com.atlassian.bamboo.task.TaskException;
import com.atlassian.bamboo.task.TaskResult;
import com.atlassian.bamboo.task.TaskResultBuilder;
import com.atlassian.bamboo.task.TaskType;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.HttpEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;

public class NeuVectorScannerTask implements TaskType {
    private static final int HTTP_CLIENT_CONFIG_TIMEOUT_SECOND = 60;
    private String token;
    private String registryType;
    private String repository;
    private String tag;
    private boolean scanLayers;
    private String highVul;
    private String mediumVul;
    private String controllerIP;
    private int controllerPort;
    private String nvUsername;
    private String nvPassword;
    private String registryURL;
    private String registryUsername;
    private String registryPassword;
    private BuildLogger buildLogger;

    @Override
    public TaskResult execute(final TaskContext taskContext) throws TaskException {
        final TaskResultBuilder builder = TaskResultBuilder.newBuilder(taskContext).success();
        buildLogger = taskContext.getBuildLogger();
        registryType = (String)taskContext.getConfigurationMap().get("registryType");
        repository = (String)taskContext.getConfigurationMap().get("repository");
        tag = (String)taskContext.getConfigurationMap().get("tag");
        scanLayers = Boolean.valueOf((String)taskContext.getConfigurationMap().get("scanLayers"));
        highVul = (String)taskContext.getConfigurationMap().get("highVul");
        mediumVul = (String)taskContext.getConfigurationMap().get("mediumVul");
        controllerIP = AdminConfigUtil.getAdminConfig("controllerIP");
        String controllerPortString = AdminConfigUtil.getAdminConfig("controllerPort");
        nvUsername = AdminConfigUtil.getAdminConfig("nvUsername");
        nvPassword = AdminConfigUtil.getAdminConfig("nvPassword");

        if (registryType != null && registryType.equals("custom")) {
            registryURL = (String)taskContext.getConfigurationMap().get("customRegistryURL");
            registryUsername = (String)taskContext.getConfigurationMap().get("customRegistryUsername");
            registryPassword = (String)taskContext.getConfigurationMap().get("customRegistryPassword");
        } else {
            registryURL = AdminConfigUtil.getAdminConfig("registryURL");
            registryUsername = AdminConfigUtil.getAdminConfig("registryUsername");
            registryPassword = AdminConfigUtil.getAdminConfig("registryPassword");
        }

        if (controllerIP == null || controllerIP.trim().isEmpty()) {
            buildLogger.addErrorLogEntry("Please configure Controller IP.");
            return builder.failed().build();
        }

        if (controllerPortString == null || controllerPortString.trim().isEmpty()) {
            buildLogger.addErrorLogEntry("Please configure Controller Port.");
            return builder.failed().build();
        } else {
            try {
                controllerPort = Integer.parseInt(controllerPortString.trim());
            } catch (NumberFormatException e) {
                buildLogger.addErrorLogEntry("Please enter a number for Controller Port.");
                return builder.failed().build();
            }
        }

        try (CloseableHttpClient httpclient = makeHttpClient()) {
            getToken(httpclient);
            try {
                requestScan(httpclient);
            } finally {
                logout(httpclient);
            }
        } catch (TaskException e) {
            buildLogger.addErrorLogEntry(e.getMessage());
            return builder.failed().build();
        } catch (IOException e) {
            buildLogger.addErrorLogEntry("IOException when close httpclient. " + e.getMessage());
            return builder.failed().build();
        }

        return builder.build();
    }

    private CloseableHttpClient makeHttpClient() throws TaskException {
        SSLContextBuilder builder = new SSLContextBuilder();
        SSLConnectionSocketFactory sslsf;
        try {
            builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
            sslsf = new SSLConnectionSocketFactory(builder.build(), new TrustAllStrategy());
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            throw new TaskException("SSL context builder error.");
        }
        RequestConfig config = RequestConfig.custom().setConnectTimeout(HTTP_CLIENT_CONFIG_TIMEOUT_SECOND * 1000).build();
        return HttpClients.custom().setSSLSocketFactory(sslsf).setDefaultRequestConfig(config).build();
    }

    private void getToken(CloseableHttpClient httpclient) throws TaskException {
        String uriPathForGetToken = "/v1/auth";
        URI uriForGetToken = buildUri(controllerIP, controllerPort, uriPathForGetToken);

        HttpPost httpPostForGetToken = new HttpPost(uriForGetToken);
        httpPostForGetToken.addHeader("Content-Type", "application/json");

        JSONObject passwordJson = new JSONObject();
        passwordJson.put("username", nvUsername);
        passwordJson.put("password", nvPassword);
        JSONObject httpBodyJson = new JSONObject();
        httpBodyJson.put("password", passwordJson);

        try {
            httpPostForGetToken.setEntity(new StringEntity(httpBodyJson.toString()));
        } catch (UnsupportedEncodingException e) {
            throw new TaskException("Unsupported encoding from NeuVector Username and/or Password in global configuration.");
        }

        try (CloseableHttpResponse httpResponseFromGetToken = httpclient.execute(httpPostForGetToken)) {
            int statusCode = httpResponseFromGetToken.getStatusLine().getStatusCode();
            HttpEntity httpEntityFromGetToken = httpResponseFromGetToken.getEntity();
            String serverMessageFromGetToken = EntityUtils.toString(httpEntityFromGetToken);
            EntityUtils.consume(httpEntityFromGetToken);

            if (statusCode == 200) {
                token = JSONObject.fromObject(serverMessageFromGetToken).getJSONObject("token").getString("token");
            } else if (statusCode == 401 || statusCode == 404 || statusCode == 405) {
                throw new TaskException("Invalid credential of NeuVector controller");
            } else {
                throw new TaskException("Failed to get token. Http status code: " + statusCode + ". Message: " + serverMessageFromGetToken);
            }
        } catch (ClientProtocolException e) {
            throw new TaskException("Invalid NeuVector controller IP or port.");
        } catch (IOException e) {
            throw new TaskException("NeuVector controller connection error.");
        }
    }

    private void requestScan(CloseableHttpClient httpclient) throws TaskException, IOException {
        String uriPathForScan = "/v1/scan/repository";
        URI uriForScan = buildUri(controllerIP, controllerPort, uriPathForScan);

        HttpPost httpPostForScan = new HttpPost(uriForScan);
        httpPostForScan.addHeader("Content-Type", "application/json");
        httpPostForScan.addHeader("X-Auth-Token", token);

        JSONObject httpBodyJson = new JSONObject();
        JSONObject requestJson = new JSONObject();
        requestJson.put("repository", repository);
        if (tag != null) {
            requestJson.put("tag", tag);
        }

        requestJson.put("registry", registryURL);
        requestJson.put("username", registryUsername);
        requestJson.put("password", registryPassword);
        requestJson.put("scan_layers", scanLayers);

        httpBodyJson.put("request", requestJson);

        try {
            httpPostForScan.setEntity(new StringEntity(httpBodyJson.toString()));
        } catch (UnsupportedEncodingException e) {
            throw new TaskException("Unsupported encoding from registry, repository or tag.");
        }

        CloseableHttpResponse httpResponseFromScan = null;

        try {
            httpResponseFromScan = httpclient.execute(httpPostForScan);
            while (httpResponseFromScan.getStatusLine().getStatusCode() == 304) {
                httpResponseFromScan = httpclient.execute(httpPostForScan);
                buildLogger.addBuildLogEntry("Scanning in progress...");
            }

            int statusCode = httpResponseFromScan.getStatusLine().getStatusCode();
            HttpEntity httpEntityFromScan = httpResponseFromScan.getEntity();
            String serverMessageFromScan = "N/A";

            if (httpEntityFromScan != null) {
                serverMessageFromScan = EntityUtils.toString(httpEntityFromScan);
                EntityUtils.consume(httpEntityFromScan);
            }

            if (statusCode == 200 && httpEntityFromScan != null) {
                processScanReport(serverMessageFromScan);
            } else {
                throw new TaskException("Scan failed. Http status code: " + statusCode + ". Message: " + serverMessageFromScan);
            }
        } catch (IOException e) {
            throw new TaskException("NeuVector controller connection error.");
        } finally {
            if (httpResponseFromScan != null) {
                httpResponseFromScan.close();
            }
        }
    }

    private void logout(CloseableHttpClient httpclient) throws TaskException, IOException {
        String uriPathForLogout = "/v1/auth";
        URI uriForLogout = buildUri(controllerIP, controllerPort, uriPathForLogout);
        HttpDelete httpDeleteForLogout = new HttpDelete(uriForLogout);
        httpDeleteForLogout.addHeader("Content-Type", "application/json");
        httpDeleteForLogout.addHeader("X-Auth-Token", token);
        CloseableHttpResponse httpResponseFromLogout = httpclient.execute(httpDeleteForLogout);
        httpResponseFromLogout.close();
    }

    private URI buildUri(String host, int port, String path) throws TaskException {
        URI uri;
        try {
            uri = new URIBuilder().setScheme("https").setHost(host).setPort(port).setPath(path).build();
        } catch (URISyntaxException e) {
            throw new TaskException("URI syntax error from NeuVector Controller IP and/or API port in global configuration.");
        }
        return uri;
    }

    private void processScanReport(String serverMessageFromScan) throws TaskException {
        int currentHighSeverity = 0;
        int currentMediumSeverity = 0;

        buildLogger.addBuildLogEntry("");
        buildLogger.addBuildLogEntry("************************ Scan Report ************************");

        JSONObject reportJson = JSONObject.fromObject(serverMessageFromScan).getJSONObject("report");

        buildLogger.addBuildLogEntry("Registry URL: " + reportJson.getString("registry"));
        buildLogger.addBuildLogEntry("Repository: " + reportJson.getString("repository"));
        buildLogger.addBuildLogEntry("Tag: " + reportJson.getString("tag"));
        buildLogger.addBuildLogEntry("");
        buildLogger.addBuildLogEntry("********************** Vulnerabilities **********************");
        buildLogger.addBuildLogEntry("");

        JSONArray vulnerabilityArray = reportJson.getJSONArray("vulnerabilities");

        if (vulnerabilityArray.size() == 0) {
            buildLogger.addBuildLogEntry("Scanned. No vulnerabilities found.");
        } else {
            for (int i = 0; i < vulnerabilityArray.size(); i++) {
                JSONObject vulnerabilityObject = vulnerabilityArray.getJSONObject(i);

                int vulnerabilityNumber = i + 1;
                String name = vulnerabilityObject.getString("name").toLowerCase();
                String severity = vulnerabilityObject.getString("severity");

                buildLogger.addBuildLogEntry("********************** Vulnerability " + vulnerabilityNumber + " **********************");
                buildLogger.addBuildLogEntry("Name: " + name.toUpperCase());
                buildLogger.addBuildLogEntry("Score: " + vulnerabilityObject.get("score"));
                buildLogger.addBuildLogEntry("Severity: " + severity);
                buildLogger.addBuildLogEntry("Vectors: " + vulnerabilityObject.getString("vectors"));
                buildLogger.addBuildLogEntry("Description: " + vulnerabilityObject.getString("description"));
                buildLogger.addBuildLogEntry("Package_name: " + vulnerabilityObject.getString("package_name"));
                buildLogger.addBuildLogEntry("Package_version: " + vulnerabilityObject.getString("package_version"));
                buildLogger.addBuildLogEntry("Fixed_version: " + vulnerabilityObject.getString("fixed_version"));
                buildLogger.addBuildLogEntry("Link: " + vulnerabilityObject.getString("link"));
                buildLogger.addBuildLogEntry("");

                if (severity.equalsIgnoreCase("High")) {
                    currentHighSeverity++;
                } else if (severity.equalsIgnoreCase("Medium")) {
                    currentMediumSeverity++;
                }
            }
        }

        if (scanLayers) {
            buildLogger.addBuildLogEntry("");
            if (reportJson.has("layers")) {
                buildLogger.addBuildLogEntry("**************** Layer Vulnerability History ****************");
                buildLogger.addBuildLogEntry("");
                JSONArray layerArray = reportJson.getJSONArray("layers");
                for (int i = 0; i < layerArray.size(); i++) {
                    JSONObject layerObject = layerArray.getJSONObject(i);
                    String layerDigest = layerObject.getString("digest").substring(0, 12);
                    JSONArray layerVulnerabilityArray = layerObject.getJSONArray("vulnerabilities");
                    buildLogger.addBuildLogEntry("Layer digest " + layerDigest + " contains " + layerVulnerabilityArray.size() + " vulnerabilities.");
                    buildLogger.addBuildLogEntry("");
                    for (int j = 0; j < layerVulnerabilityArray.size(); j++) {
                        JSONObject layerVulnerabilityObject = layerVulnerabilityArray.getJSONObject(j);
                        buildLogger.addBuildLogEntry("Name: " + layerVulnerabilityObject.getString("name") 
                            + ", Score: " + layerVulnerabilityObject.get("score") 
                            + ", Package_name: " + layerVulnerabilityObject.getString("package_name") 
                            + ", Package_version: " + layerVulnerabilityObject.getString("package_version") 
                            + ", Fixed_version: " + layerVulnerabilityObject.getString("fixed_version") 
                            + ", Link: " + layerVulnerabilityObject.getString("link"));
                    }
                    buildLogger.addBuildLogEntry("");
                }
            } else {
                buildLogger.addBuildLogEntry("*** Your Controller Does Not Support Layer Vulnerability Scan ***");
            }
        }
        makeIfFailDecision(currentHighSeverity, currentMediumSeverity);
    }

    private void makeIfFailDecision(int currentHighSeverity, int currentMediumSeverity) throws TaskException {
        boolean numberExceed = false;
        StringBuilder statementBuilder = new StringBuilder();

        if (highVul != null && !highVul.trim().isEmpty()) {
            int configNumberOfHigh = Integer.parseInt(highVul.trim());
            if (configNumberOfHigh != 0 && configNumberOfHigh <= currentHighSeverity) {
                numberExceed = true;
                statementBuilder.append(currentHighSeverity).append(" High severity vulnerabilities");
            }
        }

        if (mediumVul != null && !mediumVul.trim().isEmpty()) {
            int configNumberOfMedium = Integer.parseInt(mediumVul.trim());
            if (configNumberOfMedium != 0 && configNumberOfMedium <= currentMediumSeverity) {
                if (numberExceed) {
                    statementBuilder.append(", ");
                }
                numberExceed = true;
                statementBuilder.append(currentMediumSeverity).append(" Medium severity vulnerabilities");
            }
        }

        if (numberExceed) {
            statementBuilder.append(" are present.");
            throw new TaskException("Build failed because " + statementBuilder.toString());
        }
    }
}
