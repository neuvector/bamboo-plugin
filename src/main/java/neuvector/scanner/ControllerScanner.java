package neuvector.scanner;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import org.apache.http.HttpEntity;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;

import com.atlassian.bamboo.build.logger.BuildLogger;
import com.atlassian.bamboo.task.TaskContext;
import com.atlassian.bamboo.task.TaskException;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import neuvector.NeuVectorGlobalConfigurator;
import neuvector.ScanConfig;
import neuvector.TrustAllStrategy;
import neuvector.report.*;

public class ControllerScanner {
    private static final int HTTP_CLIENT_CONFIG_TIMEOUT_SECOND = 60;
    private TaskContext taskContext;
    private ProcessResult processResult;
    private ScanConfig scanConfig;
    private BuildLogger buildLogger;
    private NeuVectorGlobalConfigurator nvConfigurator = new NeuVectorGlobalConfigurator();

    public ControllerScanner(final TaskContext taskContext, ProcessResult processResult, ScanConfig scanConfig) {
        this.taskContext = taskContext;
        this.processResult = processResult;
        this.scanConfig = scanConfig;
        this.buildLogger = taskContext.getBuildLogger();
    }
    
    public void scan() {
        String scanResultString;

        // Make sure IP is correctly setting
        if (!nvConfigurator.checkControllerIP(scanConfig.getControllerIP()) || !nvConfigurator.checkControllerPort(scanConfig.getControllerPortString())) {
            return;
        }
        scanConfig.setControllerPort(Integer.parseInt(scanConfig.getControllerPortString().trim()));

        try (CloseableHttpClient httpclient = makeHttpClient()) {
            getToken(httpclient);
            try {
                scanResultString = requestScan(httpclient);
            } finally {
                logout(httpclient);
            }
            processResult.setsSanResultString(scanResultString);

        } catch (TaskException e) {
            buildLogger.addErrorLogEntry(e.getMessage());
        } catch (IOException e) {
            buildLogger.addErrorLogEntry("IOException when close httpclient. " + e.getMessage());
        }
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
        URI uriForGetToken = buildUri(scanConfig.getControllerIP(), scanConfig.getControllerPort(), uriPathForGetToken);

        HttpPost httpPostForGetToken = new HttpPost(uriForGetToken);
        httpPostForGetToken.addHeader("Content-Type", "application/json");

        JsonObject passwordJson = new JsonObject();
        passwordJson.addProperty("username", scanConfig.getNvUsername());
        passwordJson.addProperty("password", scanConfig.getNvPassword());
        JsonObject httpBodyJson = new JsonObject();
        httpBodyJson.add("password", passwordJson);

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
                // JsonObject responseJson = new JsonParser().parse(serverMessageFromGetToken).getAsJsonObject();
                JsonElement responseElement = JsonParser.parseString(serverMessageFromGetToken);
                if (responseElement.isJsonObject()) {
                    JsonObject responseJson = responseElement.getAsJsonObject();
                    scanConfig.setToken(responseJson.getAsJsonObject("token").get("token").getAsString());
                }
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

    private String requestScan(CloseableHttpClient httpclient) throws TaskException, IOException {
        String scanResultString;
        String uriPathForScan = "/v1/scan/repository";
        URI uriForScan = buildUri(scanConfig.getControllerIP(), scanConfig.getControllerPort(), uriPathForScan);

        HttpPost httpPostForScan = new HttpPost(uriForScan);
        httpPostForScan.addHeader("Content-Type", "application/json");
        httpPostForScan.addHeader("X-Auth-Token", scanConfig.getToken());

        JsonObject httpBodyJson = new JsonObject();
        JsonObject requestJson = new JsonObject();
        requestJson.addProperty("repository", scanConfig.getRepository());
        if (scanConfig.getToken() != null) {
            requestJson.addProperty("tag", scanConfig.getTag());
        }

        requestJson.addProperty("registry", scanConfig.getRegistryURL());
        requestJson.addProperty("username", scanConfig.getRegistryUsername());
        requestJson.addProperty("password", scanConfig.getRegistryPassword());
        requestJson.addProperty("scan_layers", scanConfig.isScanLayers());

        httpBodyJson.add("request", requestJson);

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
            }

            int statusCode = httpResponseFromScan.getStatusLine().getStatusCode();
            HttpEntity httpEntityFromScan = httpResponseFromScan.getEntity();
            String serverMessageFromScan = "N/A";

            if (httpEntityFromScan != null) {
                serverMessageFromScan = EntityUtils.toString(httpEntityFromScan);
                EntityUtils.consume(httpEntityFromScan);
            }

            if (statusCode == 200 && httpEntityFromScan != null) {
                scanResultString = serverMessageFromScan;
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
        return scanResultString;
    }

    private void logout(CloseableHttpClient httpclient) throws TaskException, IOException {
        String uriPathForLogout = "/v1/auth";
        URI uriForLogout = buildUri(scanConfig.getControllerIP(), scanConfig.getControllerPort(), uriPathForLogout);
        HttpDelete httpDeleteForLogout = new HttpDelete(uriForLogout);
        httpDeleteForLogout.addHeader("Content-Type", "application/json");
        httpDeleteForLogout.addHeader("X-Auth-Token", scanConfig.getToken());
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
}
