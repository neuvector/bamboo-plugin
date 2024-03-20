package neuvector.scanner;

import com.atlassian.bamboo.build.logger.BuildLogger;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

import com.atlassian.bamboo.task.TaskContext;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.PullImageResultCallback;
import com.github.dockerjava.api.command.WaitContainerResultCallback;
import com.github.dockerjava.api.model.AuthConfig;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientConfig;
import com.github.dockerjava.core.DockerClientImpl;
import com.github.dockerjava.httpclient5.ApacheDockerHttpClient;
import com.github.dockerjava.transport.DockerHttpClient;

import neuvector.ScanConfig;
import neuvector.report.*;

public class StandaloneScanner {
    private TaskContext taskContext;
    private ProcessResult processResult;
    private ScanConfig scanConfig;
    private BuildLogger buildLogger;
    private static final String SCAN_REPORT = "scan_result.json";

    public StandaloneScanner(final TaskContext taskContext, ProcessResult processResult, ScanConfig scanConfig) throws IOException {
        this.taskContext = taskContext;
        this.processResult = processResult;
        this.scanConfig = scanConfig;
        this.buildLogger = taskContext.getBuildLogger();
    }

    private DockerClient prepareDockerClient() throws Exception {
        try {
            // Use environment variables or external configuration to securely store credentials
            String dockerHost = System.getenv("DOCKER_HOST"); 
            String registryUrl = System.getenv("DOCKER_REGISTRY_URL"); 
            
            // Build the Docker client configuration
            DockerClientConfig config = DefaultDockerClientConfig.createDefaultConfigBuilder()
                    .withDockerHost(dockerHost != null ? dockerHost : "unix:///var/run/docker.sock") 
                    .withRegistryUrl(registryUrl != null ? registryUrl : "https://index.docker.io/v1/")
                    .withRegistryUsername(scanConfig.getScannerRegistryUsername())
                    .withRegistryPassword(scanConfig.getScannerRegistryPassword())
                    .build();

            DockerHttpClient httpClient = new ApacheDockerHttpClient.Builder()
                .dockerHost(config.getDockerHost())
                .sslConfig(config.getSSLConfig())
                .maxConnections(100)
                .build();

            DockerClient dockerClient = DockerClientImpl.getInstance(config, httpClient);
            return dockerClient;
        } catch (Exception e) {
            // Optionally log the exception here
            buildLogger.addErrorLogEntry("Failed to prepare Docker client: " + e.getMessage());
            throw new Exception("Failed to prepare Docker client", e);
        }
    }

    public void scan() throws IOException {
        DockerClient dockerClient;
        try {
            dockerClient = prepareDockerClient();
        } catch (Exception e) {
            buildLogger.addErrorLogEntry("Exception: " + e.getMessage());
            return;
        }

        if (dockerClient == null) {
            return;
        }

        try {
            authenticateAndPullImage(dockerClient);
            CreateContainerResponse container = createContainer(dockerClient);
            startContainer(dockerClient, container);
            waitContainer(dockerClient, container);

            String destinationPathOnHost = taskContext.getWorkingDirectory() + SCAN_REPORT;
            copyResultFromContainer(dockerClient, container, destinationPathOnHost);
            cleanupAndClose(dockerClient, container);

            processResultFile(destinationPathOnHost);

        } catch (InterruptedException e) {
            buildLogger.addErrorLogEntry("InterruptedException: " + e.getMessage());
        }
    }

    private void authenticateAndPullImage(DockerClient dockerClient) throws InterruptedException {
        AuthConfig authConfig = new AuthConfig()
            .withUsername(scanConfig.getScannerRegistryUsername())
            .withPassword(scanConfig.getScannerRegistryPassword())
            .withRegistryAddress(scanConfig.getScannerRegistryURL());
        dockerClient.authCmd().withAuthConfig(authConfig).exec();

        dockerClient.pullImageCmd(scanConfig.getScannerImageRepository())
                    .exec(new PullImageResultCallback())
                    .awaitCompletion();
    }

    private CreateContainerResponse createContainer(DockerClient dockerClient) {
        return dockerClient.createContainerCmd(scanConfig.getScannerImageRepository())
            .withEnv(
                "SCANNER_REGISTRY=" + scanConfig.getRegistryURL(),
                "SCANNER_REGISTRY_USERNAME=" + scanConfig.getRegistryUsername(),
                "SCANNER_REGISTRY_PASSWORD=" + scanConfig.getRegistryPassword(),
                "SCANNER_REPOSITORY=" + scanConfig.getRepository(),
                "SCANNER_TAG=" + scanConfig.getTag(),
                "SCANNER_SCAN_LAYERS=" + scanConfig.isScanLayers(),
                "SCANNER_ON_DEMAND=true"
            )
            .exec();
    }

    private void startContainer(DockerClient dockerClient, CreateContainerResponse container) {
        dockerClient.startContainerCmd(container.getId()).exec();
    }

    private void waitContainer(DockerClient dockerClient, CreateContainerResponse container) throws InterruptedException {
        dockerClient.waitContainerCmd(container.getId()).exec(new WaitContainerResultCallback()).awaitCompletion();
    }

    private void copyResultFromContainer(DockerClient dockerClient, CreateContainerResponse container, String destinationPathOnHost) {
        String filePathInContainer = "/var/neuvector/" + SCAN_REPORT;
        try (InputStream response = dockerClient.copyArchiveFromContainerCmd(container.getId(), filePathInContainer).exec()) {
            Files.copy(response, Paths.get(destinationPathOnHost), StandardCopyOption.REPLACE_EXISTING);
            buildLogger.addBuildLogEntry("File copied successfully: " + destinationPathOnHost);
        } catch (IOException e) {
            e.printStackTrace();
            buildLogger.addErrorLogEntry("Error copying file from container: " + e.getMessage());
        }
    }

    private void cleanupAndClose(DockerClient dockerClient, CreateContainerResponse container) throws IOException {
        try {
            dockerClient.removeContainerCmd(container.getId()).withForce(true).exec();
        } finally {
            dockerClient.close();
        }
    }

    private void processResultFile(String destinationPathOnHost) {
        StringBuilder contentBuilder = new StringBuilder();
        try (InputStream fi = new FileInputStream(destinationPathOnHost);
             BufferedInputStream bi = new BufferedInputStream(fi);
             TarArchiveInputStream ti = new TarArchiveInputStream(bi)) {

            org.apache.commons.compress.archivers.ArchiveEntry entry;
            while ((entry = ti.getNextTarEntry()) != null) {
                if (entry.getName().endsWith(".json")) {
                    Files.copy(ti, Paths.get(destinationPathOnHost), StandardCopyOption.REPLACE_EXISTING);
                    String content = new String(Files.readAllBytes(Paths.get(destinationPathOnHost)), StandardCharsets.UTF_8);
                    contentBuilder.append(content);
                    break;
                }
            }
            processResult.setSuccess(true);
            processResult.setsSanResultString(contentBuilder.toString());
        } catch (IOException e) {
            buildLogger.addErrorLogEntry("Error handling tar file: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
