package neuvector.utils;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class DockerRegistryClient {
    private String registryURL = "https://hub.docker.com/v2";
    private String username;
    private String password;

    public DockerRegistryClient(String username, String password) {
        this.username = username;
        this.password = password;
    }
    
    public Set<String> getAllRepositoriesWithTagsAll() {
        Set<String> repoSet = new HashSet<>();
        try {
            String[] repositories = listRepositories();
            for (String repo : repositories) {
                String[] tags = listTags(repo);
                for (String tag : tags) {
                    repoSet.add(repo+":"+tag);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return repoSet;
    }

    private String[] listRepositories() throws Exception {
        String endpoint = "/repositories/" + username + "/";
        String response = sendGetRequest(endpoint);
        Gson gson = new Gson();
        JsonObject json = gson.fromJson(response, JsonObject.class);
        JsonArray repos = json.getAsJsonArray("results");
        String[] repositories = new String[repos.size()];
        for (int i = 0; i < repos.size(); i++) {
            repositories[i] = repos.get(i).getAsJsonObject().get("name").getAsString();
        }
        return repositories;
    }
    
    private String[] listTags(String repository) throws Exception {
        String endpoint = "/repositories/" + username + "/" + repository + "/tags";
        String response = sendGetRequest(endpoint);
        Gson gson = new Gson();
        JsonObject json = gson.fromJson(response, JsonObject.class);
        JsonArray tags = json.getAsJsonArray("results");
        String[] tagList = new String[tags.size()];
        for (int i = 0; i < tags.size(); i++) {
            tagList[i] = tags.get(i).getAsJsonObject().get("name").getAsString();
        }
        return tagList;
    }

    private String sendGetRequest(String endpoint) throws Exception {
        URL url = new URL(registryURL + endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
    
        // Add Basic Authentication header
        String auth = username + ":" + password;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes("UTF-8"));
        conn.setRequestProperty("Authorization", "Basic " + encodedAuth);
    
        int responseCode = conn.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
            String inputLine;
            StringBuilder response = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            return response.toString();
        } else {
            throw new Exception("GET request not worked, Response Code: " + responseCode);
        }
    }
}
