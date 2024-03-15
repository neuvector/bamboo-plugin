package neuvector.report;

import com.google.gson.JsonObject;

public class ProcessResult {
    private ScanResult scanResult;
    private Vulnerability vulnerability;
    private boolean success;
    private String scanResultString;
    private JsonObject scanResultJson;
    
    public ProcessResult() {
        success = false;
        scanResult = new ScanResult();
        vulnerability = new Vulnerability();
    }

    public ScanResult getScanResult() {
        return this.scanResult;
    }

    public Vulnerability getVulnerability() {
        return this.vulnerability;
    }

    public boolean isSuccess() {
        return this.success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public void setsSanResultString(String scanResultString) {
        this.scanResultString = scanResultString;
    }

    public String getScanResultString() {
        return this.scanResultString;
    }

    public void setScanResultJson(JsonObject scanResultJson) {
        this.scanResultJson = scanResultJson;
    }

    public JsonObject getScanResultJson() {
        return this.scanResultJson;
    }
}
