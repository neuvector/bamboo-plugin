[@ww.checkbox label="Enable Standalone" name="enableStandalone" toggle="true" required="false"/]
[@ww.radio label="Choose registry type" name="registryType" listKey="key" listValue="value" toggle="true" list=registryMap /]
[@ui.bambooSection dependsOn="registryType" showOn="custom"]
    [@ww.textfield label="Registry URL" name="customRegistryURL" required="false"/]
    [@ww.textfield label="Registry Username" name="customRegistryUsername" required="false"/]
    [@ww.password label="Registry Password" name="customRegistryPassword" showPassword="true" required="false"/]
[/@ui.bambooSection]
[@ww.textfield label="Repository" name="repository" required="true"/]
[@ww.textfield label="Tag" name="tag" required="true"/]
[@ww.checkbox label="Scan Layers" name="scanLayers" toggle="true" required="false"/]
[@ww.textfield label="Critical vulnerabilities to fail" name="criticalVul" required="false"/]
[@ww.textfield label="High vulnerabilities to fail" name="highVul" required="false"/]
[@ww.textfield label="Medium vulnerabilities to fail" name="mediumVul" required="false"/>

<!-- Custom styles for the dynamic sections -->
<style>
    .button-add {
        margin-top: 10px;
        display: block;
    }

    .input-group {
        margin-top: 10px;
        display: flex;
        align-items: center;
    }

    .delete-button {
        margin-right: 10px;
        cursor: pointer;
    }

    .section {
        margin-bottom: 10px;
    }

    .section label, .section .button-add {
        display: block;
    }

    .input-group input {
        margin-left: 10px;
    }
</style>

<!-- Sections for dynamic input fields -->
<div class="section">
    <label>Fail the build if any of the following vulnerabilities are present:</label>
    <button type="button" id="addVulnerabilityToFail" class="button-add">Add Vulnerability to Fail</button>
    <div id="dynamicFieldsToFail"></div>
</div>

<div class="section">
    <label>Exempt the following vulnerabilities in Scan:</label>
    <button type="button" id="addVulnerabilityToExempt" class="button-add">Add Vulnerability to Exempt</button>
    <div id="dynamicFieldsToExempt"></div>
</div>

<!-- JavaScript logic to handle adding and deleting dynamic fields -->
<script type="text/javascript">
    var globalCounter = 0;

    // These lines should be replaced with correct server-side template tags that inject the JSON.
    var vulnerabilitiesToFail = JSON.parse('${vulnerabilitiesToFailJson}');
    var vulnerabilitiesToExempt = JSON.parse('${vulnerabilitiesToExemptJson}');

    vulnerabilitiesToFail.forEach(function(vuln) {
        addTextField('dynamicFieldsToFail', 'failVul', vuln);
    });

    vulnerabilitiesToExempt.forEach(function(vuln) {
        addTextField('dynamicFieldsToExempt', 'exemptVul', vuln);
    });

    function addTextField(divId, baseName, value = '') {
        var container = document.getElementById(divId);
        var inputName = baseName + (++globalCounter);

        var div = document.createElement('div');
        div.className = 'input-group';
        div.innerHTML = '<div class="delete-button" onclick="removeTextField(this)">X</div>' +
                         '<input type="text" name="' + inputName + '" value="' + escapeHtml(value) + '" />';

        container.appendChild(div);
    }

    function removeTextField(element) {
        var container = element.parentNode.parentNode;
        container.removeChild(element.parentNode);
    }

    function escapeHtml(text) {
        var map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    document.getElementById('addVulnerabilityToFail').addEventListener('click', function() {
        addTextField('dynamicFieldsToFail', 'failVul');
    });

    document.getElementById('addVulnerabilityToExempt').addEventListener('click', function() {
        addTextField('dynamicFieldsToExempt', 'exemptVul');
    });
</script>

