<html>
<head>
    <meta name="decorator" content="atl.admin">
    <title>[@ww.text name="NeuVector"/]</title>
</head>
<body>
[@ww.form action="neuvectorGlobalConfiguration!save.action" method="post" submitLabelKey="Save"]
	[@ui.bambooSection titleKey="Scan Registry Configuration"]
		[@ww.textfield labelKey="Registry URL" name="registryURL" description="Registry URL, includes http or https" required="false"/]
		[@ww.textfield labelKey="Registry Username" name="registryUsername" description="Registry Username, can be empty" required="false"/]
		[@ww.password labelKey="Registry Password" name="registryPassword" description="Registry password, can be empty" showPassword="true" required="false"/]
	[/@ui.bambooSection]

	[@ui.bambooSection titleKey="NeuVector Controller Configuration"]
		[@ww.textfield labelKey="Controller IP" name="controllerIP" description="The IP of NeuVector Controller, without http or https" required="false"/]
		[@ww.textfield labelKey="Controller Port" name="controllerPort" description="The port of the NeuVector Controller" required="false"/]
		[@ww.textfield labelKey="NeuVector Username" name="nvUsername" description="The NeuVector Username" required="false"/]
		[@ww.password labelKey="NeuVector Password" name="nvPassword" description="The NeuVector Password" required="false" showPassword="true"/]
	[/@ui.bambooSection]

	[@ui.bambooSection titleKey="NeuVector Standalone Configuration"]
		[@ww.textfield labelKey="NeuVector Scanner Registry URL" name="scannerRegistryURL" description="Enter the NeuVector Scanner Registry URL, including http or https." required="false"/]
        [@ww.textfield labelKey="NeuVector Scanner Image Repository" name="scannerImageRepository" description="Enter the NeuVector Scanner Image Repository, e.g. user/repo:tag" required="false"/]
        [@ww.textfield labelKey="NeuVector Scanner Registry User" name="scannerRegistryUsername" description="Enter the NeuVector Scanner Registry username, if applicable." required="false"/]
        [@ww.password labelKey="NeuVector Scanner Registry Password" name="scannerRegistryPassword" description="Enter the NeuVector Scanner Registry password, if applicable." showPassword="true" required="false"/]
	[/@ui.bambooSection]

	[@ui.bambooSection titleKey="NeuVector Custom Criteria Configuration"]
		[@ww.textfield labelKey="Custom Critical Severity Threshold" name="customCriticalThreshold" description="From the Critical Severity Threshold to 10.0 is the Critical Severity Range. Vulnerabilities that score in the Critical Severity Range has the Critical severity level.." required="false"/]
        [@ww.textfield labelKey="Custom High Severity Threshold" name="customHighThreshold" description="From the High Severity Threshold to Critical Severity Threshold is the High Severity Range. Vulnerabilities that score in the High Severity Range has the High severity level." required="false"/]
        [@ww.textfield labelKey="Custom Medium Severity Threshold" name="customMediumThreshold" description="From the Medium Severity Threshold to the High Severity Threshold is the Medium Severity Range. Vulnerabilities that score in the Medium Severity Range has the Medium severity level." required="false"/]
	[/@ui.bambooSection]
[/@ww.form]
</body>
</html>