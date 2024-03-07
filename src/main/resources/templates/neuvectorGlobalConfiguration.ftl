<html>
<head>
    <meta name="decorator" content="atl.admin">
    <title>[@ww.text name="NeuVector"/]</title>
</head>
<body>
[@ui.bambooSection titleKey="NeuVector Global Configuration"]
    [@ww.form action="neuvectorGlobalConfiguration!save.action" method="post" submitLabelKey="Save"]
	    [@ww.textfield labelKey="Controller IP" name="controllerIP" description="The IP of NeuVector Controller, without http or https" required="true"/]
	    [@ww.textfield labelKey="Controller Port" name="controllerPort" description="The port of the NeuVector Controller" required="true"/]
	    [@ww.textfield labelKey="NeuVector Username" name="nvUsername" description="The NeuVector Username" required="true"/]
	    [@ww.password labelKey="NeuVector Password" name="nvPassword" description="The NeuVector Password" required="true" showPassword="true"/]
	    [@ww.textfield labelKey="Registry URL" name="registryURL" description="Registry URL, includes http or https" required="false"/]
	    [@ww.textfield labelKey="Registry Username" name="registryUsername" description="Registry Username, can be empty" required="false"/]
	    [@ww.password labelKey="Registry Password" name="registryPassword" description="Registry password, can be empty" showPassword="true" required="false"/]
    [/@ww.form]
[/@ui.bambooSection]
</body>
</html>
