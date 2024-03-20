# Bamboo plugin
- [Work flow](#work-flow)
- [Env setup](#env-setup)
  - [Prerequest](#prerequest)
  - [Server setup](#server-setup)
  - [Plugin setup](#plugin-setup)
  - [How to run the plugin](#how-to-run-the-plugin)
- [Trouble shooting](#trouble-shooting)
- [Build from source](#build-from-source)
- [Reference](#reference)

# Work flow
![CI-plugin drawio](https://github.com/pohanhuangtw/bamboo-plugin/assets/145627854/a248014b-a562-45f5-ac92-a52c24091f3e)


# Env setup
## Prerequest
- [Install the Atlassian SDK on a Linux or Mac system](https://developer.atlassian.com/server/framework/atlassian-sdk/install-the-atlassian-sdk-on-a-linux-or-mac-system/#install-the-atlassian-sdk-on-a-linux-or-mac-system)

## Server setup
1. Start a bamboo server (bamboo server or you have your own)
    - Simply run `atlas-create-bamboo-plugin` in terminal.
    - Then `atlas-run`
2. Go to Manage App, install it with .obr file
<img width="1133" alt="Screen Shot 2024-03-15 at 4 57 46 PM" src="https://github.com/pohanhuangtw/bamboo-plugin/assets/145627854/88bc2066-445f-4e60-9205-9a4423abee52">


## Plugin setup
1. Go to Neuvector Section
<img width="769" alt="Screen Shot 2024-03-15 at 5 06 28 PM" src="https://github.com/pohanhuangtw/bamboo-plugin/assets/145627854/65bfa246-c10c-4387-8966-8a983f2bf1e2">

2. Setup the env based on your need.
<img width="1333" alt="Screen Shot 2024-03-15 at 5 09 32 PM" src="https://github.com/pohanhuangtw/bamboo-plugin/assets/145627854/355ee0eb-a193-4017-8a86-4e81dbbd276a">


2. [Create a Project](https://www.youtube.com/watch?v=7KuNy9CD1lA&t=7s) and set up tasks.
3. Set up the task based on your need
    - Set up the fail / exempt, write in format like **CVE-2021-23840**
    - Click X can dynamically delete the CVE
    <img width="1333" alt="Screen Shot 2024-03-15 at 5 09 32 PM" src="https://github.com/pohanhuangtw/bamboo-plugin/assets/145627854/2e7e5552-c80e-48b6-96d5-53b869d931bb">


4. Create artifact in task, must create or you have no such report
<img width="1944" alt="Screen Shot 2024-03-20 at 12 03 59 PM" src="https://github.com/pohanhuangtw/bamboo-plugin/assets/145627854/8ac4316a-482d-468f-9633-6824ce8cd638">




## How to run the plugin
- Click run.
- When finish, we will have two files (you can click to download)
    - Html
    - Json
    - Txt
  <img width="1018" alt="Screen Shot 2024-03-20 at 12 03 44 PM" src="https://github.com/pohanhuangtw/bamboo-plugin/assets/145627854/cc73964f-78d8-49ba-86dc-872db66984f8">



# Trouble shooting
1. buildLogger.addBuildLogEntry() shows in console of the task.
<img width="1326" alt="Screen Shot 2024-03-15 at 5 13 23 PM" src="https://github.com/pohanhuangtw/bamboo-plugin/assets/145627854/19978663-0bd8-4801-992d-95bcbc35a881">


2. System.out.println() shows in bamboo server, where your run `atlas-run`
<img width="1186" alt="Screen Shot 2024-03-15 at 5 12 15 PM" src="https://github.com/pohanhuangtw/bamboo-plugin/assets/145627854/c8537949-8ae4-42f5-8a76-9029e5dde9ae">



# Build from source
`atlas-clean && atlas-mvn package` can generate the .obr / .jar

# Reference
1. [Create a HelloWorld plugin project](https://developer.atlassian.com/server/framework/atlassian-sdk/create-a-helloworld-plugin-project/#create-a-helloworld-plugin-project)
2. [Bamboo Tutorial](https://www.youtube.com/watch?v=7KuNy9CD1lA&t=7s)
