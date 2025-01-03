# Home Tunnel via Cloud Service Provider (cumulus-tunnel)

Creating a custom solution similar to [NGrok](https://ngrok.com/our-product/secure-tunnels) tunneling using a Public Cloud like AWS.

> [!IMPORTANT]  
> This is a personal project to solve a specific challenge. I do not offer any guarantees in terms of security or costs. Use at your own risk.

# What problem is this solving

> I have a private system not directly exposed to the internet and I want to expose at least some services to the Internet 
> in a controlled and restricted way. This is similar to the `ngrok` tunneling solution. I don't use `ngrok` or other 
> solutions is because the free options was too limiting and switching to a subscription would be too expensive and still 
> leave me with some lacking features. I also have a concern about the potential for eves dropping or man-in-the-middle 
> attacks from third party services. The latter could perhaps still be an issue with a Public Cloud provider, but since I 
> control the SSH keys for the traffic tunneling, it feels a little more secure.

# Project Status

| Date       | Status           | Notes                                                                                                                                                                                                              |
|------------|:----------------:|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 2025-01-03 | Web Proxy        | Focusing on the web proxy next.                                                                                                                                                                                    |
| 2025-01-02 | More or less MVP | Functionally everything now works from a technical perspective. Will focus next on some documentation and then packaging of the various services to make this a more user friendly solution.                       |
|            |                  | The web reverse tunnel is still a major outstanding feature, but the current reverse tunnels provide an acceptable work around.                                                                                    |
|            |                  | There is also still a lot of work left in terms of management web user interfaces.                                                                                                                                 |
| 2025-01-01 | Focus on Agent   | Provisioning the relay server works and with manually added Security Group rules, a relay can be set-up end-to-end. Now need to automate the process of client registration and dynamic Security Group management. |
| 2024-12-24 | Major Refactor   | After some practical tests, first major refactor done. Still lots to do.                                                                                                                                           |
|            |                  | Updated integration diagram                                                                                                                                                                                        |
|            |                  | Reorganized features and progress                                                                                                                                                                                  |
| 2024-12-17 | Work in Progress | Most of the AWS IaC is done. Busy with the tunnel service                                                                                                                                                          |
| 2024-12-07 | Planning         | Initial planning and setup of the project                                                                                                                                                                          |

# Planned features

* [X] Relay Server Agent
  * [ ] Python Package
  * [ ] Relay Server Admin UI (Web)
* [X] Client Agent
  * [ ] Python Package
  * [ ] Client Local Admin UI (Web)
* [X] Deployment Script
* [ ] API Commands
  * [X] Register Relay Server
  * [X] Deregister Relay Server
  * [X] Get Relay Server Config and Status
  * [X] Manage Agent Rules (for AWS, this is Security Group rules)
  * [ ] Get overall status
* [ ] AMI Image Builder Solution to Prepare AMI Images and set a SSM Parameter

The initial solution will be based on AWS but I will keep options open to potential roll it out to various other Cloud Service Providers that have the following features available for this solution:

* Virtual Machine instance to start the relay server
  * Failure tolerant - meaning a terminated instance will automatically restart
  * Pipeline to build new patched images on a regular bases
* DNS management capabilities (add/remove/edit records)
* Simple storage solution to act as a repository for some temporary data as needed

![Integration Design Overview](./images/design-Integration.png)

# Cost

> [!NOTE]
> These cost estimates is based on a previous design which is no longer used. This will be updated again at a later stage.

For AWS the expected monthly cost breakdown is in the file [aws_cost_estimate.json](./aws_cost_estimate.json) and comes down to:

* Less than USD12 per month

The price is less than the cheapest `ngrok` option above free-tier (around USD18 on 2024-12-07).

> [!CAUTION]
> These are cost estimates and many factors may influence the final cost. Use the [AWS Pricing Calculator](https://calculator.aws/#/) to adjust the numbers to your own needs.

# Documentation

Still limited, but you can start to look at the [development notes](./DEV_NOTES.md) that will be updated as progress is made until proper documentation can be created.

