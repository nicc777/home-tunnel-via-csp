# Home Tunnel via Cloud Service Provider (cumulus-tunnel)

Creating a custom solution similar to [NGrok](https://ngrok.com/our-product/secure-tunnels) tunneling using a Public Cloud like AWS.

> [!IMPORTANT]  
> This is a personal project to solve a specific challenge. I do not offer any guarantees in terms of security or costs. Use at your own risk.

# What problem is this solving

> I have a private system not directly exposed to the internet and I want to expose at least some services to the Internet in a controlled and restricted way. This is similar to the `ngrok` tunneling solution. Why I don't use `ngrok` or other solutions is that the free options was too limiting and switching to a subscription would be too expensive and still leave me with some lacking features.

# Project Status

| Date       | Status           | Notes                                                     |
|------------|:----------------:|-----------------------------------------------------------|
| 2024-12-17 | Work in Progress | Most of the AWS IaC is done. Busy with the tunnel service |
| 2024-12-07 | Planning         | Initial planning and setup of the project                 |

# Planned features

* [ ] Creating a Virtual Machine Instance where the tunnel will terminate (known as the relay host)
* [ ] Track the user systems NAT address to the Internet for maintaining firewall rules to the relay machine (this may be a laptop from where a person may want to access the private system)
  * [x] Agent to collect and upload public IP addresses
  * [ ] Lambda function to react on S3 object write events
  * [ ] Lambda function to react to S3 delete events
* [ ] Create reverse port tunneling from the private system to a local port
* [ ] Enable authentication of the reverse HTTP proxy
* [ ] Enable custom header requirements and other filters to allow/restrict access
* [ ] Use `nginx` to setup an HTTP reverse proxy to the private system
* [ ] Use `socat` (or similar) port forwarding from random or fixed ports to the forwarded ports from the private system
* [ ] Create one or more custom DNS entries for the relay system for easy connection. Multiple subdomains can be created to map to the relay host Public IP address.
* [ ] TLS certificate management (private certificates) for the `nginx` proxy
* [ ] Create dashboards to track the status and network usage

The initial solution will be based on AWS but I will keep options open to potential roll it out to various other Cloud Service Providers that have the following features available for this solution:

* Virtual Machine instance to start the relay host
  * Failure tolerant - meaning a terminated instance will automatically restart
  * Pipeline to build new patched images on a regular bases
* DNS management capabilities (add/remove/edit records)
* Simple storage solution to act as a repository for some temporary data as needed

# Cost

For AWS the expected monthly cost breakdown is in the file [aws_cost_estimate.json](./aws_cost_estimate.json) and comes down to:

* Less than USD12 per month

The price is less than the cheapest `ngrok` option above free-tier (around USD18 on 2024-12-07).

> [!CAUTION]
> These are cost estimates and many factors may influence the final cost. Use the [AWS Pricing Calculator](https://calculator.aws/#/) to adjust the numbers to your own needs.

# Documentation

Still limited, but you can start to look at the [development notes](./DEV_NOTES.md) that will be updated as progress is made until proper documentation can be created.

