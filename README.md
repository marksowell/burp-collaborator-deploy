# Deploy a Private Burp Collaborator Server
This repository automates the deployment of a Private Burp Collaborator server on Google Cloud Platform (GCP). It leverages a wildcard Let's Encrypt SSL certificate for enhanced security, complete with automatic renewal. Tailored for advanced penetration testing, this project simplifies the cloud deployment process, providing scripts and step-by-step instructions to ensure a seamless setup experience.

## Features
- **Automatic Wildcard SSL Certificate:** Automates the acquisition and renewal of a Let's Encrypt SSL certificate, securing your server without manual intervention.  
- **Seamless Cloud Deployment:** Streamlines the deployment process across GCP resources, including VM instances and static IPs, with ready-to-execute scripts.  
- **Optimized for Penetration Testing:** Designed to meet the needs of security professionals and penetration testers seeking a private and secure environment.  

## Getting Started


### Prerequisites

- A [Google Cloud Platform account](https://cloud.google.com/).
- Familiarity with GCP services and the command line. For an introduction to GCP, see [GCP Fundamentals](https://cloud.google.com/docs/overview).
- A registered domain name.
- A new GCP project created.

## Deploy Now
Click the button below to start deploying your Private Burp Collaborator server in Google Cloud Shell. You'll be prompted to enter your domain, project ID, zone, region, and email for SSL certification. Follow the on-screen instructions to complete the deployment. When prompted to configure your DNS settings, refer to [Configuring DNS](https://medium.com/p/e4c98e046c00#a4d2) for an example.  

[![Open in Google Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/marksowell/burp-collaborator-deploy&page=shell&open_in_editor=deploy.sh)


## Support and Contributions
For support, questions, or contributions, please [open an issue](https://github.com/marksowell/burp-collaborator-deploy/issues) or submit a pull request in this repository. Your feedback and contributions are welcome to improve the deployment process and extend the project's capabilities.
