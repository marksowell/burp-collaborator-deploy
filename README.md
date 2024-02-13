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

1. Click the button below to start deploying your Private Burp Collaborator server in Google Cloud Shell. You will be prompted to clone the repository.  

   [![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/marksowell/burp-collaborator-deploy.git&show=terminal)
3. Click `Confirm` to clone the repository.
4. Authorize the gcloud CLI
   ```bash
   gcloud auth login --quiet
   ```
   Follow the browser-based authorization flow to authenticate the account and grant access permissions.
5. Change the script's permissions to make it executable, then start the deployment process by executing the script in the Cloud Shell terminal.  
   ```bash
   chmod +x deploy.sh
   ./deploy.sh
   ```
6. Follow the on-screen instructions to enter required information such as your domain name, Google Cloud Project ID, zone, region, and email for SSL certificate registration. When prompted to configure your DNS settings, refer to [Configuring DNS](https://medium.com/p/e4c98e046c00#a4d2) for an example.


## Support and Contributions
For support, questions, or contributions, please [open an issue](https://github.com/marksowell/burp-collaborator-deploy/issues) or submit a pull request in this repository. Your feedback and contributions are welcome to improve the deployment process and extend the project's capabilities.
