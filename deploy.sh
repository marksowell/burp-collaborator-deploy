#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Prompt for the domain name
read -p "Enter the domain name (e.g., domain.com): " DOMAIN
if [[ -z "$DOMAIN" ]]; then
    echo "Domain name is required."
    exit 1
fi

# Prompt for the Google Cloud project ID
read -p "Enter your Google Cloud Project ID: " PROJECT_ID
if [[ -z "$PROJECT_ID" ]]; then
    echo "Project ID is required."
    exit 1
fi

# Prompt for the Google Cloud zone
read -p "Enter your Google Cloud Zone (e.g., us-central1-a): " ZONE
if [[ -z "$ZONE" ]]; then
    echo "Zone is required."
    exit 1
fi

# Prompt for the Google Cloud region
read -p "Enter your Google Cloud Region (e.g., us-central1): " REGION
if [[ -z "$REGION" ]]; then
    echo "Region is required."
    exit 1
fi

# Prompt for the email address for SSL certificate registration
read -p "Enter your email for SSL certificate registration: " CERT_EMAIL
if [[ -z "$CERT_EMAIL" ]]; then
    echo "Email is required for SSL certificate registration."
    exit 1
fi

# Variables
VM_NAME="${DOMAIN%%.*}" # Extracts 'domain' from 'burp.domain.com' or 'domain.com'
MACHINE_TYPE="e2-micro" # Adjust based on your needs
IMAGE_FAMILY="debian-12"
IMAGE_PROJECT="debian-cloud"
TAGS="burp-collaborator" # Tag used for targeting firewall rules
WORKING_DIR="/root/burp"
RANDOM_STRING=$(openssl rand -base64 12 | tr -d '/+' | cut -c1-16)
BURP_KEYS_PATH="/root/burp/keys"
AUTH_HOOK_SCRIPT="/root/burp/auth-hook-script.sh"
CLEANUP_HOOK_SCRIPT="/root/burp/cleanup-hook-script.sh"
DEPLOY_HOOK_SCRIPT="/root/burp/deploy-hook-script.sh"
LE_PATH="/etc/letsencrypt/live/$DOMAIN"
PKCS8_KEY_PATH="${BURP_KEYS_PATH}/wildcard_${DOMAIN}.key.pkcs8"
CRT_PATH="${BURP_KEYS_PATH}/wildcard_${DOMAIN}.crt"
INTERMEDIATE_CRT_PATH="${BURP_KEYS_PATH}/intermediate.crt"

# Function to check if VM already exists
check_vm_exists() {
    if gcloud compute instances describe "$VM_NAME" --project="$PROJECT_ID" --zone="$ZONE" &>/dev/null; then
        echo "A VM with the name $VM_NAME already exists in project $PROJECT_ID, zone $ZONE."
        echo "Please delete the existing VM or use a different name/domain."
        exit 1
    else
        echo "No existing VM found with the name $VM_NAME. Continuing with deployment..."
    fi
}

# Check if the VM already exists
check_vm_exists

# Function to check if the external IP already exists
check_external_ip() {
    if ! gcloud compute addresses describe "$VM_NAME-ip" --project="$PROJECT_ID" --region="$REGION" &>/dev/null; then
        gcloud compute addresses create "$VM_NAME-ip" --project="$PROJECT_ID" --region="$REGION" --network-tier=PREMIUM
        echo "Static external IP address reserved."
    else
        echo "Static external IP address already exists."
    fi
}

# Check if the external IP already exists, if not, reserve one
check_external_ip

# Get the reserved IP address
EXTERNAL_IP=$(gcloud compute addresses describe "$VM_NAME"-ip --project="$PROJECT_ID" --region="$REGION" --format="get(address)")

echo "Configure ns1.$DOMAIN and ns2.$DOMAIN to point to $EXTERNAL_IP"

# Create VM instance with the name based on the domain and the reserved IP address
gcloud compute instances create $VM_NAME \
    --project=$PROJECT_ID \
    --zone=$ZONE \
    --machine-type=$MACHINE_TYPE \
    --image-family=$IMAGE_FAMILY \
    --image-project=$IMAGE_PROJECT \
    --tags="$TAGS" \
    --address="$EXTERNAL_IP" \
    --create-disk="auto-delete=yes,boot=yes,device-name=${VM_NAME}-disk,image=projects/${IMAGE_PROJECT}/global/images/family/${IMAGE_FAMILY},size=30,type=pd-standard"

echo "VM instance created."

# Check and create firewall rules
check_and_create_firewall_rules() {
    declare -A FW_RULES=(
        [allow-dns]="udp:53"
        [allow-http]="tcp:80"
        [allow-https]="tcp:443"
        [allow-smtp]="tcp:25,tcp:587"
        [allow-smtps]="tcp:465"
    )

    for RULE_NAME in "${!FW_RULES[@]}"; do
        if ! gcloud compute firewall-rules describe "$RULE_NAME" --project="$PROJECT_ID" &>/dev/null; then
            gcloud compute firewall-rules create "$RULE_NAME" \
                --project="$PROJECT_ID" \
                --direction=INGRESS \
                --priority=1000 \
                --network=default \
                --action=ALLOW \
                --rules="${FW_RULES[$RULE_NAME]}" \
                --source-ranges=0.0.0.0/0 \
                --target-tags="$TAGS"
            echo "Firewall rule $RULE_NAME created."
        else
            echo "Firewall rule $RULE_NAME already exists."
        fi
    done
}

# Firewall rule check and creation
check_and_create_firewall_rules

# Get the latest BurpSuite release URL from PortSwigger
LATEST_URL=$(curl -si https://portswigger.net/burp/releases/professional/latest | grep -i location | awk '{print $2}' | tr -d '\r')

# Extract the version number and construct the download URL
VERSION=$(echo $LATEST_URL | grep -oP 'professional-community-\K[\d-]+')
DOWNLOAD_URL="https://portswigger-cdn.net/burp/releases/download?product=pro&version=${VERSION}&type=Jar"

# Ensure the directory exists
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --project="$PROJECT_ID" --command="sudo mkdir -p $WORKING_DIR"

# Download the JAR file to the VM
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --project="$PROJECT_ID" --command="sudo wget -O ${WORKING_DIR}/burpsuite_pro.jar '$DOWNLOAD_URL'"

echo "BurpSuite version ${VERSION} downloaded."

# Update and install Java
gcloud compute ssh $VM_NAME --zone=$ZONE --command="sudo apt update && sudo apt install -y openjdk-17-jdk"

echo "Java installed."

# Get the internal IP address
INTERNAL_IP=$(gcloud compute instances describe $VM_NAME --zone=$ZONE --format='get(networkInterfaces[0].networkIP)')

# Configuration file content
CONFIG_CONTENT=$(cat <<EOF
{
    "serverDomain": "$DOMAIN",
    "workerThreads": 10,
    "interactionLimits": {
        "http": 8192,
        "smtp": 8192
    },
    "eventCapture": {
        "localAddress": ["$INTERNAL_IP"],
        "publicAddress": ["$EXTERNAL_IP"],
        "http": {
            "ports": 80
        },
        "https": {
            "ports": 443
        },
        "smtp": {
            "ports": [25, 587]
        },
        "smtps": {
            "ports": 465
        }
    },
    "metrics": {
        "path": "$RANDOM_STRING",
        "addressWhitelist": ["0.0.0.0/0"]
    },
    "dns": {
        "interfaces": [{
                "name": "ns1.$DOMAIN",
                "localAddress": "$INTERNAL_IP",
                "publicAddress": "$EXTERNAL_IP"
            }],
        "ports": 53
    },
    "logLevel": "INFO",
    "customDnsRecords" : []
}
EOF
)

echo "The metrics page will be located at https://$DOMAIN/$RANDOM_STRING/metrics."

# Write the configuration
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="sudo echo '$CONFIG_CONTENT' > ${WORKING_DIR}/myconfig.config"

echo "Configuration file created."

# Command to create burp.service file
CREATE_SERVICE_CMD=$(cat <<'EOF'
cat <<'EOT' > /etc/systemd/system/burp.service
[Unit]
Description=Burp Collaborator
After=network.target

[Service]
ExecStart=/usr/bin/java -Xms50m -Xmx300m -XX:GCTimeRatio=19 -jar /root/burp/burpsuite_pro.jar --collaborator-server --collaborator-config=/root/burp/myconfig.config
Restart=always
User=root
Group=root
Environment=PATH=/usr/bin:/bin:/usr/local/bin
WorkingDirectory=/root/burp

[Install]
WantedBy=multi-user.target
EOT
EOF
)

# Execute the command to create the service file on the VM
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="sudo $CREATE_SERVICE_CMD"

# Reload systemd, enable, and start the service
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="sudo systemctl daemon-reload && sudo systemctl enable burp.service && sudo systemctl start burp.service"

echo "Burp Collaborator service created and started."

# Create directory for keys
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --project="$PROJECT_ID" --command="sudo mkdir -p $BURP_KEYS_PATH"

# Install Certbot
gcloud compute ssh $VM_NAME --zone=$ZONE --command="sudo apt update && sudo apt install -y certbot"

echo "Certbot installed."

# Install jq
gcloud compute ssh $VM_NAME --zone=$ZONE --command="sudo apt install -y jq"

echo "jq installed."

# Create auth-hook-script.sh
cat << 'EOF' > /root/burp/auth-hook-script.sh
#!/bin/bash

# Define paths
CONFIG_FILE="/root/burp/myconfig.config"
SSL_CONFIG_BACKUP="/root/burp/ssl_config_backup.json"
TEMP_CONFIG="/root/burp/temp_myconfig.config"

# Backup only once and remove SSL section
if jq -e '.eventCapture.ssl' "$CONFIG_FILE" > /dev/null && [ ! -f "$SSL_CONFIG_BACKUP" ]; then
    jq '.eventCapture.ssl' "$CONFIG_FILE" > "$SSL_CONFIG_BACKUP"
    jq 'del(.eventCapture.ssl)' "$CONFIG_FILE" > "$TEMP_CONFIG" && mv "$TEMP_CONFIG" "$CONFIG_FILE"
    echo "SSL configuration backed up and removed."
else
    echo "SSL configuration already backed up or does not exist."
fi

# Function to add DNS challenge record
add_dns_challenge() {
    jq --arg name "_acme-challenge" --arg token "$CERTBOT_VALIDATION" '.customDnsRecords += [{"label": $name, "type": "TXT", "record": $token, "ttl": 60}]' "$CONFIG_FILE" > "$TEMP_CONFIG" && mv "$TEMP_CONFIG" "$CONFIG_FILE"
}

add_dns_challenge

# Restart service to apply changes
sudo systemctl restart burp.service
EOF

# Create cleanup-hook-script.sh
cat << 'EOF' > /root/burp/cleanup-hook-script.sh
#!/bin/bash

# Define paths
CONFIG_FILE="/root/burp/myconfig.config"
SSL_CONFIG_BACKUP="/root/burp/ssl_config_backup.json"
TEMP_CONFIG="/root/burp/temp_myconfig.config"

# Function to remove a DNS challenge record
remove_dns_challenge() {
    jq --arg name "_acme-challenge" 'del(.customDnsRecords[] | select(.label == $name))' "$CONFIG_FILE" > "$TEMP_CONFIG" && mv "$TEMP_CONFIG" "$CONFIG_FILE"
}

remove_dns_challenge

# Restore SSL configuration if backup exists
if [ -f "$SSL_CONFIG_BACKUP" ]; then
    # Restore SSL configuration from backup
    jq --slurpfile sslConfig "$SSL_CONFIG_BACKUP" '.eventCapture.ssl = ($sslConfig[0])' "$CONFIG_FILE" > "$TEMP_CONFIG" && mv "$TEMP_CONFIG" "$CONFIG_FILE"
    echo "SSL configuration restored from backup."
    
    # Remove the backup file to prevent restoration in subsequent cleanup operations
    rm -f "$SSL_CONFIG_BACKUP"
else
    echo "SSL configuration backup does not exist. No restoration needed."
fi

# Restart service to apply changes
sudo systemctl restart burp.service
EOF

# deploy-hook-script.sh content
DEPLOY_SCRIPT_CONTENT=$(cat <<EOF
#!/bin/bash

# Stop the Burp Collaborator service
sudo systemctl stop burp.service
    
# Convert the private key and handle certificates
sudo openssl pkcs8 -topk8 -inform PEM -outform PEM -in '$LE_PATH/privkey.pem' -out '$BURP_KEYS_PATH/wildcard_${DOMAIN}.key.pkcs8' -nocrypt && sudo cp '$LE_PATH/fullchain.pem' '$BURP_KEYS_PATH/wildcard_${DOMAIN}.crt' && sudo awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/ { if (n++ > 1) print }' '$LE_PATH/fullchain.pem' > '$BURP_KEYS_PATH/intermediate.crt'
    
# Start the Burp Collaborator service
sudo systemctl start burp.service
    
# Log completion
echo "SSL certificate creation and post-processing completed for $DOMAIN."
EOF
)

# Execute the command to create the deploy-hook-script.sh on the VM
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="sudo echo '$DEPLOY_SCRIPT_CONTENT' > ${WORKING_DIR}/deploy-hook-script.sh"

# Ensure hooks scripts are executable
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="sudo chmod +x $AUTH_HOOK_SCRIPT $CLEANUP_HOOK_SCRIPT $DEPLOY_HOOK_SCRIPT"

# Execute the Certbot command to request a new certificate
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="sudo certbot certonly --manual --preferred-challenges dns --manual-auth-hook \"$AUTH_HOOK_SCRIPT\" --manual-cleanup-hook \"$CLEANUP_HOOK_SCRIPT\" --deploy-hook \"$DEPLOY_HOOK_SCRIPT\" --domains \"$DOMAIN,*.${DOMAIN}\" --no-self-upgrade --non-interactive --agree-tos --email $CERT_EMAIL"

# Command to add SSL configuration to myconfig.config using jq
ADD_SSL_CONFIG_CMD=$(cat <<EOF
jq '. + {"ssl": {"certificateFiles": ["$PKCS8_KEY_PATH", "$CRT_PATH", "$INTERMEDIATE_CRT_PATH"]}}' /root/burp/myconfig.config > /root/burp/myconfig.tmp && mv /root/burp/myconfig.tmp /root/burp/myconfig.config
EOF
)

# Execute the command on the VM
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="sudo $ADD_SSL_CONFIG_CMD"

echo "SSL configuration added to myconfig.config."

# Restart the Burp Collaborator service
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="sudo systemctl restart burp.service"

echo "Restarted burp.service."
echo "Deployment script completed."
