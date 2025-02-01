variable "ACCONT_ID" {
  type = string
}

variable "ORG" {
  type = string
}

variable "MACHINE_TYPE" {
  type = string
  default = "n2-standard-2"
}

variable "ZONE" {
  type = string
  default = "us-central1-a"
}

resource "google_service_account" "default" {
  account_id   = var.ACCONT_ID
  display_name = "Custom SA for VM Instance"
}

resource "google_network_security_security_profile" "security_profile" {
    name        = "sec-profile"
    type        = "THREAT_PREVENTION"
    parent      = var.ORG
    location    = "global"
	
	custom_mirroring_profile {
		mirroring_endpoint_group = google_network_security_mirroring_endpoint_group.default.id
	}
}

resource "google_compute_network" "vpc_network" {
  project                                   = "my-project-name"
  name                                      = "vpc-network"
  auto_create_subnetworks                   = true
  network_firewall_policy_enforcement_order = "BEFORE_CLASSIC_FIREWALL"
}

resource "google_compute_firewall" "rules" {
  name        = "my-firewall-rule"
  network     = "default"
  description = "Creates firewall rule targeting tagged instances"

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web"]
}

resource "google_network_security_intercept_deployment_group" "default" {
  provider                      = google-beta
  intercept_deployment_group_id = "deployment-group"
  location                      = "global"
  network                       = google_compute_network.default.id
}

resource "google_network_security_intercept_endpoint_group" "default" {
  provider                      = google-beta
  intercept_endpoint_group_id   = "endpoint-group"
  location                      = "global"
  intercept_deployment_group    = google_network_security_intercept_deployment_group.default.id
}

resource "google_network_security_security_profile_group" "default" {
  provider                  = google-beta
  name                      = "sec-profile-group"
  parent                    = var.ORG
  description               = "Security group"
  threat_prevention_profile = google_network_security_security_profile.security_profile.id
}


resource "google_compute_instance" "wazuh" {
  name         = "my-wazuh"
  machine_type = var.MACHINE_TYPE
  zone         = var.ZONE

  boot_disk {
    initialize_params {
      image = "ubuntu-minimal-2210-kinetic-amd64-v20230126"
    }
  }

  scratch_disk {
    interface = "NVME"
  }

  network_interface {
    network = google_compute_network.default.id
  }

  metadata_startup_script = "curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && bash ./wazuh-install.sh -a"

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.default.email
    scopes = ["cloud-platform"]
  }
}


resource "google_compute_instance" "misp" {
  name         = "my-misp"
  machine_type = var.MACHINE_TYPE
  zone         = var.ZONE

  boot_disk {
    initialize_params {
      image = "ubuntu-minimal-2210-kinetic-amd64-v20230126"
    }
  }

  scratch_disk {
    interface = "NVME"
  }

  network_interface {
    network = google_compute_network.default.id
  }

  metadata_startup_script = "apt-get update && apt-get install wget && wget --no-cache -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh && bash /tmp/INSTALL.sh -c"

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.default.email
    scopes = ["cloud-platform"]
  }
}
