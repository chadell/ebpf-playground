resource "digitalocean_droplet" "vm" {
  image  = "ubuntu-22-04-x64"
  name   = format("%s-%s", "ebpf-lab", "1")
  region = var.vm_region
  size   = var.vm_size
  ssh_keys = [
    data.digitalocean_ssh_key.terraform.id
  ]
  tags = [
    "ebpf-playground"
  ]

  connection {
    host        = self.ipv4_address
    user        = "root"
    type        = "ssh"
    private_key = file(var.pvt_key)
    timeout     = "2m"
  }

  provisioner "file" {
    source      = var.pub_ssh_key
    destination = "/tmp/temp.pub"
  }


  provisioner "remote-exec" {
    inline = [
      # Set up SSH keys
      "cat /tmp/temp.pub >> ~/.ssh/authorized_keys",
      "sudo apt-get update -y",
      "sleep 60",
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apt-transport-https ca-certificates curl clang llvm jq",
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libelf-dev libpcap-dev libbfd-dev binutils-dev build-essential make",
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-tools-common linux-tools-$(uname -r)",
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bpfcc-tools",
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-pip",
    ]
  }
}




resource "digitalocean_firewall" "fw" {
  name = "fw-rules"

  droplet_ids = [digitalocean_droplet.vm.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  #   inbound_rule {
  #     protocol         = "tcp"
  #     port_range       = "8080"
  #     source_addresses = ["0.0.0.0/0", "::/0"]
  #   }

  #   inbound_rule {
  #     protocol         = "tcp"
  #     port_range       = "443"
  #     source_addresses = ["0.0.0.0/0", "::/0"]
  #   }

  #   inbound_rule {
  #     protocol         = "tcp"
  #     port_range       = "12000-12999"
  #     source_addresses = ["0.0.0.0/0", "::/0"]
  #   }

  inbound_rule {
    protocol         = "icmp"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "tcp"
    port_range            = "53"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "53"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

output "ssh_commands" {
  value = "ssh -o StrictHostKeyChecking=no -i ${var.pvt_key} root@${digitalocean_droplet.vm.ipv4_address}"
}
