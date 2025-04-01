+++
date = 2025-02-17T02:17:31-03:00
lastmod = 2025-02-18T18:40:04-03:00
draft = false
title = "Virtualização de Redes"
description = "Laboratório de virtualização de redes usando qemu/kvm, network namespaces e openvSwitch"
tags = ['Virtualização', 'Redes', 'qemu', 'openvswitch']
categories = []
featured = true
+++

## O que é virtualização
A virtualização é a tecnologia que permite rodar múltiplos sistemas operacionais ou aplicações em um único hardware, criando versões virtuais de servidores, redes ou armazenamento. Isso otimiza recursos, reduz custos e é a base da computação em nuvem.
## Linha do tempo de tecnologias de virtualização
- **2002** - Surgimento do VMware Workstation, solução proprietária que popularizou a virtualização de sistemas, inspirando futuros projetos open source.
- **2005** - Lançamento do Virtuozzo (posteriormente OpenVZ), pioneiro em virtualização via containers Linux, introduzindo isolamento de recursos em nível de sistema operacional.
- **2006–2007** - Integração do KVM (Kernel-based Virtual Machine) ao kernel Linux, estabelecendo-se como hypervisor tipo 1 open source para criação de máquinas virtuais de alto desempenho.
- **2008** - Lançamento do Microsoft Hyper-V, solução proprietária que impulsionou a competição e o aprimoramento de alternativas open source como KVM e Xen.
- **2010** - Criação do OpenStack, incluindo o componente Neutron para virtualização de redes em nuvens, integrando redes virtuais, armazenamento e computação.
- **2011** - Surgimento do oVirt, plataforma open source derivada do Red Hat Enterprise Virtualization, focada em orquestração de VMs baseadas em KVM.
- **2013** - Revolução com o Docker, que popularizou containers leves, impactando a arquitetura de redes distribuídas através de microserviços isolados.
- **2014** - Lançamento do Kubernetes pelo Google, padrão para orquestração de containers, com projetos posteriores como KubeVirt (2016) unindo VMs e containers.
- **2015** - Padronização da NFV (Virtualização de Funções de Rede) pela ETSI, impulsionando projetos como OpenStack e OPNFV para substituir hardware dedicado por VMs.
- **2016–2020** - Expansão de ecossistemas como KubeVirt (integração de VMs ao Kubernetes) e Cilium (redes baseadas em eBPF), aprimorando redes em ambientes cloud-native.
- **2023** - Consolidação de tecnologias como KVM e OpenStack após a aquisição da VMware pela Broadcom, com foco em SDN, automação via IaC e edge computing.

## Maquinas virtuais e containeres
| Característica             | **Máquinas Virtuais (VMs)**                          | **Contêineres**                                                              |
| -------------------------- | ---------------------------------------------------- | ---------------------------------------------------------------------------- |
| **Isolamento**             | Cada VM tem seu próprio sistema operacional completo | Compartilham o mesmo kernel do host, isolando apenas processos e bibliotecas |
| **Uso de Recursos**        | Mais pesado, pois cada VM precisa de um SO próprio   | Mais leve, pois compartilha recursos do SO do host                           |
| **Tempo de Inicialização** | Lento, pois precisa iniciar um SO completo           | Rápido, pois roda como um processo do host                                   |
| **Escalabilidade**         | Requer mais recursos para escalar                    | Altamente escalável e eficiente para microsserviços                          |
| **Casos de Uso**           | Aplicações legadas, múltiplos SOs no mesmo hardware  | Desenvolvimento ágil, cloud computing e microsserviços                       |
![vm/container](https://www.researchgate.net/publication/369061128/figure/fig2/AS:11431281125201275@1678232029210/Docker-Container-vs-Virtual-Machine.png)

## Interface de rede físicas
Uma **interface física de rede** é um hardware, como uma placa de rede (NIC), porta Ethernet ou adaptador Wi-Fi, que conecta um dispositivo a uma rede. Seu papel é transmitir e receber dados entre computadores, servidores e outros dispositivos, garantindo a comunicação na rede local ou na internet.

![NIC](https://upload.wikimedia.org/wikipedia/commons/thumb/9/9e/Network_card.jpg/1280px-Network_card.jpg)


## Interfaces de rede virtuais
Uma **interface virtual de rede** é uma interface criada por software que simula uma conexão de rede sem a necessidade de hardware físico. Ela é usada para comunicação entre máquinas virtuais, contêineres ou diferentes processos dentro de um sistema. 
Exemplos incluem **veth (Virtual Ethernet)** para comunicação entre namespaces no Linux, **bridge interfaces** para conectar VMs a redes físicas, e **tun/tap interfaces**, que criam conexões de rede tuneladas. 

## Virtual Interfaces
### Tap/Tun
[What is the TAP](https://vtun.sourceforge.net/tun/faq.html#1.2)
```
 The TAP is a Virtual Ethernet network device.  
 TAP driver was designed as low level kernel support for  
 Ethernet tunneling. It provides to userland application  
 two interfaces:  
   - /dev/tapX - character device;  
   - tapX - virtual Ethernet interface.  
  
 Userland application can write Ethernet frame to /dev/tapX  
 and kernel will receive this frame from tapX interface.  
 In the same time every frame that kernel writes to tapX  
 interface can be read by userland application from /dev/tapX  
 device.
```

O driver TUN/TAP fornece recepção e transmissão de pacotes para programas em espaço de usuário. Ele pode ser visto como um dispositivo simples de Ponto-a-Ponto ou Ethernet que, em vez de receber pacotes de uma mídia física, os recebe de um programa em espaço de usuário, e em vez de enviar pacotes por uma mídia física, os escreve para o programa em espaço de usuário.[^1]

Em outras palavras, o driver TUN/TAP cria uma interface de rede virtual no seu host Linux. Essa interface funciona como qualquer outra, ou seja, você pode atribuir um IP a ela, analisar o tráfego, rotear tráfego para ela, etc. Quando o tráfego é enviado para a interface, ele é entregue ao programa em espaço de usuário em vez de ser encaminhado para a rede real.[^1]
### veth
Dispositivos Veth são criados em pares de interfaces Ethernet virtuais conectadas e podem ser vistos como um cabo de rede virtual. O que entra em uma extremidade sai pela outra.
Isso torna os pares veth ideais para conectar diferentes componentes de rede virtual, como bridges do Linux, bridges OVS e contêineres LXC.[^1]


![Comparison of virtual interfaces](https://www.packetcoders.io/content/images/2020/10/image1.png)


## Setup da VM com qemu
Vamos realizar o download de uma Ubuntu Cloud Image. Essa img é otimizada para uso em cloud (utilizando hypervisors) e não vem com senha por padrão. Será necessário fornecer o arquivo para prover configuração de usuários e rede em uma próxima etapa.
### Criar qcow2 overlay com qemu-img
Queremos criar duas máquinas virtuais com base na imagem que fizemos download, porém não queremos alterar a imagem base, dessa maneira criamos uma imagem overlay qcow2 com base na imagem original utilizando *qemu-img*: `qemu-img create -f qcow2 -b ubuntu-24.04-server-cloudimg-amd64.img -F qcow2 vm.qcow2` 
### cloud-init
Em ambientes Cloud, geralmente existe um componente dedicado a fornecer esse arquivo para as VMs, ocorrendo como um servidor web que fornece os metadados ou o próprio hypervisor adiciona um driver semelhante ao que será feito de maneira local no lab.
O conteúdo do cloud init está em [[network-virtualization#Apêndice#Cloud Init]], os arquivos de rede devem estar separados do user-data.
O pacote [cloud-utils](https://github.com/canonical/cloud-utils) deve ser instalado para gerar localmente a imagem.
`cloud-localds --network-config=./config-data/network-config my-seed.img ./config-data/user-data.yaml`
Adicionalmente, o pacote cloud-init tem um validator para conferir se o schema desses dois arquivos são válidos:
`cloud-init schema --config-file user-data.yaml`
`cloud-init schema -c network-config-dns --schema-type network-config` 
### Execução da VM com qemu:
A primeira VM será criada executando o seguinte comando:
```
# Create machine using e1000 driver
qemu-system-x86_64 \
-name "Legacy-Net-Driver" \
-cpu host \
-enable-kvm \
-drive if=virtio,format=qcow2,file=e1000.qcow2 \
-drive if=virtio,format=raw,file=my-seed.img \
-m 2048 -smp 2 \
-netdev tap,id=mynet0,ifname=tap0,script=no,downscript=no \
-device e1000,netdev=mynet0,mac=52:54:00:12:34:56 \
-nographic -serial mon:stdio
```
Explicação dos argumentos mais relevantes:
-  -enable-kvm -> habilita o KVM (utiliza instruções do processador de virtualização para melhor desempenho)
- -drive if=virtio,format=qcow2,file=e1000.qcow2 -> carrega o driver com a imagem que foi criada a partir da cloudimg original, virtio é especificado como driver para melhor desempenho.
- -drive if=virtio,format=raw,file=my-seed.img -> carrega a imagem de cloud-init que foi criada
- -m 2048 -> 2gb de memória ram
- -smp 2 -> 2 cores virtuais
- -netdev tap,id=mynet0,ifname=tap0,script=no,downscript=no 
	- netdev especifica que uma interface tap será utilizada para conectar a vm a rede
	- id é um identificador para essa interface
	- ifname será o nome do tap que foi criado manualmente
- -device e1000,netdev=mynet0,mac=52:54:00:12:34:56
	- adiciona um dispositivo de rede virtual usando o driver e1000
	- netdev conecta a interface ao backend no comando anterior
	- mac define um endereço mac para a interface 
A diferença entre as duas VMs criadas é que invés de usar o driver e1000, virtio será utilizado como driver de rede, permitindo maior largura de banda.
## Linux Bridges
Uma bridge Linux se comporta como um switch de rede. Ela encaminha pacotes entre interfaces conectadas a ela. Normalmente é utilizada para encaminhar pacotes em roteadores, em gateways ou entre máquinas virtuais e namespaces de rede em um host.[^2]
### Por que Open vSwitch no lugar de Linux Bridges?
Open vSwitch está direcionado para implantações de virtualização multi-servidor, um cenário para o qual a stack anterior não era bem adequada. Estes ambientes são frequentemente caracterizados por pontos finais altamente dinâmicos, a manutenção de abstrações lógicas, e (às vezes) integração com ou offloading para hardware de switching especializado.[^3]
## Linux Network Namespaces
Namespaces de rede são uma característica do kernel Linux que permite criar ambientes de rede isolados dentro de um único sistema. Cada namespace de rede tem sua própria pilha de rede e conjunto de recursos de networking, como interfaces de rede virtuais, tabelas de roteamento, regras de firewall e mais. Isso possibilita criar múltiplos contextos de networking independentes em um único sistema, cada um com seu próprio conjunto de configurações de networking.

Namespaces de rede são frequentemente utilizados em conjunto com outros tipos de namespaces, como PID namespaces, para criar ambientes isolados para execução de processos. Este é um aspecto fundamental da containerização e virtualização, pois permite criar ambientes leves, portáteis e seguros para execução de aplicações.[^4]

## Laboratório

Será construído uma topologia de rede semelhante ao exemplo de bridge nesse artigo sobre [interfaces virtuais da Red Hat](https://developers.redhat.com/blog/2018/10/22/introduction-to-linux-interfaces-for-virtual-networking#). Duas VMs serão criadas (para usar diferentes drivers de rede virtuais) e um namespace Linux.

![Bridge](https://developers.redhat.com/blog/wp-content/uploads/2018/10/bridge.png)

```
# ------------ core componentes installation -------------
# Download KVM
# - Arch: pacman -S qemu
# - Debian: apt install qemu-system

# Download Open vSwitch
# - Arch: pacman -S openvswitch
# - Debian: apt install openvswitch-switch openvswitch-common

# Start ovs server 
# - sudo /usr/share/openvswitch/scripts/ovs-ctl start 


# ------------ vm and ovs setup -------------
# Download ubuntu cloudimg
wget https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img

# Create two overlays of the base image
qemu-img create -f qcow2 -b ubuntu-24.04-server-cloudimg-amd64.img -F 
qcow2 e1000.qcow2
qemu-img create -f qcow2 -b ubuntu-24.04-server-cloudimg-amd64.img -F 
qcow2 virtio.qcow2

# Create TAP devices 
sudo ip tuntap add mode tap user $USER name tap0
sudo ip tuntap add mode tap user $USER name tap1
sudo ip link set tap0 up
sudo ip link set tap1 up

# Create OVS bridge and add ports
sudo ovs-vsctl add-br ovs-br
sudo ovs-vsctl add-port ovs-br tap0
sudo ovs-vsctl add-port ovs-br tap1

# Assign IP to bridge for host communication
sudo ip addr add 192.168.100.1/24 dev ovs-br
sudo ip link set ovs-br up

# Enable ip forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Use nat to provide vms virtual connection, wlp2s0 should
# be your internet connected interface and ovs-br should be your bridge
sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o wlp2s0 -j MASQUERADE
sudo iptables -A FORWARD -i ovs-br -o wlp2s0 -j ACCEPT
sudo iptables -A FORWARD -i wlp2s0 -o ovs-br -m state --state RELATED,ESTABLISHED -j ACCEPT

# Set up a DHCP server to provide IPs to VMs
# install dnsmasq
sudo apt install dnsmasq

# Edit the /etc/dnsmasq.conf file
sudo vim /etc/dnsmasq.conf

# Enable the service 
sudo systemctl start dnsmasq.service

# Allow dhcp traffic [may not be necessary]
# sudo iptables -A INPUT -p udp --dport 67 -j ACCEPT
# sudo iptables -A INPUT -p udp --dport 68 -j ACCEPT

# Create cloud-init.yaml using cloud-init yaml
# Install cloud-image-utils on arch or cloud-utils on apt-based
sudo apt install cloud-utils

# Generate cloud-init img
cloud-localds --network-config=./config-data/network-config my-seed.img ./c
onfig-data/user-data.yaml

# Start VMs
# Create machine using e1000 driver
qemu-system-x86_64 \
-name "Legacy-Net-Driver" \
-cpu host \
-enable-kvm \
-drive if=virtio,format=qcow2,file=e1000.qcow2 \
-drive if=virtio,format=raw,file=my-seed.img \
-m 2048 -smp 2 \
-netdev tap,id=mynet0,ifname=tap0,script=no,downscript=no \
-device e1000,netdev=mynet0,mac=52:54:00:12:34:56 \
-nographic -serial mon:stdio

# Create machine using virtio driver
qemu-system-x86_64 \
-name "Virtio-Net-Driver" \
-cpu host \
-enable-kvm \
-drive if=virtio,format=qcow2,file=virtio.qcow2 \
-drive if=virtio,format=raw,file=my-seed.img \
-m 2048 -smp 2 \
-netdev tap,id=mynet1,ifname=tap1,script=no,downscript=no \
-device virtio-net-pci,netdev=mynet1,mac=52:54:00:12:34:57 \
-nographic -serial mon:stdio

# if dhcp with dnsmasq fail for some reason, you can configure manually IP, 
# routes and dns inside the virtual machines/namespace:
# inside vms, set up network interface ip, a default gw to internet
# through the bridge and change the dns to 8.8.8.8 manually editing 
# /etc/resolv.conf
# sudo ip a add 192.168.100.3/24 dev ens3
# sudo ip r add default via 192.168.100.1 dev ens3
# sudo vim /etc/resolv.conf

# ------------ linux namespaces -------------
# on the host system, create a linux network namespace
sudo ip netns add ns1

# create a veth pair and move one end to the namespace
sudo ip link add veth-host type veth peer name veth-ns
sudo ip link set veth-ns netns ns1

# activate both ends
sudo ip netns exec ns1 ip link set veth-ns up
sudo ip link set veth-host up

# add the host-side to the bridge
sudo ovs-vsctl add-port ovs-br veth-host

# run bash inside the namespace
sudo ip netns exec ns1 bash

# if dnsmasq is providing dhcp, get an ip using dhclient
# if dnsmasq is not providing, configure ip, routes and dns manually
dhclient -v


# ------------ benchmarking -------------

# install iperf3 on the hosts and the vms
sudo apt update
sudo pat install iperf3

# Benchmarking bandwidth
# on the host, start iperf3 server
iperf3 -s -B 192.168.100.1
# on the virtual machines/namespaces connect to the server
iperf3 -c 192.168.100.1


# ------------ cleanup -------------
sudo ovs-vsctl del-br ovs-br
sudo ip link del tap0
sudo ip link del tap1
sudo ip netns del ns1
sudo ip link del veth-host
```

## Apêndice
### Cloud Init
Será necessário criar os dois arquivos para adicionar ao cloud-init:

``` network-config.yaml
version: 2
ethernets:
  ens3:
    dhcp4: true
```

``` user-data.yaml
#cloud-config
ssh_pwauth: True
chpasswd:
  expire: false
  users:
  - {name: ubuntu, password: ubuntu, type: text}
users:
  - name: ubuntu
    ssh-authorized-keys:
      - <your public key here>
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    groups: users, sudo
    shell: /bin/bash
```

### Servidor dhcp
dnsmasq será utilizado para prover dhcp, edite o arquivo de configurações em `/etc/dnsmasq.conf` com o conteúdo a seguir:
``` dnsmasq.conf
interface=ovs-br
dhcp-range=192.168.100.2,192.168.100.200,12h
dhcp-option=option:dns-server,8.8.8.8
```

## Referências

[^1]: https://www.packetcoders.io/virtual-networking-devices-tun-tap-and-veth-pairs-explained/

[^2]: https://developers.redhat.com/blog/2018/10/22/introduction-to-linux-interfaces-for-virtual-networking#bridge

[^3]: https://docs.openvswitch.org/en/latest/intro/why-ovs/#why-open-vswitch

[^4]: https://abdelouahabmbarki.com/linux-namespaces-network-ns/
	

