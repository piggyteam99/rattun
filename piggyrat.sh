#!/bin/bash

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   sleep 1
   exit 1
fi

press_key(){
 read -p "Press any key to continue..."
}

colorize() {
    local color="$1"
    local text="$2"
    local style="${3:-normal}"
    
    local black="\033[30m"
    local red="\033[31m"
    local green="\033[32m"
    local yellow="\033[33m"
    local blue="\033[34m"
    local magenta="\033[35m"
    local cyan="\033[36m"
    local white="\033[37m"
    local reset="\033[0m"
    
    local normal="\033[0m"
    local bold="\033[1m"
    local underline="\033[4m"
    
    local color_code
    case $color in
        black) color_code=$black ;;
        red) color_code=$red ;;
        green) color_code=$green ;;
        yellow) color_code=$yellow ;;
        blue) color_code=$blue ;;
        magenta) color_code=$magenta ;;
        cyan) color_code=$cyan ;;
        white) color_code=$white ;;
        *) color_code=$reset ;; 
    esac
    local style_code
    case $style in
        bold) style_code=$bold ;;
        underline) style_code=$underline ;;
        normal | *) style_code=$normal ;; 
    esac

    echo -e "${style_code}${color_code}${text}${reset}"
}

install_unzip() {
    if ! command -v unzip &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y unzip
        fi
    fi
}
install_unzip

install_cron() {
    if ! command -v cron &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y cron
        fi
    fi
}
install_cron

install_jq() {
    if ! command -v jq &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y jq
        fi
    fi
}
install_jq

# ----------------- HAPROXY INSTALLATION -----------------
HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
HAPROXY_MARK="# RATHOLE_LB"

install_haproxy() {
  if ! command -v haproxy >/dev/null 2>&1; then
    echo -e "${YELLOW}Installing HAProxy for Load Balancing...${NC}"
    if command -v apt-get >/dev/null; then
      sudo apt-get update -y
      sudo apt-get install -y haproxy
    fi
  fi
  
  if [[ ! -f "$HAPROXY_CFG" ]] || ! grep -q "$HAPROXY_MARK GLOBAL" "$HAPROXY_CFG"; then
    cat > "$HAPROXY_CFG" <<EOF
global
    daemon
    maxconn 500000

defaults
    mode tcp
    timeout connect 10s
    timeout client 1m
    timeout server 1m

$HAPROXY_MARK GLOBAL
EOF
  fi
}

restart_haproxy() {
  haproxy -c -f "$HAPROXY_CFG" >/dev/null 2>&1
  systemctl restart haproxy
  systemctl enable haproxy >/dev/null 2>&1 || true
}

config_dir="/root/rathole-core"
download_and_extract_rathole() {
    if [[ -f "${config_dir}/rathole" ]]; then
        if [[ "$1" == "sleep" ]]; then
            colorize green "Rathole Core is already installed." bold
        	sleep 1
       	fi 
        return 1
    fi

    ENTRY="185.199.108.133 raw.githubusercontent.com"
    if ! grep -q "$ENTRY" /etc/hosts; then
        echo "$ENTRY" >> /etc/hosts
    fi

    if [[ $(uname) == "Linux" ]]; then
        ARCH=$(uname -m)
        DOWNLOAD_URL=$(curl -sSL https://api.github.com/repos/rapiz1/rathole/releases/latest | grep -o "https://.*$ARCH.*linux.*zip" | head -n 1)
    else
        exit 1
    fi
    if [[ "$ARCH" == "x86_64" ]]; then
    	DOWNLOAD_URL='https://github.com/Musixal/rathole-tunnel/raw/main/core/rathole.zip'
    fi

    DOWNLOAD_DIR=$(mktemp -d)
    curl -sSL -o "$DOWNLOAD_DIR/rathole.zip" "$DOWNLOAD_URL"
    unzip -q "$DOWNLOAD_DIR/rathole.zip" -d "$config_dir"
    chmod u+x ${config_dir}/rathole
    rm -rf "$DOWNLOAD_DIR"
}
download_and_extract_rathole

SERVER_COUNTRY=$(curl --max-time 3 -sS "http://ipwhois.app/json/$SERVER_IP" | jq -r '.country' 2>/dev/null)
SERVER_ISP=$(curl --max-time 3 -sS "http://ipwhois.app/json/$SERVER_IP" | jq -r '.isp' 2>/dev/null)

display_logo() {   
    echo -e "${CYAN}"
    cat << "EOF"
               __  .__           .__          
____________ _/  |_|  |__   ____ |  |   ____  
\_  __ \__  \\   __|  |  \ /  _ \|  | _/ __ \ 
 |  | \// __ \|  | |   Y  (  <_> |  |_\  ___/ 
 |__|  (____  |__| |___|  /\____/|____/\___  >
            \/          \/                 \/ 	
EOF
    echo -e "${NC}${GREEN}"
    echo -e "Version: ${YELLOW}v3.0 (HAProxy + Rathole Hybrid LB)${GREEN}"
    echo -e "Github: ${YELLOW}github.com/Musixal/Rathole-Tunnel${GREEN}"
}

display_server_info() {
    echo -e "\e[93m═════════════════════════════════════════════\e[0m"  
    echo -e "${CYAN}Location:${NC} $SERVER_COUNTRY "
    echo -e "${CYAN}Datacenter:${NC} $SERVER_ISP"
}

display_rathole_core_status() {
    if [[ -f "${config_dir}/rathole" ]]; then
        echo -e "${CYAN}Rathole Core:${NC} ${GREEN}Installed${NC}"
    else
        echo -e "${CYAN}Rathole Core:${NC} ${RED}Not installed${NC}"
    fi
    echo -e "\e[93m═════════════════════════════════════════════\e[0m"  
}

check_ipv6() {
    local ip=$1
    ipv6_pattern="^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$|^(([0-9a-fA-F]{1,4}:){1,7}|:):((:[0-9a-fA-F]{1,4}){1,7}|:)$"
    ip="${ip#[}"
    ip="${ip%]}"
    if [[ $ip =~ $ipv6_pattern ]]; then return 0; else return 1; fi
}

check_port() {
    local PORT=$1
	local TRANSPORT=$2
    if [ -z "$PORT" ]; then return 1; fi
	if [[ "$TRANSPORT" == "tcp" ]]; then
		if ss -tlnp "sport = :$PORT" | grep "$PORT" > /dev/null; then return 0; else return 1; fi
	else
		if ss -ulnp "sport = :$PORT" | grep "$PORT" > /dev/null; then return 0; else return 1; fi
   	fi
}

configure_tunnel() {
    if [[ ! -d "$config_dir" ]]; then
        echo -e "\n${RED}Rathole-core directory not found. Install it first.${NC}\n"
        read -p "Press Enter to continue..."
        return 1
    fi
    clear
    colorize green "Essential tips for Load Balancing:" bold
    colorize yellow "   Because we use HAProxy for load balancing, Transport is enforced to TCP."
    echo
    colorize green "1) Configure for IRAN server" bold
    colorize magenta "2) Configure for KHAREJ server" bold
    echo
    read -p "Enter your choice: " configure_choice
    case "$configure_choice" in
        1) iran_server_configuration ;;
        2) kharej_server_configuration ;;
        *) echo -e "${RED}Invalid option!${NC}" && sleep 1 ;;
    esac
    echo
    read -p "Press Enter to continue..."
}

service_dir="/etc/systemd/system"
  
iran_server_configuration() {  
    clear
    colorize cyan "Configuring IRAN server (HAProxy + Rathole)" bold
    echo
    
    install_haproxy

    # 1. Get Target Port (The one user connects to)
    while true; do
        colorize magenta "[!] Target Port: پورت کانفیگ شما (مثلا 8080) که میخواهید روی صد پورت تانل لود بالانس شود."
	    echo -ne "[*] Enter Target Port (SINGLE PORT): "
	    read -r target_port
	    if [[ "$target_port" =~ ^[0-9]+$ ]] && [ "$target_port" -gt 22 ] && [ "$target_port" -le 65535 ]; then
	        if check_port "$target_port" "tcp"; then
	            colorize red "Port $target_port is in use by another app."
	        else
	            break
	        fi
	    else
	        colorize red "Please enter a valid port number."
	    fi
	done
    echo

    # 2. Get Tunnel Ports Range
    declare -a tunnel_ports
	while true; do
        colorize magenta "[!] Tunnel Ports Range: رنج پورت‌های تانل بین دو سرور (مثلا 7000-7099)"
	    echo -ne "[*] Enter Tunnel Ports Range: "
	    read -r t_input
        t_input=$(echo "$t_input" | tr -d ' ')

        if [[ "$t_input" == *-* ]]; then
            IFS='-' read -r start end <<< "$t_input"
            if [[ "$start" =~ ^[0-9]+$ ]] && [[ "$end" =~ ^[0-9]+$ ]] && [ "$start" -le "$end" ]; then
                for (( p=start; p<=end; p++ )); do
                    if ! check_port "$p" "tcp"; then tunnel_ports+=("$p"); fi
                done
                break
            else
                colorize red "Invalid range format!"
            fi
        else
            colorize red "Please enter a range (e.g. 7000-7050)."
        fi
	done
	
	echo
	local nodelay=""
	while [[ "$nodelay" != "true" && "$nodelay" != "false" ]]; do
	    echo -ne "[*] Enable TCP_NODELAY (true/false): " 
	    read -r nodelay
	done
    
    echo
	local HEARTBEAT=""
	while [[ "$HEARTBEAT" != "true" && "$HEARTBEAT" != "false" ]]; do
	    echo -ne "[*] Enable HEARTBEAT (true/false): " 
	    read -r HEARTBEAT
	done
    if [[ "$HEARTBEAT" == "true" ]]; then HEARTBEAT="30"; else HEARTBEAT="0"; fi
    
    echo
	echo -ne "[-] Security Token (press enter to use default value): "
	read -r token
	if [[ -z "$token" ]]; then token="musixal"; fi
	echo 
	
    local num_tunnels=${#tunnel_ports[@]}
    colorize cyan "Generating Configuration for 1 Target Port ($target_port) load-balanced over $num_tunnels Tunnels..."

    # 3. Configure HAProxy on Iran
    local haproxy_id="IRAN_LB_${target_port}_${tunnel_ports[0]}_${num_tunnels}"
    cat >> "$HAPROXY_CFG" <<EOF

$HAPROXY_MARK START $haproxy_id

frontend main_$haproxy_id
    bind *:$target_port
    default_backend balance_$haproxy_id

backend balance_$haproxy_id
    balance roundrobin
EOF

    # 4. Generate Rathole Iran Configs and HAProxy backend servers
    # We will use dummy ports starting from 20000+ for internal communication
    local base_dummy=20000
    for i in "${!tunnel_ports[@]}"; do
        local t_port=${tunnel_ports[$i]}
        local dummy_port=$((base_dummy + i))

        # Add to HAProxy backend
        echo "    server s${dummy_port}_$haproxy_id 127.0.0.1:$dummy_port check" >> "$HAPROXY_CFG"

        # Create Rathole TOML
        cat << EOF > "${config_dir}/iran${t_port}.toml"
[server]
bind_addr = "0.0.0.0:${t_port}"
default_token = "$token"
heartbeat_interval = $HEARTBEAT

[server.transport]
type = "tcp"

[server.transport.tcp]
nodelay = $nodelay

[server.services.srv_${target_port}]
type = "tcp"
bind_addr = "127.0.0.1:${dummy_port}"
EOF

        # Create Service
        cat << EOF > "${service_dir}/rathole-iran${t_port}.service"
[Unit]
Description=Rathole Iran Port $t_port
After=network.target

[Service]
Type=simple
ExecStart=${config_dir}/rathole ${config_dir}/iran${t_port}.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload >/dev/null 2>&1
        systemctl enable --now "${service_dir}/rathole-iran${t_port}.service" >/dev/null 2>&1
    done

    echo "$HAPROXY_MARK END $haproxy_id" >> "$HAPROXY_CFG"
    restart_haproxy
     
    echo
    colorize green "IRAN server Hybrid Load-Balanced configuration completed successfully!"
}

kharej_server_configuration() {
    clear
    colorize cyan "Configuring KHAREJ server (Rathole Aggregation)" bold 
    echo
 
	while true; do
	    echo -ne "[*] IRAN server IP address [IPv4/IPv6]: " 
	    read -r SERVER_ADDR
	    if [[ -n "$SERVER_ADDR" ]]; then break; fi
	done
    echo

    # 1. Get Target Port (The real final port of Xray/Panel on Kharej)
    while true; do
        colorize magenta "[!] Target Port: پورت واقعی سرور خارج (همان پورتی که در ایران وارد کردید، مثلا 8080)"
	    echo -ne "[*] Enter Target Port (SINGLE PORT): "
	    read -r target_port
	    if [[ "$target_port" =~ ^[0-9]+$ ]] && [ "$target_port" -gt 22 ] && [ "$target_port" -le 65535 ]; then
	        break
	    else
	        colorize red "Please enter a valid port number."
	    fi
	done
    echo
    
    # 2. Get Tunnel Ports Range
    declare -a tunnel_ports
 	while true; do
        colorize magenta "[!] Tunnel Ports Range: رنج پورت‌های تانل (دقیقا همان رنجی که در ایران زدید، مثلا 7000-7099)"
	    echo -ne "[*] Enter Tunnel Ports Range: "
	    read -r t_input
        t_input=$(echo "$t_input" | tr -d ' ')

        if [[ "$t_input" == *-* ]]; then
            IFS='-' read -r start end <<< "$t_input"
            if [[ "$start" =~ ^[0-9]+$ ]] && [[ "$end" =~ ^[0-9]+$ ]] && [ "$start" -le "$end" ]; then
                for (( p=start; p<=end; p++ )); do
                    tunnel_ports+=("$p")
                done
                break
            else
                colorize red "Invalid range format!"
            fi
        else
            colorize red "Please enter a range (e.g. 7000-7050)."
        fi
	done
    echo
    
	local nodelay=""
	while [[ "$nodelay" != "true" && "$nodelay" != "false" ]]; do
	    echo -ne "[*] TCP_NODELAY (true/false): " 
	    read -r nodelay
	done
	echo
	
	local HEARTBEAT=""
	while [[ "$HEARTBEAT" != "true" && "$HEARTBEAT" != "false" ]]; do
	    echo -ne "[*] Enable HEARTBEAT (true/false): " 
	    read -r HEARTBEAT
	done
    if [[ "$HEARTBEAT" == "true" ]]; then HEARTBEAT="40"; else HEARTBEAT="0"; fi
    echo

	echo -ne "[-] Security Token (press enter to use default value): "
	read -r token
	if [[ -z "$token" ]]; then token="musixal"; fi
	echo
			
	local_ip='127.0.0.1'
	if check_ipv6 "$SERVER_ADDR"; then
	    SERVER_ADDR="${SERVER_ADDR#[}"
	    SERVER_ADDR="${SERVER_ADDR%]}"
	fi

    local num_tunnels=${#tunnel_ports[@]}
    colorize cyan "Generating Configuration: $num_tunnels Tunnels merging into Target Port $target_port..."

    # 3. Create Rathole Client Configs (All pointing to the exact same Target Port)
    for t_port in "${tunnel_ports[@]}"; do
        cat << EOF > "${config_dir}/kharej${t_port}.toml"
[client]
remote_addr = "${SERVER_ADDR}:${t_port}"
default_token = "$token"
heartbeat_timeout = $HEARTBEAT
retry_interval = 1

[client.transport]
type = "tcp"

[client.transport.tcp]
nodelay = $nodelay

[client.services.srv_${target_port}]
type = "tcp"
local_addr = "${local_ip}:${target_port}"
EOF

        # Create Systemd Services
        cat << EOF > "${service_dir}/rathole-kharej${t_port}.service"
[Unit]
Description=Rathole Kharej Port $t_port 
After=network.target

[Service]
Type=simple
ExecStart=${config_dir}/rathole ${config_dir}/kharej${t_port}.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload >/dev/null 2>&1
        systemctl enable --now "${service_dir}/rathole-kharej${t_port}.service" >/dev/null 2>&1
    done

    echo
    colorize green "KHAREJ server Aggregation configuration completed successfully."
}

check_tunnel_status() {
    echo
	if ! ls "$config_dir"/*.toml 1> /dev/null 2>&1; then
	    colorize red "No config files found in the rathole directory." bold
	    echo 
	    press_key
	    return 1
	fi
	clear
    colorize yellow "Checking all services status (Summary)..." bold
    sleep 1
    echo
    
    local iran_running=0
    local iran_total=0
    for config_path in "$config_dir"/iran*.toml; do
        if [ -f "$config_path" ]; then
            ((iran_total++))
			config_name=$(basename "$config_path")
			config_name="${config_name%.toml}"
			service_name="rathole-${config_name}.service"
			if systemctl is-active --quiet "$service_name"; then ((iran_running++)); fi
   		fi
    done
    
    local kharej_running=0
    local kharej_total=0
    for config_path in "$config_dir"/kharej*.toml; do
        if [ -f "$config_path" ]; then
            ((kharej_total++))
			config_name=$(basename "$config_path")
			config_name="${config_name%.toml}"
			service_name="rathole-${config_name}.service"
			if systemctl is-active --quiet "$service_name"; then ((kharej_running++)); fi
   		fi
    done

    if [ $iran_total -gt 0 ]; then
        colorize cyan "Iran Tunnels: $iran_running / $iran_total are RUNNING." bold
    fi
    if [ $kharej_total -gt 0 ]; then
        colorize cyan "Kharej Tunnels: $kharej_running / $kharej_total are RUNNING." bold
    fi
    
    echo
    press_key
}

tunnel_management() {
    echo
    colorize yellow "Management for hybrid tunnels requires complete removal and recreation for safety."
    echo
    read -p "Do you want to REMOVE ALL current tunnels? (y/n): " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        # Remove HAProxy blocks
        if [ -f "$HAPROXY_CFG" ]; then
            sed -i "/$HAPROXY_MARK START/,/$HAPROXY_MARK END/d" "$HAPROXY_CFG"
            restart_haproxy
        fi
        
        # Remove services and files
        for config_path in "$config_dir"/*.toml; do
            if [ -f "$config_path" ]; then
                config_name=$(basename "$config_path" .toml)
                service_name="rathole-${config_name}.service"
                systemctl disable --now "$service_name" >/dev/null 2>&1
                rm -f "${service_dir}/${service_name}"
                rm -f "$config_path"
            fi
        done
        systemctl daemon-reload
        colorize green "All tunnels destroyed."
    fi
    press_key
}

remove_core(){
	echo
	if find "$config_dir" -type f -name "*.toml" | grep -q .; then
	    colorize red "You should delete all services first and then delete the rathole-core."
	    sleep 3
	    return 1
	fi
	echo
	colorize yellow "Do you want to remove rathole-core? (y/n)"
    read -r confirm
	echo     
	if [[ $confirm == [yY] ]]; then
	    if [[ -d "$config_dir" ]]; then
	        rm -rf "$config_dir" >/dev/null 2>&1
	        colorize green "Rathole-core directory removed." bold
	    else
	        colorize red "Rathole-core directory not found." bold
	    fi
	fi
	echo
	press_key
}

# ----------------- Hawshemi & Limits -----------------
SYS_PATH="/etc/sysctl.conf"
PROF_PATH="/etc/profile"
ask_reboot() {
    echo -ne "${YELLOW}Reboot now? (Recommended) (y/n): ${NC}"
    while true; do
        read choice
        echo 
        if [[ "$choice" == 'y' || "$choice" == 'Y' ]]; then sleep 0.5; reboot; exit 0; fi
        if [[ "$choice" == 'n' || "$choice" == 'N' ]]; then break; fi
    done
}
sysctl_optimizations() {
    cp $SYS_PATH /etc/sysctl.conf.bak
    sed -i -e '/fs.file-max/d' -e '/net.core.default_qdisc/d' -e '/net.core.netdev_max_backlog/d' -e '/net.core.optmem_max/d' -e '/net.core.somaxconn/d' -e '/net.core.rmem_max/d' -e '/net.core.wmem_max/d' -e '/net.core.rmem_default/d' -e '/net.core.wmem_default/d' -e '/net.ipv4.tcp_rmem/d' -e '/net.ipv4.tcp_wmem/d' -e '/net.ipv4.tcp_congestion_control/d' -e '/net.ipv4.tcp_fastopen/d' -e '/net.ipv4.tcp_fin_timeout/d' -e '/net.ipv4.tcp_keepalive_time/d' -e '/net.ipv4.tcp_keepalive_probes/d' -e '/net.ipv4.tcp_keepalive_intvl/d' -e '/net.ipv4.tcp_max_orphans/d' -e '/net.ipv4.tcp_max_syn_backlog/d' -e '/net.ipv4.tcp_max_tw_buckets/d' -e '/net.ipv4.tcp_mem/d' -e '/net.ipv4.tcp_mtu_probing/d' -e '/net.ipv4.tcp_notsent_lowat/d' -e '/net.ipv4.tcp_retries2/d' -e '/net.ipv4.tcp_sack/d' -e '/net.ipv4.tcp_dsack/d' -e '/net.ipv4.tcp_slow_start_after_idle/d' -e '/net.ipv4.tcp_window_scaling/d' -e '/net.ipv4.tcp_adv_win_scale/d' -e '/net.ipv4.tcp_ecn/d' -e '/net.ipv4.tcp_ecn_fallback/d' -e '/net.ipv4.tcp_syncookies/d' -e '/net.ipv4.udp_mem/d' -e '/net.ipv6.conf.all.disable_ipv6/d' -e '/net.ipv6.conf.default.disable_ipv6/d' -e '/net.ipv6.conf.lo.disable_ipv6/d' -e '/net.unix.max_dgram_qlen/d' -e '/vm.min_free_kbytes/d' -e '/vm.swappiness/d' -e '/vm.vfs_cache_pressure/d' -e '/net.ipv4.conf.default.rp_filter/d' -e '/net.ipv4.conf.all.rp_filter/d' -e '/net.ipv4.conf.all.accept_source_route/d' -e '/net.ipv4.conf.default.accept_source_route/d' -e '/net.ipv4.neigh.default.gc_thresh1/d' -e '/net.ipv4.neigh.default.gc_thresh2/d' -e '/net.ipv4.neigh.default.gc_thresh3/d' -e '/net.ipv4.neigh.default.gc_stale_time/d' -e '/net.ipv4.conf.default.arp_announce/d' -e '/net.ipv4.conf.lo.arp_announce/d' -e '/net.ipv4.conf.all.arp_announce/d' -e '/kernel.panic/d' -e '/vm.dirty_ratio/d' -e '/^#/d' -e '/^$/d' "$SYS_PATH"
cat <<EOF >> "$SYS_PATH"
fs.file-max = 67108864
net.core.default_qdisc = fq_codel
net.core.netdev_max_backlog = 32768
net.core.optmem_max = 262144
net.core.somaxconn = 65536
net.core.rmem_max = 33554432
net.core.rmem_default = 1048576
net.core.wmem_max = 33554432
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 16384 1048576 33554432
net.ipv4.tcp_wmem = 16384 1048576 33554432
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fin_timeout = 25
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 7
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_max_orphans = 819200
net.ipv4.tcp_max_syn_backlog = 20480
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_mem = 65536 1048576 33554432
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 32768
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = -2
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_ecn_fallback = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.udp_mem = 65536 1048576 33554432
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
net.unix.max_dgram_qlen = 256
vm.min_free_kbytes = 65536
vm.swappiness = 10
vm.vfs_cache_pressure = 250
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.neigh.default.gc_thresh1 = 512
net.ipv4.neigh.default.gc_thresh2 = 2048
net.ipv4.neigh.default.gc_thresh3 = 16384
net.ipv4.neigh.default.gc_stale_time = 60
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.lo.arp_announce = 2
net.ipv4.conf.all.arp_announce = 2
kernel.panic = 1
vm.dirty_ratio = 20
EOF
    sudo sysctl -p
}
limits_optimizations() {
    sed -i '/ulimit -c/d' $PROF_PATH; sed -i '/ulimit -d/d' $PROF_PATH; sed -i '/ulimit -f/d' $PROF_PATH; sed -i '/ulimit -i/d' $PROF_PATH; sed -i '/ulimit -l/d' $PROF_PATH; sed -i '/ulimit -m/d' $PROF_PATH; sed -i '/ulimit -n/d' $PROF_PATH; sed -i '/ulimit -q/d' $PROF_PATH; sed -i '/ulimit -s/d' $PROF_PATH; sed -i '/ulimit -t/d' $PROF_PATH; sed -i '/ulimit -u/d' $PROF_PATH; sed -i '/ulimit -v/d' $PROF_PATH; sed -i '/ulimit -x/d' $PROF_PATH
    echo "ulimit -c unlimited" | tee -a $PROF_PATH; echo "ulimit -d unlimited" | tee -a $PROF_PATH; echo "ulimit -f unlimited" | tee -a $PROF_PATH; echo "ulimit -i unlimited" | tee -a $PROF_PATH; echo "ulimit -l unlimited" | tee -a $PROF_PATH; echo "ulimit -m unlimited" | tee -a $PROF_PATH; echo "ulimit -n 1048576" | tee -a $PROF_PATH; echo "ulimit -q unlimited" | tee -a $PROF_PATH; echo "ulimit -s -H 65536" | tee -a $PROF_PATH; echo "ulimit -s 32768" | tee -a $PROF_PATH; echo "ulimit -t unlimited" | tee -a $PROF_PATH; echo "ulimit -u unlimited" | tee -a $PROF_PATH; echo "ulimit -v unlimited" | tee -a $PROF_PATH; echo "ulimit -x unlimited" | tee -a $PROF_PATH
}

hawshemi_script(){
clear
colorize magenta "Special thanks to Hawshemi..." bold
sleep 2
sysctl_optimizations
limits_optimizations
ask_reboot
}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\e[36m'
MAGENTA="\e[95m"
NC='\033[0m'

display_menu() {
    clear
    display_logo
    display_server_info
    display_rathole_core_status
    echo
    colorize green " 1. Configure a Hybrid LB Tunnel (HAProxy+Rathole)" bold
    colorize red " 2. Destroy all Tunnels" bold
    colorize cyan " 3. Check tunnels status" bold
 	echo -e " 4. Optimize network & system limits"
 	echo -e " 5. Remove rathole core"
    echo -e " 0. Exit"
    echo
    echo "-------------------------------"
}

read_option() {
    read -p "Enter your choice [0-5]: " choice
    case $choice in
        1) configure_tunnel ;;
        2) tunnel_management ;;
        3) check_tunnel_status ;;
        4) hawshemi_script ;;
        5) remove_core ;;
        0) exit 0 ;;
        *) echo -e "${RED} Invalid option!${NC}" && sleep 1 ;;
    esac
}

while true
do
    display_menu
    read_option
done
