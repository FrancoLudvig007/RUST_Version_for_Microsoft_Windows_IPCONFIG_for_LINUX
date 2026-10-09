use std::collections::{HashMap, HashSet};
use std::fs;
use std::process::Command;
use std::sync::OnceLock;
use regex::Regex;

// ─────────────────────────────────────────────
// Estrutura de Dados
// ─────────────────────────────────────────────

#[derive(Debug, Default)]
struct InterfaceInfo {
    name: String,
    state: String,
    flags: String,
    mtu: u32,
    mac: Option<String>,
    ipv4: Option<String>,
    cidr: Option<u32>,
    ipv6_global: Vec<String>,
    ipv6_link_local: Option<String>,
    gateway: Option<String>,
    dns_servers: Vec<String>,
    dhcp_enabled: bool,
}

impl InterfaceInfo {
    fn is_disconnected(&self) -> bool {
        self.state == "DOWN" || self.flags.contains("NO-CARRIER")
    }

    fn adapter_label(&self) -> String {
        if self.name.starts_with("wl") {
            format!("Adaptador Rede Sem Fio {}", self.name)
        } else if self.name.starts_with("en") || self.name.starts_with("eth") {
            format!("Adaptador Ethernet {}", self.name)
        } else if self.name.starts_with("tun") || self.name.starts_with("tap") {
            format!("Adaptador de Túnel {}", self.name)
        } else {
            format!("Adaptador de Rede {}", self.name)
        }
    }
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

fn run_cmd(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_default()
}

fn cidr_to_mask(cidr: u32) -> String {
    let mask = if cidr == 0 { 0 } else { (!0u32) << (32 - cidr) };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF
    )
}

fn pad_label(label: &str, width: usize) -> String {
    let padding_len = width.saturating_sub(label.chars().count());
    let dots = ".".repeat(padding_len);
    format!("   {} {} : ", label, dots)
}

// ─────────────────────────────────────────────
// Coleta de Dados
// ─────────────────────────────────────────────

fn get_gateways() -> HashMap<String, String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"default via ([\d\.]+) dev (\S+)").unwrap());

    let mut gateways = HashMap::new();
    let output = run_cmd("ip", &["route"]);

    for line in output.lines() {
        if let Some(caps) = re.captures(line) {
            let ip = caps.get(1).unwrap().as_str().to_string();
            let dev = caps.get(2).unwrap().as_str().to_string();
            gateways.insert(dev, ip);
        }
    }
    gateways
}

fn get_dns_per_interface() -> HashMap<String, Vec<String>> {
    static RE_LINK: OnceLock<Regex> = OnceLock::new();
    let re_link = RE_LINK.get_or_init(|| Regex::new(r"Link \d+ \((\S+)\)").unwrap());
    
    static RE_DNS: OnceLock<Regex> = OnceLock::new();
    let re_dns = RE_DNS.get_or_init(|| Regex::new(r"DNS Servers:\s+(.+)").unwrap());

    let mut result: HashMap<String, Vec<String>> = HashMap::new();
    let output = run_cmd("resolvectl", &["status"]);

    if !output.trim().is_empty() {
        let mut current_iface = String::new();
        for line in output.lines() {
            let line = line.trim();
            if let Some(caps) = re_link.captures(line) {
                current_iface = caps.get(1).unwrap().as_str().to_string();
                result.entry(current_iface.clone()).or_default();
            } else if !current_iface.is_empty() {
                if let Some(caps) = re_dns.captures(line) {
                    let servers = caps.get(1).unwrap().as_str().split_whitespace().map(|s| s.to_string());
                    if let Some(list) = result.get_mut(&current_iface) {
                        list.extend(servers);
                    }
                }
            }
        }
        if !result.is_empty() {
            return result;
        }
    }

    // Fallback para /etc/resolv.conf
    static RE_RESOLV: OnceLock<Regex> = OnceLock::new();
    let re_resolv = RE_RESOLV.get_or_init(|| Regex::new(r"nameserver\s+([\d\.a-fA-F:]+)").unwrap());
    
    let mut fallback = Vec::new();
    if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            if let Some(caps) = re_resolv.captures(line) {
                fallback.push(caps.get(1).unwrap().as_str().to_string());
            }
        }
    }
    
    result.insert("__global__".to_string(), fallback);
    result
}

fn get_dhcp_interfaces() -> HashSet<String> {
    static RE_DEV: OnceLock<Regex> = OnceLock::new();
    let re_dev = RE_DEV.get_or_init(|| Regex::new(r"GENERAL\.DEVICE:(.+)").unwrap());
    
    static RE_METHOD: OnceLock<Regex> = OnceLock::new();
    let re_method = RE_METHOD.get_or_init(|| Regex::new(r"IP4\.METHOD:auto").unwrap());

    let mut dhcp_ifaces = HashSet::new();
    let output = run_cmd("nmcli", &["-t", "-f", "DEVICE,IP4.METHOD", "device", "show"]);
    
    let mut current_dev = String::new();
    for line in output.lines() {
        if let Some(caps) = re_dev.captures(line) {
            current_dev = caps.get(1).unwrap().as_str().trim().to_string();
        } else if !current_dev.is_empty() && re_method.is_match(line) {
            dhcp_ifaces.insert(current_dev.clone());
        }
    }
    dhcp_ifaces
}

fn split_interface_blocks(ip_output: &str) -> Vec<String> {
    static RE_START: OnceLock<Regex> = OnceLock::new();
    let re_start = RE_START.get_or_init(|| Regex::new(r"^\d+:").unwrap());

    let mut blocks = Vec::new();
    let mut current = Vec::new();

    for line in ip_output.lines() {
        if re_start.is_match(line) {
            if !current.is_empty() {
                blocks.push(current.join("\n"));
            }
            current = vec![line];
        } else if !current.is_empty() {
            current.push(line);
        }
    }
    if !current.is_empty() {
        blocks.push(current.join("\n"));
    }
    blocks
}

fn parse_block(block: &str) -> Option<InterfaceInfo> {
    static RE_HEADER: OnceLock<Regex> = OnceLock::new();
    let re_header = RE_HEADER.get_or_init(|| Regex::new(r"^\d+:\s+(\S+?)(?:@\S+)?:\s+<([^>]+)>.*mtu\s+(\d+).*state\s+(\S+)").unwrap());

    static RE_MAC: OnceLock<Regex> = OnceLock::new();
    let re_mac = RE_MAC.get_or_init(|| Regex::new(r"link/(?:ether|wifi)\s+([\da-f:]{17})").unwrap());

    static RE_IPV4: OnceLock<Regex> = OnceLock::new();
    let re_ipv4 = RE_IPV4.get_or_init(|| Regex::new(r"inet\s+([\d\.]+)/(\d+)").unwrap());

    static RE_IPV6: OnceLock<Regex> = OnceLock::new();
    let re_ipv6 = RE_IPV6.get_or_init(|| Regex::new(r"inet6\s+([a-fA-F\d:]+)/(\d+)\s+scope\s+(\S+)").unwrap());

    let mut lines = block.lines();
    let first_line = lines.next()?;

    let caps = re_header.captures(first_line)?;
    let name = caps.get(1)?.as_str().to_string();
    
    if name == "lo" {
        return None;
    }

    let flags = caps.get(2)?.as_str().to_string();
    let mtu = caps.get(3)?.as_str().parse().unwrap_or(0);
    let state = caps.get(4)?.as_str().to_string();

    let mut info = InterfaceInfo {
        name: name.clone(),
        state,
        flags,
        mtu,
        ..Default::default()
    };

    for line in lines {
        let line = line.trim();

        if let Some(caps) = re_mac.captures(line) {
            info.mac = Some(caps.get(1)?.as_str().to_uppercase());
        } else if let Some(caps) = re_ipv4.captures(line) {
            info.ipv4 = Some(caps.get(1)?.as_str().to_string());
            info.cidr = caps.get(2)?.as_str().parse().ok();
        } else if let Some(caps) = re_ipv6.captures(line) {
            let addr = caps.get(1)?.as_str();
            let prefix = caps.get(2)?.as_str();
            let scope = caps.get(3)?.as_str();

            if scope == "link" {
                info.ipv6_link_local = Some(format!("{}%{}", addr, name));
            } else if scope == "global" {
                info.ipv6_global.push(format!("{}/{}", addr, prefix));
            }
        }
    }

    Some(info)
}

// ─────────────────────────────────────────────
// Impressão
// ─────────────────────────────────────────────

fn print_header() {
    let hostname = run_cmd("hostname", &[]).trim().to_string();
    let fqdn = run_cmd("hostname", &["-f"]).trim().to_string();
    let mut suffix = String::new();
    
    if !fqdn.is_empty() && fqdn != hostname {
        suffix = fqdn.replacen(&hostname, "", 1).trim_start_matches('.').to_string();
    }

    println!("\nConfiguração de IP do Windows\n");
    println!("{}{}", pad_label("Nome do Host", 38), hostname);
    if !suffix.is_empty() {
        println!("{}{}", pad_label("Sufixo DNS Primário", 38), suffix);
    }
    println!("{}Híbrido", pad_label("Tipo de Nó", 38));
    println!("{}Não", pad_label("Roteamento IP Habilitado", 38));
    println!("{}Não\n", pad_label("Proxy WINS Habilitado", 38));
}

fn print_interface(info: &InterfaceInfo) {
    println!("{}:\n", info.adapter_label());

    if info.is_disconnected() {
        println!("{}Mídia desconectada\n", pad_label("Estado do Meio", 38));
        return;
    }

    if let Some(mac) = &info.mac {
        println!("{}{}", pad_label("Endereço Físico", 38), mac.replace(':', "-"));
    }

    println!("{}{}", pad_label("DHCP Habilitado", 38), if info.dhcp_enabled { "Sim" } else { "Não" });
    println!("{}Sim", pad_label("Configuração Automática Habilitada", 38));

    if let Some(ipv6_ll) = &info.ipv6_link_local {
        println!("{}{}", pad_label("Endereço IPv6 de Link Local", 38), ipv6_ll);
    }

    for ipv6 in &info.ipv6_global {
        println!("{}{}", pad_label("Endereço IPv6", 38), ipv6);
    }

    if let Some(ipv4) = &info.ipv4 {
        println!("{}{}", pad_label("Endereço IPv4", 38), ipv4);
        if let Some(cidr) = info.cidr {
            println!("{}{}", pad_label("Máscara de Sub-rede", 38), cidr_to_mask(cidr));
        }
    }

    println!("{}{}", pad_label("Gateway Padrão", 38), info.gateway.as_deref().unwrap_or(""));

    if !info.dns_servers.is_empty() {
        println!("{}{}", pad_label("Servidores DNS", 38), info.dns_servers[0]);
        for server in info.dns_servers.iter().skip(1) {
            println!("{:>42}  {}", "", server);
        }
    }

    println!("{}{}\n", pad_label("MTU", 38), info.mtu);
}

// ─────────────────────────────────────────────
// Ponto de entrada
// ─────────────────────────────────────────────

fn main() {
    let ip_output = run_cmd("ip", &["a"]);
    if ip_output.trim().is_empty() {
        println!("Erro: não foi possível obter informações de rede.");
        return;
    }

    let gateways = get_gateways();
    let mut dns_map = get_dns_per_interface();
    let dhcp_ifaces = get_dhcp_interfaces();

    let global_dns = dns_map.remove("__global__").unwrap_or_default();

    print_header();

    for block in split_interface_blocks(&ip_output) {
        if let Some(mut info) = parse_block(&block) {
            info.gateway = gateways.get(&info.name).cloned();
            
            info.dns_servers = dns_map.get(&info.name).cloned().unwrap_or_else(|| global_dns.clone());
            info.dhcp_enabled = dhcp_ifaces.contains(&info.name);

            print_interface(&info);
        }
    }
}