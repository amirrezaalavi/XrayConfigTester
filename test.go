package main

import (
    "bufio"
    "bytes"
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "os"
    "os/exec"
    "strings"
    "sync"
    "time"
)

const (
    TestTimeout = 100 * time.Second
    
//builddir    TestTimeout = 100000000000000
    BatchSize   = 5
    InputFile   = "config.txt"
    OutputFile  = "valid.txt"
)

type ProxyConfig struct {
    Raw     string
    Type    string // vmess / vless / trojan
    Parsed  map[string]interface{}
}

// ======================= Config Parsing =======================

func parseProxy(raw string) (*ProxyConfig, error) {
    raw = strings.TrimSpace(raw)
    if raw == "" {
        return nil, fmt.Errorf("empty line")
    }
    switch {
    case strings.HasPrefix(raw, "vmess://"):
        parsed, err := parseVMess(raw)
        return &ProxyConfig{Raw: raw, Type: "vmess", Parsed: parsed}, err
    case strings.HasPrefix(raw, "vless://"):
        parsed, err := parseVLESS(raw)
        return &ProxyConfig{Raw: raw, Type: "vless", Parsed: parsed}, err
    case strings.HasPrefix(raw, "trojan://"):
        parsed, err := parseTrojan(raw)
        return &ProxyConfig{Raw: raw, Type: "trojan", Parsed: parsed}, err
    default:
        return nil, fmt.Errorf("unsupported protocol")
    }
}

func parseVMess(raw string) (map[string]interface{}, error) {
    data := raw[8:] // remove 'vmess://'
    decoded, err := base64.StdEncoding.DecodeString(data)
    if err != nil {
        return nil, err
    }
    var m map[string]interface{}
    err = json.Unmarshal(decoded, &m)
    if err != nil {
        return nil, err
    }
    return m, nil
}

func parseVLESS(raw string) (map[string]interface{}, error) {
    u := raw[8:] // remove 'vless://'
    atIndex := strings.Index(u, "@")
    if atIndex == -1 {
        return nil, fmt.Errorf("invalid format")
    }
    queryStart := strings.Index(u, "?")
    if queryStart == -1 {
        queryStart = len(u)
    }
    userPass := u[:atIndex]
    hostPort := u[atIndex+1 : queryStart]

    var uuid, password string
    if strings.Contains(userPass, ":") {
        parts := strings.SplitN(userPass, ":", 2)
        uuid = parts[0]
        password = parts[1]
    } else {
        uuid = userPass
        password = ""
    }

    host, port, err := net.SplitHostPort(hostPort)
    if err != nil {
        host = hostPort
        port = "443"
    }

    params := make(map[string]string)
    if queryStart < len(u) {
        q := u[queryStart+1:]
        for _, pair := range strings.Split(q, "&") {
            kv := strings.SplitN(pair, "=", 2)
            if len(kv) == 2 {
                params[kv[0]] = kv[1]
            }
        }
    }

    return map[string]interface{}{
        "uuid":      uuid,
        "password":  password,
        "host":      host,
        "port":      port,
        "security":  params["security"],
        "type":      params["type"],
        "path":      params["path"],
        "hostHeader": params["host"],
        "flow":      params["flow"],
    }, nil
}

func parseTrojan(raw string) (map[string]interface{}, error) {
    u := raw[9:] // remove 'trojan://'
    atIndex := strings.Index(u, "@")
    if atIndex == -1 {
        return nil, fmt.Errorf("invalid format")
    }
    userPass := u[:atIndex]
    hostPort := u[atIndex+1:]

    password := userPass
    host, port, err := net.SplitHostPort(hostPort)
    if err != nil {
        host = hostPort
        port = "443"
    }

    return map[string]interface{}{
        "password": password,
        "host":     host,
        "port":     port,
    }, nil
}

// ======================= Build Xray JSON =======================

func buildXrayJSON(cfg *ProxyConfig) ([]byte, error) {
    var outbound map[string]interface{}

    switch cfg.Type {
    case "vmess":
        vmess := cfg.Parsed
        outbound = map[string]interface{}{
            "protocol": "vmess",
            "settings": map[string]interface{}{
                "vnext": []map[string]interface{}{
                    {
                        "address": vmess["add"],
                        "port":    vmess["port"],
                        "users": []map[string]interface{}{
                            {
                                "id":       vmess["id"],
                                "alterId":  vmess["aid"],
                                "security": "auto",
                            },
                        },
                    },
                },
            },
            "streamSettings": func() map[string]interface{} {
                netType := vmess["net"].(string)
                settings := map[string]interface{}{
                    "network": netType,
                }
                if tls := vmess["tls"]; tls == "tls" {
                    settings["security"] = "tls"
                }
                switch netType {
                case "tcp":
                    settings["tcpSettings"] = map[string]interface{}{
                        "header": map[string]string{"type": "none"},
                    }
                case "ws":
                    host, ok := vmess["host"].(string)
                    if !ok {
                        host = "www.cloudflare.com" // default or fail early

                        settings["wsSettings"] = map[string]interface{}{
                        "path": vmess["path"],
                        
                    }
                }
                    if ok{
                    settings["wsSettings"] = map[string]interface{}{
                        "path": vmess["path"],
                        "headers": map[string]string{
                            "Host": host,
                        },
                    }}
                }
                return settings
            }(),
        }
    case "vless":
        vless := cfg.Parsed
        outbound = map[string]interface{}{
            "protocol": "vless",
            "settings": map[string]interface{}{
                "vnext": []map[string]interface{}{
                    {
                        "address": vless["host"],
                        "port":    vless["port"],
                        "users": []map[string]interface{}{
                            {
                                "id":         vless["uuid"],
                                "encryption": "none",
                                "flow":       vless["flow"],
                            },
                        },
                    },
                },
            },
            "streamSettings": func() map[string]interface{} {
                netType := vless["type"].(string)
                settings := map[string]interface{}{
                    "network": netType,
                }
                if sec := vless["security"]; sec == "tls" {
                    settings["security"] = "tls"
                }
                switch netType {
                case "tcp":
                    settings["tcpSettings"] = map[string]interface{}{
                        "header": map[string]string{"type": "none"},
                    }
                case "ws":
                    settings["wsSettings"] = map[string]interface{}{
                        "path": vless["path"],
                        "headers": map[string]string{
                            "Host": vless["hostHeader"].(string),
                        },
                    }
                }
                return settings
            }(),
        }
    case "trojan":
        trojan := cfg.Parsed
        outbound = map[string]interface{}{
            "protocol": "trojan",
            "settings": map[string]interface{}{
                "servers": []map[string]interface{}{
                    {
                        "address": trojan["host"],
                        "port":    trojan["port"],
                        "password": trojan["password"],
                    },
                },
            },
            "streamSettings": map[string]interface{}{
                "network":  "tcp",
                "security": "tls",
            },
        }
    default:
        return nil, fmt.Errorf("unknown type")
    }

    config := map[string]interface{}{
        "inbounds": []map[string]interface{}{
            {
                "port":     1080,
                "protocol": "socks",
                "sniffing": map[string]interface{}{
                    "enabled": true,
                    "destOverride": []string{"http", "tls"},
                },
                "settings": map[string]bool{"udp": true},
            },
        },
        "outbounds": []interface{}{outbound},
    }

    return json.MarshalIndent(config, "", "  ")
}

// ======================= Test Function =======================

func testConfigWithXray(proxyCfg *ProxyConfig) bool {
    cfgBytes, err := buildXrayJSON(proxyCfg)
    if err != nil {
        //log.Printf("[ERROR] %s\n", err)
        return false
    }

    tmpfile, err := os.CreateTemp("", "xray-config-*.json")
    if err != nil {
        log.Printf("[ERROR] Temp file: %v", err)
        return false
    }
    defer os.Remove(tmpfile.Name())
    defer tmpfile.Close()

    if _, err := tmpfile.Write(cfgBytes); err != nil {
        log.Printf("[ERROR] Writing config: %v", err)
        return false
    }

    ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
    defer cancel()

    cmd := exec.CommandContext(ctx, "xray", "-test", "-config", tmpfile.Name())
    var stderr bytes.Buffer
    cmd.Stderr = &stderr

    start := time.Now()
    err = cmd.Run()
    //log.Printf("%s", err)
    elapsed := time.Since(start)

    if ctx.Err() == context.DeadlineExceeded {
        //log.Printf("[TIMEOUT] %s (%v)", proxyCfg.Raw, elapsed)
        return false
    }

    if err != nil {
        log.Printf("[FAILED] %s (%v): %s", proxyCfg.Raw, elapsed, stderr.String())
        return false
    }

    fmt.Printf("%s\n", proxyCfg.Raw)
//    log.Printf("[SUCCESS] %s (delay: %v)", proxyCfg.Raw, elapsed)
    return true
}

// ======================= Main Loop =======================

func main() {
    file, err := os.Open(InputFile)
    if err != nil {
        log.Fatalf("Error opening input file: %v", err)
    }
    defer file.Close()

    validFile, err := os.Create(OutputFile)
    if err != nil {
        log.Fatalf("Error creating output file: %v", err)
    }
    defer validFile.Close()

    scanner := bufio.NewScanner(file)
    var wg sync.WaitGroup
    semaphore := make(chan struct{}, BatchSize)

    for scanner.Scan() {
        line := scanner.Text()
        if line == "" {
            continue
        }

        cfg, err := parseProxy(line)
        if err != nil {
            //log.Printf("[SKIP] %q: %v", line, err)
            continue
        }

        semaphore <- struct{}{}
        wg.Add(1)
        go func(cfg *ProxyConfig) {
            defer func() {
                <-semaphore
                wg.Done()
            }()
            if testConfigWithXray(cfg) {
                _, _ = validFile.WriteString(cfg.Raw + "\n")
            }
        }(cfg)
    }

    wg.Wait()

    if err := scanner.Err(); err != nil {
        log.Printf("Reading input: %v", err)
    }
}
