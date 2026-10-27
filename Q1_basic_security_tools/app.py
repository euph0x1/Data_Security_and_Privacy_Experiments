"""Q1 – Basic Security Tools: Security Tool · TryHackMe · MyIPAddress · HashCalc · Basic Cryptography."""
import base64, hashlib, ipaddress, math, random, re, socket, struct
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Q1 · Basic Security Tools", page_icon="🔧", layout="wide")
st.title("🔧 Q1 · Basic Security Tools")
st.caption("Demonstrations of fundamental tools every security student should know.")
tabs = st.tabs(["🛡️ Basic Security Tool", "🏴 TryHackMe", "🌐 MyIPAddress", "#️⃣ HashCalc", "🔐 Basic Cryptography"])

# ═══════════════════════════════════════════════════════════════
# BASIC SECURITY TOOL – port scanner / network analyser sim
# ═══════════════════════════════════════════════════════════════
with tabs[0]:
    st.subheader("🛡️ Basic Security Tool – Port scanner & network analyser")
    st.markdown("""
A **security tool** is any software that helps identify, monitor or defend against threats.
This demo simulates the core features of beginner-friendly tools like **Angry IP Scanner**, **Advanced IP Scanner** and **Zenmap**:
- **Port scanning** – which TCP ports are open on a host
- **Banner grabbing** – what service is running on each port
- **Network range sweep** – which hosts are alive on a subnet
""")
    st.graphviz_chart('''digraph G { rankdir=LR; node [shape=box,style="rounded,filled",fontname=Helvetica,fillcolor="#e8f0fe"];
      U [label="Security analyst",fillcolor="#fef7e0"];
      subgraph cluster_t { label="Tool functions"; style=dashed;
        PS [label="Port scan\nTCP connect / SYN",fillcolor="#e6f4ea"];
        BG [label="Banner grab\nservice version",fillcolor="#e6f4ea"];
        NS [label="Network sweep\nICMP ping / ARP",fillcolor="#e6f4ea"];
        VL [label="Vulnerability lookup\nCVE by service",fillcolor="#fce8e6"]; }
      T [label="Target host / subnet",fillcolor="#fce8e6"];
      U -> PS; U -> BG; U -> NS; PS -> T; BG -> T; NS -> T; PS -> VL; }''')

    st.markdown("#### 🔌 Port scanner simulation")
    c1, c2 = st.columns(2)
    host = c1.text_input("Host (simulated)", "scanme.nmap.org")
    port_range = c2.selectbox("Port range", ["Common ports (top 20)", "Well-known (1–1023)", "Custom"])
    custom_ports = st.text_input("Custom ports (comma-separated)", "22,80,443,8080") if "Custom" in port_range else ""

    COMMON_OPEN = {21:"FTP – vsftpd 3.0.3",22:"SSH – OpenSSH 8.9p1",25:"SMTP – Postfix",
                   53:"DNS – BIND 9.18",80:"HTTP – Apache/2.4.54",110:"POP3 – Dovecot",
                   443:"HTTPS – nginx/1.24.0",3306:"MySQL – 8.0.32",3389:"RDP – xrdp 0.9",8080:"HTTP-alt – Tomcat 10.1"}
    VULNS = {21:"CVE-2011-0762 (vsftpd backdoor – check version)",22:"No known critical CVE – keep updated",
             25:"Ensure relay is disabled; SPF/DKIM/DMARC configured",80:"No TLS – all traffic in plaintext",
             443:"Check certificate expiry and TLS version (disable TLS 1.0/1.1)",3306:"DB exposed to network – should be localhost only",
             3389:"BlueKeep (CVE-2019-0708) on old Windows – patch immediately",8080:"Non-standard port – may bypass firewall rules"}

    if st.button("▶ Scan (simulated)", type="primary", key="scan"):
        rng = random.Random(hash(host) % 9999)
        if "Common" in port_range:
            ports = [21,22,25,53,80,110,443,3306,3389,8080]
        elif "Well-known" in port_range:
            ports = sorted(random.sample(range(1,1024), 15))
        else:
            ports = [int(p.strip()) for p in custom_ports.split(",") if p.strip().isdigit()]
        open_ports = {p: COMMON_OPEN[p] for p in ports if p in COMMON_OPEN}
        rows = []
        for p in sorted(ports):
            state = "open" if p in open_ports else "closed"
            svc = open_ports.get(p, "unknown")
            rows.append({"Port": p, "State": state, "Service": svc.split("–")[0].strip(), "Version": svc.split("–")[-1].strip() if "–" in svc else "-"})
        df = pd.DataFrame(rows)
        st.dataframe(df.style.apply(lambda r: ["background-color:#b3f0b3" if r["State"]=="open" else "background-color:#ffb3b3" for _ in r], axis=1), hide_index=True)
        st.markdown("**⚠️ Security notes for open ports:**")
        for p in open_ports:
            if p in VULNS: st.markdown(f"- **Port {p}** – {VULNS[p]}")

    st.markdown("---")
    st.markdown("#### 🌐 Network sweep (subnet simulation)")
    subnet = st.text_input("Subnet (CIDR)", "192.168.1.0/28")
    if st.button("▶ Sweep subnet", key="sweep"):
        try:
            net = ipaddress.IPv4Network(subnet, strict=False)
            hosts = list(net.hosts())[:16]
            rng = random.Random(42)
            results = [{"IP": str(h), "Status": "🟢 Up" if rng.random() > 0.35 else "🔴 Down",
                        "Hostname": f"host-{str(h).split('.')[-1]}.local" if rng.random() > 0.5 else "-",
                        "Open ports": ", ".join(str(p) for p in rng.sample([22,80,443,3306],rng.randint(0,3)))} for h in hosts]
            st.dataframe(pd.DataFrame(results), hide_index=True)
            up = sum(1 for r in results if "Up" in r["Status"])
            st.info(f"{up}/{len(results)} hosts responded. Network: {net.network_address}, Broadcast: {net.broadcast_address}, Mask: {net.netmask}")
        except ValueError as e:
            st.error(f"Invalid CIDR: {e}")

# ═══════════════════════════════════════════════════════════════
# TRYHACKME
# ═══════════════════════════════════════════════════════════════
with tabs[1]:
    st.subheader("🏴 TryHackMe – gamified cybersecurity learning")
    st.markdown("""
**TryHackMe** (tryhackme.com) is a beginner-friendly browser-based platform where you learn cybersecurity through guided *rooms* (interactive labs) and *CTF challenges*, all inside a web browser using an OpenVPN connection to isolated lab VMs.
No expensive hardware needed – everything runs in the cloud.
""")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### 🗺️ Learning paths")
        paths = {"🟢 Pre-Security (beginner)":"Networking basics, web fundamentals, Linux foundations",
                 "🔵 SOC Level 1":"Threat intelligence, SIEM, incident response, Phishing analysis",
                 "🔴 Jr Penetration Tester":"Intro to pen-testing, web security, Metasploit, network exploitation",
                 "⚫ Red Teaming":"Advanced adversary simulation, AV evasion, Active Directory attacks",
                 "🟣 CompTIA Pentest+":"Exam-aligned pentesting path",
                 "🟡 Cyber Defence":"Threat hunting, network analysis, digital forensics"}
        for name, desc in paths.items():
            with st.expander(name): st.markdown(desc)
    with c2:
        st.markdown("#### 🏠 Popular rooms")
        rooms = [("Introduction to Cybersecurity","Beginner","Free","What is cybersecurity, careers, ethics"),
                 ("Linux Fundamentals","Beginner","Free","File system, commands, permissions, scripting"),
                 ("Networking Fundamentals","Beginner","Free","OSI model, IP, DNS, routing"),
                 ("OWASP Top 10","Beginner","Free","Web vulnerabilities with hands-on labs"),
                 ("Metasploit","Intermediate","Free","Exploitation framework walkthrough"),
                 ("Blue","Intermediate","Free","Eternal Blue / MS17-010 exploit + defence"),
                 ("Pickle Rick","Beginner","Free","CTF – find 3 hidden flags on Rick's server"),
                 ("Advent of Cyber","Beginner","Free","Annual 24-day beginner challenge (December)"),
                 ("Kenobi","Intermediate","Subscriber","ProFTPd exploit + privilege escalation")]
        st.dataframe(pd.DataFrame(rooms, columns=["Room","Level","Access","Description"]), hide_index=True)

    st.markdown("---")
    st.markdown("#### 🚩 CTF Flag format simulator")
    st.markdown("Most TryHackMe rooms have you find a flag in the format `THM{some_secret_text}` hidden in files, processes or web pages.")
    hint = st.text_input("Hint / encoded flag", "VEhNe0Jhc2U2NF9FbmNvZGluZ19GTEFH}")
    if hint:
        result = None
        # Try Base64
        try:
            decoded = base64.b64decode(hint + "==").decode()
            if "THM{" in decoded: result = ("Base64", decoded)
        except Exception: pass
        # Try ROT13
        rot13 = hint.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                              "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
        if "THM{" in rot13: result = ("ROT13", rot13)
        if result:
            st.success(f"🚩 Flag found via {result[0]}: **{result[1]}**")
        elif "THM{" in hint:
            st.success(f"🚩 This is already a flag: **{hint}**")
        else:
            st.info("Not recognised – try decoding with base64, ROT13, hex, or searching for it in the room's file system.")

    st.markdown("#### 🛠️ Common CTF techniques")
    techniques = [("Find hidden files","ls -la  /  find / -name '*.txt' 2>/dev/null"),
                  ("Read SUID binaries","find / -perm -4000 2>/dev/null  → GTFObins for escalation"),
                  ("Check running services","ps aux | grep root  /  netstat -tulnp"),
                  ("Crack a hash","hash-identifier → john --wordlist=rockyou.txt hash.txt"),
                  ("Decode Base64","echo 'VEhN...' | base64 -d"),
                  ("View web page source","Ctrl+U in browser / curl http://target/"),
                  ("Enumerate SMB","smbclient -L //target  /  enum4linux target")]
    st.dataframe(pd.DataFrame(techniques, columns=["Task","Command / technique"]), hide_index=True)

# ═══════════════════════════════════════════════════════════════
# MYIPADDRESS
# ═══════════════════════════════════════════════════════════════
with tabs[2]:
    st.subheader("🌐 MyIPAddress – understand your IP information")
    st.markdown("**myipaddress.com** (and similar sites) show what information the internet sees about your connection. This tab explains every field and lets you analyse any IP address.")

    st.markdown("#### 🖥️ Your local IP address (this machine)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); local_ip = s.getsockname()[0]; s.close()
    except Exception:
        local_ip = "127.0.0.1"
    st.code(f"Local (private) IP: {local_ip}")
    st.caption("This is your private IP on the LAN. Your *public* IP (what websites see) is assigned by your ISP and is behind your router's NAT.")

    st.markdown("#### 🔍 IP address analyser")
    ip_input = st.text_input("Enter an IPv4 or IPv6 address", "192.168.1.100")
    if ip_input.strip():
        try:
            ip = ipaddress.ip_address(ip_input.strip())
            info = {"Address": str(ip), "Version": f"IPv{ip.version}", "Type": "Private" if ip.is_private else "Public",
                    "Loopback": ip.is_loopback, "Multicast": ip.is_multicast, "Reserved": ip.is_reserved, "Link-local": ip.is_link_local}
            if ip.version == 4:
                packed = struct.pack(">I", int(ip))
                info["Decimal"] = int(ip)
                info["Hex"] = hex(int(ip))
                info["Binary"] = ".".join(f"{b:08b}" for b in packed)
            c1, c2 = st.columns(2)
            for i,(k,v) in enumerate(info.items()):
                (c1 if i%2==0 else c2).metric(k, str(v))
            if ip.version == 4 and ip.is_private:
                for net, cls in [("10.0.0.0/8","Class A private (large enterprise)"),
                                  ("172.16.0.0/12","Class B private (medium networks)"),
                                  ("192.168.0.0/16","Class C private (home/SOHO)")]:
                    if ip in ipaddress.ip_network(net): st.info(f"Range: {cls}")
        except ValueError as e:
            st.error(f"Invalid IP: {e}")

    st.markdown("---")
    st.markdown("#### 📊 IP address concepts")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**IPv4 vs IPv6**")
        st.table({"Feature":["Address size","Example","Total addresses","Header size","NAT needed"],
                  "IPv4":["32 bits","192.168.1.1","~4.3 billion","20 bytes","Yes (shortage)"],
                  "IPv6":["128 bits","2001:db8::1","3.4×10³⁸","40 bytes","No"]})
    with c2:
        st.markdown("**Subnetting quick reference**")
        subnets = [(f"/{m}", str(2**(32-m)), str(2**(32-m)-2), f"{'.'.join(str(255 if i<m//8 else (255<<(8-m%8)&255) if i==m//8 else 0) for i in range(4))}") for m in [8,16,24,25,26,28,30]]
        st.dataframe(pd.DataFrame(subnets, columns=["CIDR","Total IPs","Usable hosts","Subnet mask"]), hide_index=True)

    st.markdown("#### 🔒 What websites see about you")
    st.code("""Your public IP    : [assigned by your ISP]
User-Agent        : Mozilla/5.0 (Windows NT 10.0; Win64; x64)...
Accept-Language   : en-IN,en;q=0.9
Timezone          : Asia/Kolkata (IST, UTC+5:30)
Screen resolution : 1920×1080
ISP               : Reliance Jio / Airtel / BSNL...
Approximate loc.  : City-level (from IP geolocation DB, not GPS)
Do Not Track      : Not set""", language="text")
    st.warning("🔒 **Privacy tip:** Use a VPN to mask your public IP from websites. Use HTTPS so your ISP cannot read page contents.")

# ═══════════════════════════════════════════════════════════════
# HASHCALC
# ═══════════════════════════════════════════════════════════════
with tabs[3]:
    st.subheader("#️⃣ HashCalc – compute and verify hashes")
    st.markdown("""
**HashCalc** (and web equivalents like md5calc.com, hashgenerator.de) compute cryptographic hash digests of text or files.
A hash is a fixed-length *fingerprint*: the same input always gives the same output, and any change in input gives a completely different output.

**Uses:** verifying file downloads, storing passwords (with a slow hash), digital signatures, data-integrity checks.
""")
    mode = st.radio("Input type", ["Text", "File upload"], horizontal=True)
    algos_selected = st.multiselect("Algorithms", ["md5","sha1","sha224","sha256","sha384","sha512","sha3_256","sha3_512","blake2b","blake2s"],
                                    default=["md5","sha1","sha256","sha512"])
    text_in = ""
    file_bytes = None
    if mode == "Text":
        text_in = st.text_area("Input text", "Hello, World!", height=100)
        encode = st.selectbox("Encoding", ["UTF-8","ASCII","Latin-1"])
        data = text_in.encode(encode, errors="replace") if text_in else b""
    else:
        uf = st.file_uploader("Upload any file")
        data = uf.getvalue() if uf else b""
        if uf: st.caption(f"{uf.name}  –  {len(data):,} bytes")

    if data and algos_selected:
        results = []
        for a in algos_selected:
            h = hashlib.new(a, data).hexdigest()
            results.append({"Algorithm": a.upper(), "Bits": len(h)*4, "Digest": h})
        st.dataframe(pd.DataFrame(results), hide_index=True)
        st.markdown("**✅ Verify integrity** – paste an expected digest to check")
        expected = st.text_input("Expected hash", key="expected_hash").strip().lower()
        if expected:
            match = [r for r in results if r["Digest"] == expected]
            (st.success if match else st.error)(f"{'✅ MATCH with '+match[0]['Algorithm'] if match else '❌ No match – data may be corrupted or tampered'}")

    st.markdown("---")
    st.markdown("#### 🌊 Avalanche effect visualiser")
    col1, col2 = st.columns(2)
    msg1 = col1.text_input("Message 1", "The quick brown fox")
    msg2 = col2.text_input("Message 2", "The quick brown Fox")  # capital F
    if msg1 and msg2:
        h1 = hashlib.sha256(msg1.encode()).hexdigest()
        h2 = hashlib.sha256(msg2.encode()).hexdigest()
        col1.code(h1); col2.code(h2)
        diff = sum(bin(int(a,16)^int(b,16)).count("1") for a,b in zip(h1,h2))
        st.metric("Bits that differ (SHA-256, 256 total)", diff, f"{diff/256:.0%}")

    st.markdown("#### 🔑 Password hashing – why hashlib alone is wrong")
    pw_demo = st.text_input("Demo password", "hunter2", type="password")
    if pw_demo:
        st.table({"Method":["MD5 (broken)","SHA-256 (fast – bad for passwords)","bcrypt (correct)","Argon2id (best)"],
                  "Hash / note":[hashlib.md5(pw_demo.encode()).hexdigest(),hashlib.sha256(pw_demo.encode()).hexdigest(),
                                 "$2b$12$... (use bcrypt library – slow by design)","$argon2id$v=19$... (use argon2-cffi)"]})
        st.error("MD5 / SHA-256 are **too fast** – a GPU can try 10 billion hashes/second. Use bcrypt, scrypt or Argon2 for passwords.")

# ═══════════════════════════════════════════════════════════════
# BASIC CRYPTOGRAPHY
# ═══════════════════════════════════════════════════════════════
with tabs[4]:
    st.subheader("🔐 Basic Cryptography")
    st.markdown("Classical and modern ciphers — encrypt, decrypt and break them interactively.")

    cipher = st.radio("Cipher", ["Caesar","ROT13","Vigenère","Base64","XOR","One-Time Pad (OTP)"], horizontal=True)
    st.markdown("---")

    if cipher == "Caesar":
        st.markdown("**Caesar cipher** – shift every letter by a fixed number.")
        c1, c2 = st.columns([3,1])
        text = c1.text_input("Text", "Hello World"); shift = c2.slider("Shift", 0, 25, 13)
        enc = "".join(chr((ord(c)-65+shift)%26+65) if c.isupper() else chr((ord(c)-97+shift)%26+97) if c.islower() else c for c in text)
        dec = "".join(chr((ord(c)-65-shift)%26+65) if c.isupper() else chr((ord(c)-97-shift)%26+97) if c.islower() else c for c in text)
        st.code(f"Original : {text}\nEncrypted: {enc}\nDecrypted: {dec}")
        st.markdown("**Brute-force (try all shifts):**")
        rows = [{"Shift":s,"Decrypted":"".join(chr((ord(c)-65-s)%26+65) if c.isupper() else chr((ord(c)-97-s)%26+97) if c.islower() else c for c in text)} for s in range(26)]
        st.dataframe(pd.DataFrame(rows), hide_index=True, height=200)
        st.caption("Caesar cipher has only 25 possible keys – trivial to brute-force.")

    elif cipher == "ROT13":
        st.markdown("**ROT13** – a special case of Caesar with shift 13. Applying it twice returns the original.")
        text = st.text_input("Text", "TryHackMe is fun!")
        rot = text.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                           "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
        back = rot.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                           "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
        st.code(f"Original : {text}\nROT13    : {rot}\nROT13×2  : {back}  (same as original ✓)")
        st.caption("ROT13 is not encryption – it provides zero security. Used to hide spoilers, not secrets.")

    elif cipher == "Vigenère":
        st.markdown("**Vigenère cipher** – uses a repeating keyword to vary the shift per character.")
        c1, c2 = st.columns([2,1])
        text = c1.text_input("Text", "ATTACKATDAWN"); key = c2.text_input("Key", "LEMON").upper()
        if text and key:
            key = re.sub(r"[^A-Z]", "", key)
            if key:
                enc = "".join(chr((ord(c)-65+(ord(key[i%len(key)])-65))%26+65) if c.isupper()
                              else chr((ord(c)-97+(ord(key[i%len(key)])-65))%26+97) if c.islower()
                              else c for i,c in enumerate(text))
                dec = "".join(chr((ord(c)-65-(ord(key[i%len(key)])-65))%26+65) if c.isupper()
                              else chr((ord(c)-97-(ord(key[i%len(key)])-65))%26+97) if c.islower()
                              else c for i,c in enumerate(enc))
                st.code(f"Plaintext : {text}\nKey       : {(key*(len(text)//len(key)+1))[:len(text)]}\nEncrypted : {enc}\nDecrypted : {dec}")
                st.caption("Vigenère resisted cryptanalysis for 300 years until Kasiski (1863) and Friedman's Index of Coincidence (1920) broke it.")

    elif cipher == "Base64":
        st.markdown("**Base64** – encodes binary data as printable ASCII. NOT encryption – anyone can decode it.")
        c1, c2 = st.columns(2)
        enc_in = c1.text_area("Encode (text)", "Secret message!"); dec_in = c2.text_area("Decode (Base64)", "U2VjcmV0IG1lc3NhZ2Uh")
        c1.code(base64.b64encode(enc_in.encode()).decode())
        try: c2.code(base64.b64decode(dec_in + "==").decode())
        except Exception as e: c2.error(str(e))
        st.caption("Variants: Base64 URL-safe (+ → - , / → _), Base32 (uppercase + 2-7), Base16 (hex).")

    elif cipher == "XOR":
        st.markdown("**XOR cipher** – the basis of stream ciphers. Key is reused byte-by-byte (unsafe if key is short).")
        c1, c2 = st.columns(2)
        text = c1.text_input("Plaintext", "Hello!"); key  = c2.text_input("Key (repeated)", "K")
        if text and key:
            key_bytes = (key * (len(text)//len(key)+1))[:len(text)].encode()
            ct = bytes(a^b for a,b in zip(text.encode(), key_bytes))
            pt = bytes(a^b for a,b in zip(ct, key_bytes))
            c1.code(f"Ciphertext (hex): {ct.hex()}")
            c2.code(f"Decrypted: {pt.decode(errors='replace')}")
            st.code("# Python\nct = bytes(a^b for a,b in zip(plaintext.encode(), key.encode()))", language="python")
            st.caption("XOR with a truly random key the same length as the message = One-Time Pad (unbreakable). Reusing the key = breakable (many-time-pad attack).")

    else:  # OTP
        st.markdown("**One-Time Pad** – the only *provably unbreakable* cipher. Key is truly random and as long as the message.")
        text = st.text_input("Message", "HELLO")
        rng = random.SystemRandom()
        key = bytes(rng.randrange(256) for _ in range(len(text)))
        ct  = bytes(a^b for a,b in zip(text.encode("ascii","replace"), key))
        pt  = bytes(a^b for a,b in zip(ct, key))
        c1, c2, c3 = st.columns(3)
        c1.markdown("**Key (random)**"); c1.code(key.hex())
        c2.markdown("**Ciphertext**"); c2.code(ct.hex())
        c3.markdown("**Decrypted**"); c3.code(pt.decode(errors="replace"))
        st.success("The ciphertext is **information-theoretically secure**: without the key, every possible plaintext is equally likely. Shannon proved this in 1949.")
        st.warning("**Practical problem:** the key must be truly random, as long as all messages ever sent, never reused and securely shared. This makes OTP impractical for most uses.")

    st.markdown("---")
    st.markdown("#### 🏛️ History of cryptography")
    timeline = [("~1900 BC","Egypt","Atbash / simple substitution in inscriptions"),
                ("100 BC","Rome","Caesar cipher – shift 3"),
                ("800 AD","Baghdad","Al-Kindi invents frequency analysis – first cryptanalysis"),
                ("1553","Italy","Vigenère cipher published"),
                ("1917","USA","Vernam patents the One-Time Pad"),
                ("1918","Germany","Enigma machine invented"),
                ("1976","USA","Diffie-Hellman public key exchange published"),
                ("1977","USA","RSA algorithm published"),
                ("2001","USA","AES (Rijndael) adopted as NIST standard"),
                ("2024","USA","NIST finalises post-quantum standards (ML-KEM, ML-DSA, SLH-DSA)")]
    st.dataframe(pd.DataFrame(timeline, columns=["Year","Origin","Event"]), hide_index=True)
