1. Two ways a service stops serving
1.1 Exploit-based takedown — crash the software
The attacker needs a specific vulnerability in that specific target's software/version. The goal is to break the process, not overload it:



Mechanism	Example
Memory corruption	Buffer/heap overflow corrupts control data → segfault kills the worker
Unhandled exception	Malformed request triggers an uncaught error → worker dies; supervisor respawns it, attacker repeats
Logic bugs	Infinite recursion → stack exhaustion; integer overflow in size calculations
Input-triggered resource leaks	Memory leak per malformed request → OOM killer terminates the service
Classic examples: Ping of Death (oversized ICMP crashed older TCP/IP stacks), teardrop (overlapping IP fragment offsets crashed reassembly).

Key defensive insight: exploit-based takedowns are fixed by patching, not by scaling. A crash bug affects a 1-core VPS and a 1000-node cluster identically.

1.2 Capacity exhaustion — DoS / DDoS
The software behaves correctly; the attack consumes a finite resource faster than the service replenishes it. Every server has finite: bandwidth, connection slots, worker capacity, memory, downstream dependencies (DB connections, APIs).




Attacker's equation of failure:

  Attack rate × cost per unit of attack  >  Service capacity × cost per unit of defense
The entire field of DDoS defense is about flipping that inequality: make each attacker request cost more (filtering, friction) and/or make defensive capacity cheaper and larger (CDNs, anycast, caching).

2. Volumetric attacks
Goal: saturate the network pipe — the server is fine; the bits never reach it.

2.1 Reflection & amplification
Exploits two properties of UDP protocols: spoofable source address and asymmetric response size.




  Attacker                        Reflector (3rd party)              Victim
     |-- 60 B request ----------------->|                               |
     |   (spoofed src = victim IP)      |-- 4000 B reply -------------->|
     |  pays for 60 B of upload         |         Victim pays for 4000 B
Approximate amplification factors (US-CERT/Cloudflare measurements):



Protocol	Trigger	Amplification
memcached (exposed UDP)	get of a large key	~10,000–51,000×
QOTD	any request	~1,400×
NTP (monlist, pre-2013)	monlist command	~556×
Chargen	any request	~359×
DNS (open resolver)	ANY / large RRset	~28–54×
SSDP	M-SEARCH	~31×
SNMPv2	bulk get	~6×
Key points:

The victim never sees the request — only the responses from legitimate third parties, so "block the attacker's IP" is impossible at the victim's edge.
The real fix lives on the third-party servers: disable NTP monlist, restrict DNS recursion, firewall memcached, disable SSDP.
BCP 38 (ingress/egress source-address filtering) is the systemic fix — where deployed, spoofing dies and reflection attacks become impossible.
2.2 Botnets
Volume from numbers, not amplification: thousands of compromised IoT cameras, routers, DVRs sending traffic simultaneously.

Mirai (2016): ~600k IoT devices brute-forced via default credentials; produced the ≈1.1 Tbps OVH attack and the Dyn DNS attack (took down Twitter, Netflix, Reddit). The vulnerability was default passwords, not any protocol.
Modern botnets are rented — "booter/stresser" panels sell DDoS-for-hire for a few dollars.
Botnet traffic can look like legitimate traffic (valid TLS, real HTTP), defeating naive filtering.
Bandwidth math: a 1 Gbps pipe receiving 50 Gbps drops ~98% of all packets — legitimate ones included — because upstream saturates first. No server tuning helps; the fix must happen upstream (provider filtering, scrubbing, CDN absorption).

3. Protocol attacks
Goal: exhaust protocol-level state (connection tables, sockets, worker threads) with minimal bandwidth.

3.1 SYN flood
TCP: SYN → SYN-ACK → ACK. The server allocates a backlog slot on SYN and waits. An attacker sends thousands of SYNs (spoofed random sources so SYN-ACKs go nowhere) and never completes — backlog fills, legitimate SYNs drop.

Mitigation — SYN cookies (Daniel J. Bernstein): when the backlog fills, the server encodes connection state inside the sequence number of the SYN-ACK:




ISN = (t << 25) | (MSS << 22) | hash(src IP, src port, dst IP, dst port, t)
No state allocated until the final ACK arrives.
The client must echo ISN+1 — only someone who actually received the SYN-ACK can do that; spoofed sources never see it.
Linux: net.ipv4.tcp_syncookies = 1, engaged automatically when the backlog fills.
Related: ACK floods, RST floods, fragmentation attacks, Smurf (ICMP echo to broadcast address with spoofed source — the 1990s precursor of amplification).

3.2 Slowloris and the slow-HTTP family
Attacks the worker pool, popularized by "RSnake" Hansen in 2009:




  Attacker conn #1:  GET / HTTP/1.1\r\nHost: x\r\n
                     X-a: b\r\n          (wait ~10-15 s)
                     X-b: c\r\n          (wait ~10-15 s)
                     ...never sends the blank line that ends headers...
  Attacker conn #200: (same, parallel)
Each connection sends almost a complete request, then dribbles fake header lines every few seconds to reset the server's timeout. The server never sees a complete request, so it holds a worker per connection. Apache prefork = one process per connection: 200–500 slow connections could pin an entire server using kilobits of bandwidth.



Variant	Trick
Slowloris	Partial headers, never terminated
Slow POST / R.U.D.Y.	Huge declared Content-Length, body dribbled 1 byte at a time
Slow Read	Complete request, then read the response agonizingly slowly
Fix: absolute time bounds on request receipt, independent of client liveness — header/body timeouts (nginx client_header_timeout; Apache mod_reqtimeout), per-IP connection caps, and event-driven servers (nginx, HAProxy, Apache event MPM) where a slow client doesn't pin a worker.

4. Application-layer attacks (L7)
Goal: legitimate-looking requests with disproportionate server-side cost. Hardest to filter — each request may be indistinguishable from a real user's.

4.1 HTTP floods
High-rate GETs/POSTs against expensive pages, or bypassing the page cache with cache-busting query strings (/page?x=<random>). Randomized paths/headers/cookies defeat signatures. Behind a CDN, attackers increasingly target the origin IP directly (via CT logs, historic DNS, misconfigured subdomains) to bypass the edge.

4.2 Expensive-endpoint targeting
Find the worst cost-per-request and hit only that:

Search with wildcard/fuzzy queries
Report/export generation (PDF/CSV)
Login/OTP flows (bcrypt cost + mail/SMS sending)
GraphQL without depth/complexity limits
REST APIs without pagination limits: /items?limit=1000000
4.3 Algorithmic complexity attacks


Attack	Mechanism
ReDoS	Catastrophic backtracking: (a+)+$ against 30 a's + one X takes exponential time
HashDoS	Crafted keys collide in hash tables (Java/PHP; 28C3 2011 demo) turning dictionary insert O(1) → O(n²)
Billion Laughs	Nested XML entity expansion — a few hundred bytes → gigabytes of memory
Zip bombs	42.zip: a few KB → petabytes
4.4 Why L7 defense is different
Requests arrive inside completed TLS sessions — payloads are hidden from network filters, so inspection happens where TLS terminates.
Bot vs. real user is a behavioral problem: rate patterns, TLS/JA3 fingerprints, JS challenges, CAPTCHA.
Defense is tiered friction: cheap checks first (IP reputation, rate), expensive checks (CAPTCHA, proof-of-work) only for suspicious traffic — the attacker pays asymmetrically, not the defender.
5. Detection & monitoring
Network/transport:

Interface bits/packets vs. baseline (NetFlow/sFlow/IPFIX for per-conversation visibility)
Backlog pressure: ss -s, netstat -an | grep SYN_RECV | wc -l
Cookie engagement: nstat -az TcpExtSyncookiesSent (nonzero = active SYN flood)
conntrack fill: nf_conntrack_count vs nf_conntrack_max
Application:

Request rate, latency p95/p99, 5xx ratio, upstream DB latency
Worker pool saturation; cache hit-ratio collapse (attacking cacheable pages shows as hit-ratio drop)
Upstream visibility: volumetric attacks are often more visible to your provider than to your saturated link — automated provider alerts matter.

6. Mitigation playbook


Attack class	First-line mitigation	Deeper/systemic mitigation
Volumetric	Upstream scrubbing / CDN absorption	Anycast; BGP blackholing (RTBH)/FlowSpec at provider
Amplification	(Not fixable at victim alone)	Third parties close resolvers/monlist/memcached; networks deploy BCP 38
SYN flood	SYN cookies; larger backlog	Provider filtering; anycast spreads state
Slowloris	Header/body timeouts; per-IP conn caps	Event-driven servers; reverse proxy in front of legacy app
HTTP/L7 flood	Rate limiting per IP/session	WAF/bot management; JS/CAPTCHA challenge tiering
Expensive endpoints	Per-endpoint budgets, pagination limits	GraphQL complexity caps; caching; circuit breakers
ReDoS/HashDoS	Fix the parser (hash seed randomization is now default)	Fuzz parsers; lint rules banning dangerous regex
The major architectural defenses
Rate limiting & connection limits per IP — token bucket at every tier (LB, web, app, DB). Tune carefully or you rate-limit your own users behind carrier-grade NAT.
SYN cookies — nearly free; on by default in modern kernels.
CDN / reverse proxy absorption — the edge has terabits of capacity and filters before your origin. Also restrict origin ingress to CDN IP ranges only, so attackers can't bypass the edge.
Anycast — the same IP announced from hundreds of data centers; the flood splits geographically (how DNS root servers survive multi-Tbps attacks).
WAF — catches malformed/exploit-pattern requests at L7; insufficient against floods of valid requests.
Scrubbing centers & BGP blackholing — for direct-to-origin volumetric: providers redirect through scrubbing (GRE tunnels) or drop via RTBH (sacrifice the destination, save the network).
Closing open amplifiers — genuinely third-party responsibility; BCP 38 + service hardening is what actually shrank these attack classes over time.
