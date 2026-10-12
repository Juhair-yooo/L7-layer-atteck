# stresssuite

Multi-vector load & stress testing suite — validates defensive controls
(rate limits, header/body timeouts, SYN cookies, connection limits,
firewall behavior) on infrastructure **you own or are contractually
authorized to test**.

> **Authorized use only.** Running this against systems without the owner's
> written permission is illegal (CFAA 18 U.S.C. §1030, Computer Misuse Act
> 1990 s.3, EU Directive 2013/40). The tool enforces a `--confirm-authorized`
> gate and warns when a target resolves to a public IP.

## Install (Kali / Debian / any Linux, zero dependencies)

```bash
git clone https://github.com/YOUR-USERNAME/stresssuite.git
cd stresssuite
python3 stresssuite.py --help
