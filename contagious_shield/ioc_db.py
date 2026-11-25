# Copyright (c) 2026 Aldian Fazrihady
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Verified Threat Intelligence IOCs for Contagious Interview and poisoned freelance/contest campaigns."""

from typing import Dict

KNOWN_MALICIOUS_DOMAINS: Dict[str, str] = {
    "ledgeroom.org": "Contagious Interview front spoofing real Georgia developer Daniel Canup (finidev); backed by Firebase greaterops-f8d8b and delivering Skyron.zip Git hook dropper.",
    "astrabytesyncs.com": "NICKEL ALLEY / Astra Byte Sync front domain linked to Contagious Interview PyLangGhost / BeaverTail lures.",
    "astrabytesync.com": "NICKEL ALLEY / Astra Byte Sync primary domain.",
    "kiggla.com": "Fabricated front company used in Contagious Interview AI resume-tailor and screening calls.",
    "stackmatch.space": "Unmasked Hetzner-hosted clone of stack-match.io linked to Contagious Interview front operations.",
    "hiregraph.space": "Unmasked Hetzner-hosted clone of HireGraph linked to Contagious Interview front operations.",
    "goapplyjob.online": "Contagious Interview SaaS front tied to BladeCKG / JobMatchAI cluster.",
    "crewjobs.app": "AWS-hosted job platform linked to +0900 (UTC+9) operative melodyxpot.",
    "amazingcoding.ai": "Contagious Interview coding platform built by published IOC partner0831 and aged European GitHub accounts.",
    "steadystake.org": "Contagious Interview Web3 presale/DCA front spoofing legitimate steadystake.app.",
    "primeworksllc.org": "Contagious Interview front site built by +0900 (UTC+9) operative dragobubba.",
    "ktopsoft.com": "Contagious Interview development shop tied to smile0614 / KTOP-Akio / infinitex.games.",
    "lavendarsolution.com": "Contagious Interview staffing front tied to LavendarSolution and xspace-solution.",
    "web-boxes.com": "Domain linked to webboxesdeveloper in the Kiggla resume-tailor factory.",
    "theeverythingagency.com": "Domain linked to Rangeview Marketing Slack workspace.",
    "jisheng.io": "Hong Kong corporate front (HONGKONG JISHENG DEVELOPMENT LIMITED, CR 3253553) linked to David Wong / kato114.",
    "davidwong.pro": "Portfolio front publishing kato114 developer email wwit.llt@gmail.com.",
    "aleksandar.my": "Belgrade persona portfolio linked to JiSheng and Telegram ktman114.",
    "resumate.app": "Job automation front linked to +0900 operative melodyxpot.",
}

KNOWN_MALICIOUS_EMAILS: Dict[str, str] = {
    "career@ledgeroom.org": "Sender email used in impersonated 'Daniel Canup' Hubstaff Talent / Built In Contagious Interview lure delivering Skyron.zip.",
    "dev@greaterops.org": "Git reflog author ('Julia <dev@greaterops.org>') inside Skyron.zip committed in +0900 (UTC+9).",
    "olexiy.buyanskyy@proton.me": "Git commit email (+0900 UTC+9) used on awerudev malware repositories.",
    "corey.ganong@proton.me": "Git commit email (+0900 UTC+9) used on awerudev/defiguard-dev BeaverTail repositories.",
    "davisnguyen654@gmail.com": "Git commit email used by lookalike account fini-dev (ID 82961929).",
    "dyup58725@gmail.com": "Confirmed Contagious Interview IOC from GitLab Threat Intelligence Report (Feb 19, 2026).",
    "speedgamba@gmail.com": "Confirmed operator email behind AstraByte / Rangeview Marketing impersonation.",
    "hobai0003@gmail.com": "Operator email behind Kiggla / job-marketing-world Slack cell.",
    "service@astrabytesync.com": "Git commit email (+0900 UTC+9) for Astra Byte Sync front.",
    "service@astrabytesyncs.com": "Published contact email on astrabytesyncs.com.",
    "randhawamanpreet37@gmail.com": "Git commit email (+0900 UTC+9) behind Jackpot-scam / Zeta-Play Contagious Interview lures.",
    "webvlada2024@gmail.com": "Git commit email (+0900 UTC+9) linked to sparkdev0917 / VladimirSimic2024.",
    "wwit.llt@gmail.com": "Developer email linking kato114, davidwong.pro, and jisheng.io.",
    "neverdreamagain9106@gmail.com": "Git commit email (+0900 UTC+9) linked to BladeCKG / Jio.",
    "tosky929@gmail.com": "Git commit email linked to skydev929 resume-tailor factory.",
    "mitsuomori0318@gmail.com": "Git commit email (+0900 UTC+9) linked to AppleSeed0318.",
    "nataphongnakorn11@outlook.com": "Git commit email (-0500 EST) used across nataphong-lab/Open-Source-Face-Recognition-Ultimate Windows PowerShell/.dat crypto-clipper commits (Freelancer #2804892 operator, separate from DPRK Contagious Interview).",
    "nataphong-lab@gmail.com": "Contact email published in nataphong-lab/Open-Source-Face-Recognition-Ultimate README.md distributing an AES-encrypted PowerShell/.dat crypto-clipper.",
}

KNOWN_MALICIOUS_GITHUB_ACTORS: Dict[str, str] = {
    "awerudev": "ID 22884168 (+0900 UTC+9): sole follower of finidev; hosts defiguard-dev BeaverTail C2 repos.",
    "fini-dev": "ID 82961929: hyphenated lookalike of finidev in awerudev's mutual follow graph; leaks Skype live:jameshess007.",
    "greaterops-org": "ID 306225071: GitHub org matching ledgeroom.org's Firebase project greaterops-f8d8b and spoofing greaterops.org.",
    "auzi-cloud": "ID 306221258: sole follower of GreaterOps-Org ('Andrei Kunin').",
    "astrasbytesyncs": "ID 235172504: Astra Byte Sync GitHub organization.",
    "mann-004": "ID 177943630 (terminated): Contagious Interview Web3 casino lure author.",
    "sisyourname": "ID 234133319 (terminated): Astra Byte Sync operator.",
    "sparkdev0917": "ID 181880267 (terminated): Astra Byte Sync operator.",
    "webboxesdeveloper": "Kiggla 47-identity AI resume-tailor factory host.",
    "skydev929": "Kiggla AI resume-tailor operator (+0800 CST).",
    "appleseed0318": "Kiggla / Marcura assessment operator (+0900 UTC+9).",
    "bladeckg": "Operator linked to GoApplyJob and GitHub DMCA extortion filing 2025-05-29-tempus-ai.md.",
    "ktopsoft": "ID 108729931 (+0900 UTC+9): 'Yuki Ono' / 'United of States'.",
    "smile0614": "ID 154412259 (formerly KTOP-Akio / bit-pal): injected runner-maintenance.yml secret exfiltration across 76 repos.",
    "uniwaydev": "UniwaySoft (+0900 UTC+9) / job-marketing-world leader 'One'.",
    "kato114": "David Wong / JiSheng operator (+0900 / +0800).",
    "superdev348": "ID 77982379 (+0900 UTC+9): 348-suffix sockpuppet ring.",
    "corasphinx": "ID 82669989 (+0900 UTC+9): CriticalRiver / FinCoPilot data leak operator.",
    "hexzilla": "ID 75077277 (+0900 UTC+9): GitHub DMCA leak filing 2025-03-19-litegix.md.",
    "nataphong-lab": "Created 2025-04-18 (1 follower, 1 repo, 742+ fake stars): distributes Windows PowerShell/.dat AES-256-CBC PyInstaller crypto clipboard hijacker via Freelancer contest #2804892 (aaront71).",
}

KNOWN_MALICIOUS_INFRA: Dict[str, str] = {
    "84.200.33.163": "UltaHost / First Colo Frankfurt Stage 1 & 2 malware staging server (/302/302m, 302l, 302w, tokenlinux.sh, parser.js).",
    "104.234.94.198": "Stage 4/5 BeaverTail / InvisibleFerret C2 server (port 1144, campaign 30621346).",
    "107.182.130.226": "Fallback Stage 4/5 BeaverTail / InvisibleFerret C2 server (port 1144, campaign 30621346).",
    "213.173.111.184": "nataphong-lab Windows crypto-clipper C2 server (port 25642, /api/clipboard-ok & /api/clipboard-job/*/status) generating lookalike vanity wallet addresses.",
    "storageplatformdiagnosticslab": "Windows staging directory (%LOCALAPPDATA%\\StoragePlatformDiagnosticsLab) and HKCU Run autostart key created by nataphong-lab PyInstaller crypto-clipper.",
    "greaterops-f8d8b": "Firebase project ID leaked in ledgeroom.org /__/firebase/init.json.",
    "company-cc843": "Firebase hosting site ID serving ledgeroom.org.",
    "15a39da2-fd11-8179-ac80-0003c5c33f58": "Notion workspace ID hosting Skyron.zip Contagious Interview archive.",
    "41439da2-fd11-80ba-96b2-f33e4f221461": "Notion page ID serving Skyron.zip Contagious Interview archive.",
    "41439da2fd1180ba96b2f33e4f221461": "Notion page URL ID serving Skyron.zip Contagious Interview archive.",
    "thread-mollusk-04b": "Notion public workspace domain hosting Skyron.zip.",
    "srv419966518.host": "Attacker Linux VPS hostname leaked in Skyron.zip .git/logs/HEAD.",
    "vscode-check-mo4-ten.vercel.app": "Contagious Interview VS Code tasks.json payload host (shawaj/Jackpot-scam).",
    "apigoogle-ashen.vercel.app": "Contagious Interview VS Code tasks.json payload host (Zeta-Play).",
}

KNOWN_MALICIOUS_WALLETS_OR_TXS: Dict[str, str] = {
    "TMpR4viF4xPeMAcgYDoF57ECAaDPpj1oXs": "TRON EtherHider dead-drop controller wallet used by Skyron.zip parser.js.",
    "7c85209eec99eb600a7c19773126c9d34d266c3cc6fd6728f87ac2c669ec5fd2": "TRON dead-drop transaction encoding BSC payload tx hash.",
    "0x2daeeefb925fc00df10d928b079daaed07caf037": "BSC EtherHider dead-drop sender wallet (nonce 69+).",
    "0x4fc971d535ab66f09472d637d4697e464df67172a83616093c6d8776fc219c6e": "BSC transaction carrying XOR-encrypted Stage 4 BeaverTail loader.",
}

KNOWN_MALICIOUS_SHA256: Dict[str, str] = {
    "9b92ca76ba12166be5b74c80711cd2a6d088da23bac051b9058b3cadae4130b1": "Skyron.zip — Trojanized Flask/Python blockchain assessment archive with .git/hooks/post-checkout dropper.",
    "d03934e0ff384c64bdefa941a8060586b4dad269394dbe9def32cc2cbd889846": "parser.js — Stage 3 dual-blockchain (TRON -> BSC) EtherHider resolver.",
    "5382ba7659af452590308e35cfb80bc8b65b039bd046e9edde885c16f0a83a1d": "Raw .eml spear-phishing email from Daniel Canup <career@ledgeroom.org> delivering Skyron.zip.",
    "a7fe61e2921e2aac65c75fadb72a8994f3e7386e73c7e089f3404d41cc35a935": "install.ps1 — PowerShell dropper decrypting Advanced.dat (AES-256-CBC / PBKDF2-SHA256) and running Invoke-Expression.",
    "68ec1e12fa8a5c11f71b7cf84e946d76093db62947928f4eec3ee381962e0080": "Advanced.dat — Encrypted PowerShell Stage 2 compiling Updated.dat & Base.dat locally with PyInstaller (--onefile --windowed).",
    "7fe030f12518b0e9041eed0048016a382cf4687660f9ad11b103fb07242e116c": "Base.dat — Mutual-resurrection Windows persistence watchdog (UserInterrupts.exe / HKCU Run UserInterruptsLab).",
    "f4c07d6865bbfccb11fb0f80ece4c1653d43dc8d2b812a5a3c3de6ab500bfbd0": "Updated.dat — Windows vanity crypto-address clipboard hijacker (SystemCompute.exe) reporting to 213.173.111.184:25642.",
    "1f72c0b96b60917a137588151092b164aff22778ab1e34dc81aad761bd25aabb": "env.conf — AES-256-CBC encrypted C2 config resolving SERVER_HOST=213.173.111.184:25642.",
}

KNOWN_SIGNATURE_ANOMALIES = (
    "5510 philips highway, 12, nj",
    "5510 philips highway",
    "904) 866-4381",
)
