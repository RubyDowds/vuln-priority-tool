import pandas as pd

eval_dataset = [
    {
        "question": "Are there any Samsung Vulnerabilities?",
        "ground_truth": "Yes, Samsung mobile devices have multiple vulnerabilities in the KEV catalog including path "
                        "traversal vulnerabilities, Out-of-Bounds Write Vulnerabilities and Use-After-Free "
                        "Vulnerabilities, among others."
    },
    {
        "question": "Are there any Cisco Vulnerabilities?",
        "ground_truth": "Yes, Cisco has multiple vulnerabilities in the KEV catalog including denial of service, "
                    "authentication bypass, and remote code execution issues affecting Cisco IOS and other products."
    },
    {
        "question": "Are there any Microsoft Vulnerabilities?",
        "ground_truth": "Yes, Microsoft has multiple vulnerabilities in the KEV catalog including buffer overflow issues, "
                        "use-after-free vulnerabilities in Internet Explorer, remote code execution vulnerabilities, "
                        "and privilege escalation issues affecting Windows and other Microsoft products."
    },
    {
        "question": "Are there any remote code execution vulnerabilities?",
        "ground_truth": "Yes, there are multiple remote code execution vulnerabilities in the KEV catalog including"
                        " issues affecting Grafana, XWiki, and various Microsoft products, as well as other products."
    },
    {
        "question": "Are there any path traversal vulnerabilities?",
        "ground_truth": "Yes, there are multiple path traversal vulnerabilities in the KEV catalog including issues "
                        "affecting RARLAB WinRAR, Fortinet FortiWeb and Gogs, among others."
    },
    {
        "question": "Are there any vulnerabilities affecting mobile devices?",
        "ground_truth": "Yes, there are multiple mobile device vulnerabilities including several affecting Samsung"
                        " mobile devices."
    },
    {
        "question": "Are there any Command Injection Vulnerabilities?",
        "ground_truth": "Yes, there are multiple Command Injection Vulnerabilities, including issues affecting "
                        "Sangoma FreePBX, Array Networks ArrayOS AG OS, Fortinet FortiWeb OS, among other products."
    },
    {
        "question": "Are there any Buffer Overflow Vulnerabilities?",
        "ground_truth": "Yes, there are multiple Buffer Overflow Vulnerabilities, including issues affecting Citrix "
                        "NetScaler ADC and Gateway, multiple Fortinet products, Microsoft product, and a few others."
    },
    {
        "question": "Are there any DrayTek Vulnerabilities?",
        "ground_truth": "Yes there are multiple DrayTek Vulnerabilities, including OS Command Injection and "
                        "Path Traversal vulnerabilities."
    },
    {
        "question": "Are there any GitLab Vulnerabilities?",
        "ground_truth": "Yes there are multiple GitLab Vulnerabilities, including Remote Code Execution, Server-Side "
                        "Request Forgery and Improper Access Control Vulnerabilities."
    },
    {
        "question": "Are there any CrushFTP Vulnerabilities?",
        "ground_truth": "Yes there are multiple CrushFTP Vulnerabilities, including Authentication Bypass, an "
                        "unspecified sandbox escape vulnerability and some others."
    },
    {
        "question": "Are there any Vulnerabilities affecting Ivanti?",
        "ground_truth": "Yes there are multiple Ivanti Vulnerabilities, including Code Injection Vulnerabilities,"
                        "Server-Side Request Forgery and Authentication Bypass Vulnerabilities, affecting different"
                        "Ivanti products such as Endpoint Manager Mobile, Connect Secure, Policy Secure and"
                        "Endpoint Manager Cloud Service Appliance, amongst others."
    },
    {
        "question": "Are there any Fortinet Vulnerabilities?",
        "ground_truth": "Yes there are multiple Fortinet Vulnerabilities, including SQL Injection, Out-of-Bound Write,"
                        "and Buffer Overflow Vulnerabilities, affecting different Fortinet products."
    },
    {
        "question": "What is the most widely discussed vulnerability in the media?",
        "ground_truth": "I don't have enough information to answer that."
    },
    # {
    #     "question": "What should I patch first?",
    #     "ground_truth": "I don't have enough information to answer that."
    # },
]

