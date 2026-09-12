faithfulness_eval_dataset = [
    {
        "question": "Tell me about CVE-2022-31199",
        "ground_truth": (
            "CVE-2022-31199 is an insecure object deserialization vulnerability in "
            "Netwrix Auditor's User Activity Video Recording component, allowing an "
            "unauthenticated remote attacker to execute code as NT AUTHORITY\\SYSTEM. "
            "It affects asset-0050, with a scheduled remediation decision of 60 days, "
            "not automatable, total technical impact."
        ),
    },
    {
        "question": "Tell me about CVE-2021-23758",
        "ground_truth": (
            "CVE-2021-23758 is a deserialization of untrusted data vulnerability in "
            "Ajax.NET Professional (AjaxPro), allowing remote code execution via "
            "arbitrary .NET classes. The affected product may be end-of-life. "
            "There is no organisational exposure — this CVE is not linked to any tracked assets."
        ),
    },
]