

agent_eval_dataset = [
    {
        "question": "What should I patch immediately?",
        "expected_tools": ["search_priorities"],
    },
    {
        "question": "Tell me about CVE-2022-31199",  # exists, has asset exposure
        "expected_tools": ["lookup_cve_details"],
    },
    {
        "question": "Tell me about CVE-2021-23758",  # exists, no asset exposure
        "expected_tools": ["lookup_cve_details"],
    },
    {
        "question": "Tell me about CVE-2028-12344",  # doesn't exist
        "expected_tools": ["lookup_cve_details"],
    },
    {
        "question": "What's going on with CVE-2026-66384",  # ambiguous phrasing
        "expected_tools": ["lookup_cve_details"],
    },
    { # todo the right tool doesn't really exist for this yet, just the best available atm, need to make a new tool
        "question": "Any Cisco vulnerabilities?",
        "expected_tools": ["search_priorities"],
    },
    {
        "question": "Tell me about the weather",  # Unrelated question; no tool called
        "expected_tools": [],
    },
]