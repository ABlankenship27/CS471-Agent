# all Example objects

from fairlib import Example

EXAMPLES = [
    # Skipping tools just means the first decision is final_answer
    Example(
        "User: The auth log shows 40 failed logins for the admin account from "
        "203.0.113.5 within two minutes, followed by one successful login "
        "from the same address.\n"
        "Thought: The evidence shows repeated failures then a success from one "
        "address. That supports a brute-force finding. I will report only what "
        "the log shows.\n"
        "Action:\n"
        "tool_name: final_answer\n"
        'tool_input: {"summary":"The log is consistent with a brute-force attack '
        'on the admin account.","findings":["40 failed admin logins from '
        '203.0.113.5 in two minutes","Successful admin login from the same '
        'address immediately afterward"]}'
    ),
    # With a tool, the loop is Thought, tool call, Observation, then another Thought, which again chooses between another tool and final_answer
    Example(
        "User: A server logged 15 failed logins per hour for 4 hours. "
        "How many failed logins in total?\n"
        "Thought: Arithmetic goes to the calculator. The input is the bare expression only.\n"
        "Action:\n"
        "tool_name: safe_calculator\n"
        "tool_input: 15 * 4"
        )
]
