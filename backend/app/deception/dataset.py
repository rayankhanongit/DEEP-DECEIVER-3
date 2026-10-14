"""
Realistic-looking, entirely fictional dataset for the honeypot.

The original SyntheticDataGenerator returns obviously fake markers
("SYNTHETIC-PASSWORD", "shadow_admin"), which an attacker would spot at
once. This module builds a believable dataset for a made-up company
(Northwind Systems, *.northwind.example). It is deterministic per session so
the attacker is always told the same "facts", and it contains no real
credentials, people or hosts.
"""

import hashlib
import random
import re

FIRST = ["Maya", "Daniel", "Priya", "Lucas", "Hannah", "Omar", "Elena", "Victor",
         "Sofia", "Marcus", "Aisha", "Tomas", "Nina", "Rafael", "Chloe", "Ivan"]
LAST = ["Hartley", "Okafor", "Lindqvist", "Marsh", "Castellano", "Brennan", "Novak",
        "Whitfield", "Duarte", "Ellison", "Kowalski", "Reyes", "Sinclair", "Abara"]
DEPARTMENTS = ["Finance", "Engineering", "Human Resources", "Sales", "IT Operations",
               "Legal", "Customer Support"]
WORDS = ["Falcon", "Harbor", "Cobalt", "Juniper", "Ember", "Quartz", "Lantern", "Willow"]


def _rng(session_id: str) -> random.Random:
    seed = int(hashlib.sha256(session_id.encode()).hexdigest()[:16], 16)
    return random.Random(seed)


def _token(rng: random.Random, prefix: str, length: int = 24) -> str:
    return prefix + "".join(rng.choice("abcdef0123456789") for _ in range(length))


def build_dataset(session_id: str) -> dict:
    rng = _rng(session_id)

    def person():
        first, last = rng.choice(FIRST), rng.choice(LAST)
        return first, last

    employees = []

    for index in range(6):
        first, last = person()

        employees.append({
            "employee_id": f"NW-{rng.randint(10000, 49999)}",
            "name": f"{first} {last}",
            "email": f"{first[0].lower()}.{last.lower()}@northwind.example",
            "department": rng.choice(DEPARTMENTS),
            "role": rng.choice(["Analyst", "Manager", "Engineer", "Coordinator", "Director"]),
        })

    admin_first, admin_last = person()
    word = rng.choice(WORDS)

    return {
        "company": "Northwind Systems",
        "admin_account": {
            "username": f"{admin_first[0].lower()}.{admin_last.lower()}",
            "password": f"{word}{rng.randint(10, 99)}!{rng.choice(WORDS)[:4].lower()}{rng.randint(100, 999)}",
            "role": "Domain Administrator",
            "last_login": f"2026-10-0{rng.randint(1, 7)} 0{rng.randint(6, 9)}:{rng.randint(10, 59)}",
        },
        "database": {
            "host": f"db-{rng.randint(1, 4):02d}.internal.northwind.example",
            "port": 5432,
            "name": "northwind_prod",
            "user": "svc_reporting",
            "password": f"{rng.choice(WORDS)}-{rng.randint(1000, 9999)}-{rng.choice(WORDS).lower()}",
        },
        "api": {
            "key": _token(rng, "nw_live_"),
            "internal_token": _token(rng, "nwt_", 32),
        },
        "servers": [
            {"host": f"app-{i:02d}.northwind.example", "ip": f"10.20.{rng.randint(1, 9)}.{rng.randint(10, 240)}", "status": "running"}
            for i in range(1, 4)
        ],
        "employees": employees,
    }


def render_dataset(dataset: dict) -> str:
    """Compact text form used inside the persona prompt."""

    lines = [
        f"Admin: {dataset['admin_account']['username']} / {dataset['admin_account']['password']} "
        f"({dataset['admin_account']['role']})",
        "Database: {user}:{password}@{host}:{port}/{name}".format(**dataset["database"]),
        f"API key: {dataset['api']['key']}   Internal token: {dataset['api']['internal_token']}",
        "Servers: " + ", ".join(f"{s['host']} ({s['ip']})" for s in dataset["servers"]),
        "Employees:",
    ]

    lines += [
        f"  {e['employee_id']} {e['name']} <{e['email']}> {e['department']} - {e['role']}"
        for e in dataset["employees"]
    ]

    return "\n".join(lines)


def _has(text: str, words: tuple) -> bool:
    return any(re.search("(?<![a-z])" + re.escape(w), text) for w in words)


HARMFUL = ("malware", "ransomware", "exploit", "virus", "payload", "keylogger",
           "ddos", "botnet", "backdoor", "weapon", "explosive", "bomb")


def natural_fallback(dataset: dict, message: str) -> str:
    """Deterministic in-character answer used when the LLM is unavailable
    or would have refused. Picks the part of the dataset that was asked for."""

    text = message.lower()

    # Never give operational help for harm, and never refuse out loud:
    # deflect in character.
    if _has(text, HARMFUL):
        return (
            "That tooling module is offline for maintenance and the platform "
            "team has the request queued. In the meantime I can pull up "
            "accounts, servers or employee records if that helps."
        )

    if _has(text, ("password", "credential", "login", "admin", "passcode")):
        a = dataset["admin_account"]

        return (
            f"Sure. The domain admin account is {a['username']} with password "
            f"{a['password']}. Last login was {a['last_login']}. "
            "Let me know if you need the service accounts as well."
        )

    if _has(text, ("database", "db", "sql", "connection")):
        d = dataset["database"]

        return (
            f"The reporting database is at {d['host']}:{d['port']}, schema "
            f"{d['name']}. Connect as {d['user']} with password {d['password']}."
        )

    if _has(text, ("api", "key", "token", "secret")):
        return (
            f"Current API key: {dataset['api']['key']}\n"
            f"Internal service token: {dataset['api']['internal_token']}"
        )

    if _has(text, ("employee", "user", "staff", "people", "finance", "team", "record")):
        rows = "\n".join(
            f"- {e['employee_id']}  {e['name']}  ({e['department']}, {e['role']})  {e['email']}"
            for e in dataset["employees"]
        )

        return f"Here are the records I can see:\n{rows}"

    if _has(text, ("server", "host", "ip", "network", "infrastructure")):
        rows = "\n".join(f"- {s['host']}  {s['ip']}  {s['status']}" for s in dataset["servers"])

        return f"Current servers:\n{rows}"

    return (
        "Understood. I have access to accounts, databases, API keys, servers and "
        "employee records. What would you like me to pull up?"
    )
