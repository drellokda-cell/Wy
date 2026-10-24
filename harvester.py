#!/usr/bin/env python3

import asyncio
import base64
import json
import re
import socket
import ssl
import time
import urllib.request
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

ROOT = Path(__file__).parent
SOURCES_FILE = ROOT / "sources.txt"
GEO_CACHE_FILE = ROOT / "geo_cache.json"

# ---------------- настройки ----------------
TCP_TIMEOUT = 2.5          # сек, таймаут TCP-подключения
TLS_TIMEOUT = 4.0          # сек, таймаут TLS-рукопожатия
CONCURRENCY = 500          # одновременных проверок
TOP_N = 600                # размер top_600.txt
FETCH_TIMEOUT = 30         # сек, скачивание подписки
REQUIRE_SECURITY = True    # отбрасывать ноды без tls/reality
NUMBERED = True           # True -> «🇩🇪 Германия 2», «🇩🇪 Германия 3»...
PLACEHOLDER_HOSTS = {"111.111.111.111", "0.0.0.0", "127.0.0.1", "localhost"}
UA = "Mozilla/5.0 (harvester-py)"

COUNTRIES = {
    "RU": "Россия", "US": "США", "DE": "Германия", "NL": "Нидерланды",
    "FI": "Финляндия", "SE": "Швеция", "NO": "Норвегия", "DK": "Дания",
    "GB": "Великобритания", "FR": "Франция", "PL": "Польша", "CZ": "Чехия",
    "AT": "Австрия", "CH": "Швейцария", "IT": "Италия", "ES": "Испания",
    "PT": "Португалия", "IE": "Ирландия", "BE": "Бельгия", "LU": "Люксембург",
    "LT": "Литва", "LV": "Латвия", "EE": "Эстония", "UA": "Украина",
    "BY": "Беларусь", "KZ": "Казахстан", "UZ": "Узбекистан", "GE": "Грузия",
    "AM": "Армения", "AZ": "Азербайджан", "MD": "Молдова", "RO": "Румыния",
    "BG": "Болгария", "RS": "Сербия", "HU": "Венгрия", "SK": "Словакия",
    "SI": "Словения", "HR": "Хорватия", "GR": "Греция", "TR": "Турция",
    "IL": "Израиль", "AE": "ОАЭ", "SA": "Саудовская Аравия", "IR": "Иран",
    "IN": "Индия", "CN": "Китай", "HK": "Гонконг", "TW": "Тайвань",
    "JP": "Япония", "KR": "Южная Корея", "SG": "Сингапур", "MY": "Малайзия",
    "TH": "Таиланд", "VN": "Вьетнам", "ID": "Индонезия", "PH": "Филиппины",
    "AU": "Австралия", "NZ": "Новая Зеландия", "CA": "Канада", "MX": "Мексика",
    "BR": "Бразилия", "AR": "Аргентина", "CL": "Чили", "ZA": "ЮАР",
    "EG": "Египет", "IS": "Исландия", "CY": "Кипр", "MT": "Мальта",
}


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


@dataclass
class Node:
    base: str                      # vless://... без #фрагмента
    host: str
    port: int
    uuid: str
    params: dict = field(default_factory=dict)
    ip: str = ""
    tcp_ms: float | None = None
    tls_ms: float | None = None
    cc: str = ""

    @property
    def key(self) -> tuple:
        return (self.host.lower(), self.port, self.uuid)


# ---------------- получение и разбор ----------------
def read_sources() -> list[str]:
    if not SOURCES_FILE.exists():
        raise SystemExit("Нет файла sources.txt")
    out = []
    for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def fetch(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        log(f"  ! не скачалось {url}: {e}")
        return ""


def maybe_b64(text: str) -> str:
    """Некоторые подписки отдаются целиком в base64."""
    if "://" in text:
        return text
    try:
        raw = re.sub(r"\s+", "", text)
        raw += "=" * (-len(raw) % 4)
        return base64.b64decode(raw).decode("utf-8", errors="ignore")
    except Exception:
        return text


LINK_RE = re.compile(r"vless://[^\s\"'<>]+", re.IGNORECASE)


def extract_links(text: str) -> list[str]:
    return LINK_RE.findall(maybe_b64(text))


def parse_vless(link: str) -> Node | None:
    base, _, _frag = link.strip().partition("#")
    try:
        u = urlsplit(base)
        if u.scheme.lower() != "vless":
            return None
        user = unquote(u.username or "")
        uuid.UUID(user)
        host = u.hostname
        port = u.port
    except ValueError:
        return None
    if not host or not port or not (1 <= port <= 65535):
        return None
    if host.lower() in PLACEHOLDER_HOSTS:
        return None
    params = {k: v[0] for k, v in parse_qs(u.query).items()}
    if params.get("security", "none").lower() == "reality" and not params.get("pbk"):
        return None
    return Node(base=base, host=host, port=port, uuid=user.lower(), params=params)


# ---------------- этап 1: TCP ----------------
async def resolve(node: Node) -> bool:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(node.host, node.port, type=socket.SOCK_STREAM), 5
        )
    except Exception:
        return False
    v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    ips = v4 or [i[4][0] for i in infos]
    if not ips:
        return False
    node.ip = ips[0]
    return True


async def tcp_check(node: Node, sem: asyncio.Semaphore) -> None:
    async with sem:
        if not await resolve(node):
            return
        best = None
        for _ in range(1):  # одна попытка, второй этап перепроверит
            t = time.perf_counter()
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(node.ip, node.port), TCP_TIMEOUT
                )
            except Exception:
                continue
            ms = (time.perf_counter() - t) * 1000
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            best = ms if best is None else min(best, ms)
        node.tcp_ms = best


# ---------------- этап 2: TLS-рукопожатие ----------------
async def tls_check(node: Node, sem: asyncio.Semaphore) -> None:
    sec = node.params.get("security", "none").lower()
    async with sem:
        if sec not in ("tls", "reality"):
            node.tls_ms = None if REQUIRE_SECURITY else node.tcp_ms
            return
        sni = node.params.get("sni") or node.params.get("host") or node.host
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        best = None
        for _ in range(2):
            t = time.perf_counter()
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(
                        node.ip, node.port, ssl=ctx, server_hostname=sni,
                        ssl_handshake_timeout=TLS_TIMEOUT,
                    ),
                    TLS_TIMEOUT + 1,
                )
            except Exception:
                continue
            ms = (time.perf_counter() - t) * 1000
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            best = ms if best is None else min(best, ms)
        node.tls_ms = best


# ---------------- страна и название ----------------
def load_geo_cache() -> dict:
    if GEO_CACHE_FILE.exists():
        try:
            return json.loads(GEO_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def geo_lookup(ips: list[str], cache: dict) -> None:
    """ip-api.com (бесплатно, HTTP, лимит ~15 batch-запросов в минуту)."""
    todo = [ip for ip in dict.fromkeys(ips) if ip not in cache]
    log(f"GeoIP: {len(todo)} новых IP")
    for i in range(0, len(todo), 100):
        chunk = todo[i:i + 100]
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=status,countryCode,query",
            data=json.dumps(chunk).encode(),
            headers={"Content-Type": "application/json", "User-Agent": UA},
        )
        wait = 0.0
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.load(r)
                # ждём только когда лимит реально исчерпан
                if r.headers.get("X-Rl") == "0":
                    wait = float(r.headers.get("X-Ttl", "60")) + 1
            for item in data:
                ok = item.get("status") == "success"
                cache[item["query"]] = item.get("countryCode", "") if ok else ""
        except Exception as e:
            log(f"  ! GeoIP ошибка: {e}")
            wait = 5.0
        if wait and i + 100 < len(todo):
            time.sleep(wait)
    GEO_CACHE_FILE.write_text(json.dumps(cache), encoding="utf-8")


def flag(cc: str) -> str:
    if len(cc) == 2 and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper())
    return "🏳️"


def display_name(cc: str) -> str:
    if not cc:
        return "🏳️ Неизвестно"
    return f"{flag(cc)} {COUNTRIES.get(cc.upper(), cc.upper())}"


def render(nodes: list[Node]) -> str:
    counters: dict[str, int] = defaultdict(int)
    lines = []
    for n in nodes:
        name = display_name(n.cc)
        if NUMBERED:
            counters[name] += 1
            if counters[name] > 1:
                name = f"{name} {counters[name]}"
        lines.append(f"{n.base}#{quote(name)}")
    return "\n".join(lines) + ("\n" if lines else "")


def write(name: str, nodes: list[Node]) -> None:
    (ROOT / name).write_text(render(nodes), encoding="utf-8")
    log(f"  {name}: {len(nodes)}")


# ---------------- основной цикл ----------------
async def run() -> None:
    sources = read_sources()
    log(f"Источников: {len(sources)}")
    texts = await asyncio.gather(*(asyncio.to_thread(fetch, u) for u in sources))

    nodes: dict[tuple, Node] = {}
    for url, text in zip(sources, texts):
        links = extract_links(text)
        added = 0
        for link in links:
            n = parse_vless(link)
            if n and n.key not in nodes:
                nodes[n.key] = n
                added += 1
        log(f"  {url}: ссылок {len(links)}, новых валидных {added}")
    log(f"Уникальных валидных URI: {len(nodes)}")

    sem = asyncio.Semaphore(CONCURRENCY)

    log("Этап 1: TCP-проверка")
    await asyncio.gather(*(tcp_check(n, sem) for n in nodes.values()))
    alive = sorted((n for n in nodes.values() if n.tcp_ms is not None),
                   key=lambda n: n.tcp_ms)
    log(f"Прошли этап 1: {len(alive)}")

    log("Этап 2: TLS-рукопожатие")
    await asyncio.gather(*(tls_check(n, sem) for n in alive))
    good = sorted((n for n in alive if n.tls_ms is not None),
                  key=lambda n: n.tls_ms)
    log(f"Прошли этап 2: {len(good)}")

    cache = load_geo_cache()
    geo_lookup([n.ip for n in alive], cache)
    for n in alive:
        n.cc = (cache.get(n.ip) or "").upper()

    log("Запись файлов")
    write("ping_tested.txt", alive)
    write("speed_tested.txt", good)
    write("top_600.txt", good[:TOP_N])
    write("non_ru.txt", [n for n in good if n.cc != "RU"])


if __name__ == "__main__":
    asyncio.run(run())
