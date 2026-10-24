
import asyncio
import base64
import json
import os
import re
import socket
import ssl
import tempfile
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
TCP_TIMEOUT = 2.5          # сек, этап 1
TLS_TIMEOUT = 4.0          # сек, этап 2
CONCURRENCY = 500          # одновременных проверок на этапах 1-2
TOP_N = 600
FETCH_TIMEOUT = 30
REQUIRE_SECURITY = True    # отбрасывать ноды без tls/reality
NUMBERED = False           # True -> «🇩🇪 Германия 2», «🇩🇪 Германия 3»...
PLACEHOLDER_HOSTS = {"111.111.111.111", "0.0.0.0", "127.0.0.1", "localhost"}
UA = "Mozilla/5.0 (harvester-py)"

# этап 3 (xray)
XRAY_BIN = os.environ.get("XRAY_BIN") or str(ROOT / "bin" / "xray")
PROXY_BATCH = 100          # нод на один процесс xray
PARALLEL_BATCHES = 3       # процессов xray одновременно
PROXY_BASE_PORT = 20000
PROXY_TIMEOUT = 8.0        # сек на один запрос через ноду
CHECK_ROUNDS = 3           # нода должна ответить ВСЕ эти разы подряд
TRACE_HOST = "1.1.1.1"
TRACE_PATH = "/cdn-cgi/trace"

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
    "IQ": "Ирак", "IN": "Индия", "CN": "Китай", "HK": "Гонконг",
    "TW": "Тайвань", "JP": "Япония", "KR": "Южная Корея", "SG": "Сингапур",
    "MY": "Малайзия", "TH": "Таиланд", "VN": "Вьетнам", "ID": "Индонезия",
    "PH": "Филиппины", "AU": "Австралия", "NZ": "Новая Зеландия",
    "CA": "Канада", "MX": "Мексика", "BR": "Бразилия", "AR": "Аргентина",
    "CL": "Чили", "ZA": "ЮАР", "EG": "Египет", "IS": "Исландия",
    "CY": "Кипр", "MT": "Мальта", "PK": "Пакистан", "BD": "Бангладеш",
    "KG": "Киргизия", "MN": "Монголия", "NG": "Нигерия", "KE": "Кения",
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
    proxy_ms: float | None = None
    exit_cc: str = ""
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
        t = time.perf_counter()
        try:
            _, w = await asyncio.wait_for(
                asyncio.open_connection(node.ip, node.port), TCP_TIMEOUT
            )
        except Exception:
            return
        node.tcp_ms = (time.perf_counter() - t) * 1000
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass


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


# ---------------- этап 3: реальная проверка через xray ----------------
def build_outbound(n: Node, tag: str) -> dict | None:
    """Строит outbound xray из параметров vless://. None = не поддерживается."""
    p = n.params
    net = p.get("type", "tcp").lower()
    if net == "splithttp":
        net = "xhttp"
    if net not in ("tcp", "ws", "grpc", "httpupgrade", "xhttp"):
        return None
    if net == "tcp" and p.get("headerType", "none") not in ("none", ""):
        return None

    sec = p.get("security", "none").lower()
    user = {"id": n.uuid, "encryption": p.get("encryption") or "none"}
    if p.get("flow"):
        user["flow"] = p["flow"]

    ss: dict = {"network": net, "security": sec if sec in ("tls", "reality") else "none"}
    if sec == "tls":
        tls = {"serverName": p.get("sni") or p.get("host") or n.host,
               "allowInsecure": True}
        if p.get("fp"):
            tls["fingerprint"] = p["fp"]
        if p.get("alpn"):
            tls["alpn"] = p["alpn"].split(",")
        ss["tlsSettings"] = tls
    elif sec == "reality":
        ss["realitySettings"] = {
            "serverName": p.get("sni") or n.host,
            "fingerprint": p.get("fp") or "chrome",
            "publicKey": p["pbk"],
            "shortId": p.get("sid", ""),
            "spiderX": p.get("spx", ""),
        }

    path = p.get("path") or "/"
    host = p.get("host", "")
    if net == "ws":
        ss["wsSettings"] = {"path": path, "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": p.get("serviceName", ""),
                              "multiMode": p.get("mode") == "multi"}
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": path, "host": host}
    elif net == "xhttp":
        ss["xhttpSettings"] = {"path": path, "host": host, "mode": p.get("mode", "auto")}

    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {"vnext": [{"address": n.ip, "port": n.port, "users": [user]}]},
        "streamSettings": ss,
    }


def xray_config(items: list[tuple[int, dict]]) -> dict:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {"tag": f"in{port}", "listen": "127.0.0.1", "port": port,
             "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}
            for port, _ in items
        ],
        "outbounds": [ob for _, ob in items],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": [f"in{port}"], "outboundTag": ob["tag"]}
                for port, ob in items
            ],
        },
    }


async def socks_get(port: int) -> str:
    """HTTP GET http://1.1.1.1/cdn-cgi/trace через SOCKS5-inbound xray."""
    r, w = await asyncio.open_connection("127.0.0.1", port)
    try:
        w.write(b"\x05\x01\x00")
        await w.drain()
        if await r.readexactly(2) != b"\x05\x00":
            raise OSError("socks auth")
        w.write(b"\x05\x01\x00\x01" + socket.inet_aton(TRACE_HOST) + (80).to_bytes(2, "big"))
        await w.drain()
        head = await r.readexactly(4)
        if head[1] != 0:
            raise OSError("socks connect")
        if head[3] == 1:
            await r.readexactly(6)
        elif head[3] == 4:
            await r.readexactly(18)
        else:
            ln = (await r.readexactly(1))[0]
            await r.readexactly(ln + 2)
        w.write(
            f"GET {TRACE_PATH} HTTP/1.1\r\nHost: {TRACE_HOST}\r\n"
            f"User-Agent: curl/8.0\r\nConnection: close\r\n\r\n".encode()
        )
        await w.drain()
        data = await r.read(-1)
        return data.decode("utf-8", errors="ignore")
    finally:
        w.close()


LOC_RE = re.compile(r"^loc=([A-Z]{2})", re.M)


async def probe(port: int) -> tuple[bool, float, str]:
    total, loc = 0.0, ""
    for _ in range(CHECK_ROUNDS):
        t = time.perf_counter()
        try:
            body = await asyncio.wait_for(socks_get(port), PROXY_TIMEOUT)
        except Exception:
            return False, 0.0, ""
        m = LOC_RE.search(body)
        if not m:
            return False, 0.0, ""
        total += (time.perf_counter() - t) * 1000
        loc = m.group(1)
    return True, total / CHECK_ROUNDS, loc


async def wait_port(port: int, proc, timeout: float = 8.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proc.returncode is not None:
            return False
        try:
            _, w = await asyncio.open_connection("127.0.0.1", port)
            w.close()
            await asyncio.sleep(0.3)
            return True
        except OSError:
            await asyncio.sleep(0.2)
    return False


async def kill(proc) -> None:
    if proc.returncode is None:
        try:
            proc.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(proc.wait(), 3)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()


async def run_batch(batch: list[Node], base: int) -> None:
    items: list[tuple[int, dict]] = []
    owners: list[Node] = []
    for n in batch:
        port = base + len(items)
        try:
            ob = build_outbound(n, f"out{port}")
        except Exception:
            ob = None
        if ob:
            items.append((port, ob))
            owners.append(n)
    if not items:
        return

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(xray_config(items), f)
        cfg_path = f.name
    proc = await asyncio.create_subprocess_exec(
        XRAY_BIN, "run", "-c", cfg_path,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    started = False
    try:
        started = await wait_port(items[-1][0], proc)
        if started:
            results = await asyncio.gather(*(probe(port) for port, _ in items))
            for n, (ok, ms, loc) in zip(owners, results):
                if ok:
                    n.proxy_ms, n.exit_cc = ms, loc
    finally:
        await kill(proc)
        try:
            os.unlink(cfg_path)
        except OSError:
            pass

    # xray не стартовал (одна кривая нода ломает весь конфиг): делим пополам
    if not started and len(owners) > 1:
        half = len(owners) // 2
        await run_batch(owners[:half], base)
        await run_batch(owners[half:], base)


async def proxy_stage(nodes: list[Node]) -> list[Node]:
    if not Path(XRAY_BIN).exists():
        log(f"  ! xray не найден ({XRAY_BIN}): этап 3 пропущен, "
            f"результат будет менее точным")
        for n in nodes:
            n.proxy_ms, n.exit_cc = n.tls_ms, n.cc
        return nodes

    queue: asyncio.Queue = asyncio.Queue()
    for i in range(0, len(nodes), PROXY_BATCH):
        queue.put_nowait(nodes[i:i + PROXY_BATCH])
    total = queue.qsize()
    done = 0

    async def worker(k: int) -> None:
        nonlocal done
        base = PROXY_BASE_PORT + k * PROXY_BATCH
        while True:
            try:
                batch = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            await run_batch(batch, base)
            done += 1
            log(f"  пачка {done}/{total}")

    await asyncio.gather(*(worker(k) for k in range(PARALLEL_BATCHES)))
    return [n for n in nodes if n.proxy_ms is not None]


# ---------------- страна и название ----------------
def load_geo_cache() -> dict:
    if GEO_CACHE_FILE.exists():
        try:
            return json.loads(GEO_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def geo_lookup(ips: list[str], cache: dict) -> None:
    """ip-api.com (бесплатно, HTTP). Нужен только для ping_tested.txt."""
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
    tls_ok = [n for n in alive if n.tls_ms is not None]
    log(f"Прошли этап 2: {len(tls_ok)}")

    cache = load_geo_cache()
    geo_lookup([n.ip for n in alive], cache)
    for n in alive:
        n.cc = (cache.get(n.ip) or "").upper()

    log("Этап 3: реальная проверка через xray")
    final = await proxy_stage(tls_ok)
    for n in final:
        n.cc = (n.exit_cc or n.cc).upper()   # страна ВЫХОДА, а не входа
    final.sort(key=lambda n: n.proxy_ms)
    log(f"Прошли этап 3: {len(final)}")

    log("Запись файлов")
    write("ping_tested.txt", alive)
    write("speed_tested.txt", final)
    write("top_600.txt", final[:TOP_N])
    write("non_ru.txt", [n for n in final if n.cc != "RU"])


if __name__ == "__main__":
    asyncio.run(run())
