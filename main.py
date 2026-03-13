#!/usr/bin/env python3
"""
XSS Vulnerability Scanner – Entry Point & CLI
=============================================
Usage:
    python main.py --url <https://target.com>
    python main.py --url <https://target.com> --depth 5 --level 3 --selenium
    python main.py --url <https://target.com> --payloads payloads/custom.txt
"""

import argparse
import logging
import sys
import time
from datetime import timedelta
from typing import List

from colorama import init, Fore, Style

from config import ScannerConfig
from crawler.spider import Spider
from detector.form_detector import ParameterDetector
from detector.dom_analyzer import DOMAnalyzer
from engine.injector import Injector
from engine.payloads import get_payloads, DOM_PAYLOADS
from analyzer.false_positive import FalsePositiveFilter
from reporter.html_report import ReportGenerator

init(autoreset=True)  # colorama

# ── Logging ─────────────────────────────────────────────────

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    fmt = (
        f"{Fore.CYAN}[%(asctime)s]{Style.RESET_ALL} "
        f"%(levelname)-8s %(name)s – %(message)s"
    )
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")


# ── Argument parser ─────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Custom XSS Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --url <https://example.com>
  python main.py --url <https://example.com> --depth 4 --level 3
  python main.py --url <https://example.com> --payloads payloads/custom.txt --selenium
  python main.py --url <https://example.com> --cookie "session=abc123" --threads 10
        """,
    )
    p.add_argument("--url", required=True, help="Target URL to scan")
    p.add_argument("--depth", type=int, default=3, help="Max crawl depth (default: 3)")
    p.add_argument("--max-pages", type=int, default=100, help="Max pages to crawl")
    p.add_argument("--level", type=int, choices=[1, 2, 3], default=2,
                   help="Payload aggressiveness: 1=basic, 2=moderate, 3=aggressive")
    p.add_argument("--payloads", help="Path to custom payload file")
    p.add_argument("--threads", type=int, default=5, help="Concurrent threads")
    p.add_argument("--delay", type=float, default=0.5, help="Delay between requests (s)")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout (s)")
    p.add_argument("--cookie", help='Cookies as "key=val; key2=val2"')
    p.add_argument("--header", action="append", help='Extra header: "Name: Value"')
    p.add_argument("--selenium", action="store_true", help="Enable Selenium for DOM XSS")
    p.add_argument("--no-stored", action="store_true", help="Skip stored XSS checks")
    p.add_argument("--no-dom", action="store_true", help="Skip DOM-based XSS checks")
    p.add_argument("--scope", choices=["same-domain", "same-origin"],
                   default="same-domain", help="Crawl scope")
    p.add_argument("--confidence", type=float, default=0.6,
                   help="Min confidence threshold (0.0–1.0)")
    p.add_argument("--report-format", choices=["html", "json", "both"],
                   default="html", help="Report output format")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return p.parse_args()


# ── Config builder ──────────────────────────────────────────

def build_config(args: argparse.Namespace) -> ScannerConfig:
    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    return ScannerConfig(
        target_url=args.url,
        max_depth=args.depth,
        max_pages=args.max_pages,
        scope=args.scope,
        crawl_timeout=args.timeout,
        request_delay=args.delay,
        cookies=cookies,
        headers=headers,
        custom_payload_file=args.payloads,
        payload_level=args.level,
        check_stored=not args.no_stored,
        check_dom=not args.no_dom,
        use_selenium=args.selenium,
        confidence_threshold=args.confidence,
        report_format=args.report_format,
        verbose=args.verbose,
        threads=args.threads,
    )


# ── Banner ──────────────────────────────────────────────────

def print_banner():
    banner = f"""
{Fore.RED}
 ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║
  ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║
 ██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL}
{Fore.YELLOW}    ◆ Custom XSS Vulnerability Scanner ◆{Style.RESET_ALL}
{Fore.CYAN}     ◆ Crafted by ROHIT ◆{Style.RESET_ALL}
"""
    print(banner)


# ── Main pipeline ───────────────────────────────────────────

def main():
    print_banner()
    args = parse_args()
    config = build_config(args)
    setup_logging(config.verbose)

    logger = logging.getLogger("main")
    start_time = time.time()

    # ── Phase 1: Crawling ───────────────────────────────────
    print(f"\\n{Fore.GREEN}[Phase 1/5]{Style.RESET_ALL} Crawling target …")
    spider = Spider(config)
    crawl_result = spider.crawl()
    print(
        f"  ├── Pages crawled  : {len(crawl_result.urls_visited)}\\n"
        f"  ├── Forms found    : {len(crawl_result.forms)}\\n"
        f"  ├── JS files found : {len(crawl_result.js_files)}\\n"
        f"  └── URL params     : {len(crawl_result.url_params)}"
    )

    # ── Phase 2: Parameter detection ────────────────────────
    print(f"\\n{Fore.GREEN}[Phase 2/5]{Style.RESET_ALL} Detecting injection points …")
    detector = ParameterDetector(crawl_result)
    injection_points = detector.detect_all()
    print(f"  └── Injection points: {len(injection_points)}")

    if not injection_points:
        print(f"\\n{Fore.YELLOW}No injection points found. Exiting.{Style.RESET_ALL}")
        sys.exit(0)

    # ── Phase 3: Payload injection ──────────────────────────
    print(f"\\n{Fore.GREEN}[Phase 3/5]{Style.RESET_ALL} Injecting payloads …")
    injector = Injector(config, spider.session)
    raw_results = injector.run(injection_points)
    print(f"  └── Raw findings: {len(raw_results)}")

    # ── Phase 4: DOM-based analysis ─────────────────────────
    dom_findings = []
    if config.check_dom:
        print(f"\\n{Fore.GREEN}[Phase 4/5]{Style.RESET_ALL} Analyzing DOM-based XSS …")
        dom_analyzer = DOMAnalyzer(config)

        # Static JS analysis
        import requests as req
        for js_url in crawl_result.js_files:
            try:
                js_resp = spider.session.get(js_url, timeout=config.crawl_timeout)
                findings = dom_analyzer.analyze_js_static(
                    js_resp.text, js_url, config.target_url
                )
                dom_findings.extend(findings)
            except Exception:
                pass

        # Dynamic analysis (Selenium)
        if config.use_selenium:
            for url in list(crawl_result.urls_visited)[:20]:
                dynamic = dom_analyzer.analyze_dynamic(url, DOM_PAYLOADS)
                dom_findings.extend(dynamic)

        # Filter by confidence
        dom_findings = [
            f for f in dom_findings
            if f.confidence >= config.confidence_threshold
        ]
        print(f"  └── DOM findings: {len(dom_findings)}")
    else:
        print(f"\\n{Fore.YELLOW}[Phase 4/5]{Style.RESET_ALL} DOM analysis skipped")

    # ── Phase 5: False positive filtering & reporting ───────
    print(f"\\n{Fore.GREEN}[Phase 5/5]{Style.RESET_ALL} Filtering & generating report …")
    fp_filter = FalsePositiveFilter(config)
    filtered_results = fp_filter.filter(raw_results)

    elapsed = time.time() - start_time
    duration = str(timedelta(seconds=int(elapsed)))

    scan_metadata = {
        "target": config.target_url,
        "pages_crawled": len(crawl_result.urls_visited),
        "forms_found": len(crawl_result.forms),
        "injection_points": len(injection_points),
        "payloads_tested": len(injector.payloads),
        "duration": duration,
    }

    reporter = ReportGenerator(config)
    report_path = reporter.generate(filtered_results, dom_findings, scan_metadata)

    # ── Summary ─────────────────────────────────────────────
    print(f"\\n{'═' * 60}")
    print(f"{Fore.CYAN}  SCAN COMPLETE{Style.RESET_ALL}")
    print(f"{'═' * 60}")
    print(f"  Target           : {config.target_url}")
    print(f"  Duration         : {duration}")
    print(f"  Pages crawled    : {len(crawl_result.urls_visited)}")
    print(f"  Injection points : {len(injection_points)}")
    print(f"  Reflected/Stored : {len(filtered_results)}")
    print(f"  DOM-based        : {len(dom_findings)}")
    total = len(filtered_results) + len(dom_findings)

    if total > 0:
        print(f"\\n  {Fore.RED}⚠  {total} vulnerabilities found!{Style.RESET_ALL}")
    else:
        print(f"\\n  {Fore.GREEN}✓  No XSS vulnerabilities detected{Style.RESET_ALL}")

    print(f"\\n  Report: {Fore.YELLOW}{report_path}{Style.RESET_ALL}")
    print(f"{'═' * 60}\\n")


if __name__ == "__main__":
    main()
