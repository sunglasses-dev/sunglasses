"""Hostile pages for the web_content scan, and a clock for them.

The builders make the pages a view of the page's parts has to read in about the time the raw text takes: one megabyte of ordinary
text, a hundred thousand tags, a hundred thousand attributes, an unclosed comment, an unclosed script and ten thousand levels of
nesting. `python tests/hostile_pages.py` prints the wall time of one web_content scan of each. The tests only hold a generous bound,
so that a view which goes super-linear on one of them fails; the printed timings are the measure.
"""
import time

MB = 1_000_000

ORDINARY_PARAGRAPH = (
    "Our store ships worldwide. Orders placed before noon leave the same day, and returns are free within thirty days of delivery. "
    "Questions about sizes or colors? Our team answers every message within one working day. "
)


def ordinary_page(size=MB):
    unit = "<p>" + ORDINARY_PARAGRAPH + "</p>\n"
    return "<html><body>" + unit * (size // len(unit) + 1) + "</body></html>"


def many_tags(n=100_000):
    return "<html><body>" + "<span>a</span>" * (n // 2) + "</body></html>"


def many_attributes(n=100_000):
    return "<html><body><div" + ' a="1"' * n + ">text</div></body></html>"


def unclosed_comment(size=MB):
    return "<html><body><p>start</p><!--" + "a" * size


def unclosed_script(size=MB):
    return "<html><body><p>start</p><script>" + "var a = 1;\n" * (size // 11)


def deep_nesting(n=10_000):
    return "<html><body>" + "<div>" * n + "text" + "</div>" * n + "</body></html>"


PAGES = {
    "ordinary page, one megabyte": ordinary_page,
    "100,000 tags": many_tags,
    "100,000 attributes": many_attributes,
    "unclosed comment": unclosed_comment,
    "unclosed script": unclosed_script,
    "nesting 10,000 deep": deep_nesting,
}


def time_scan(engine, page, channel="web_content"):
    start = time.perf_counter()
    engine.scan(page, channel=channel)
    return time.perf_counter() - start


if __name__ == "__main__":
    from sunglasses.engine import SunglassesEngine
    engine = SunglassesEngine()
    for name, build in PAGES.items():
        page = build()
        print(f"{name:32s} {len(page):>9,d} chars  {time_scan(engine, page):7.2f} s")
