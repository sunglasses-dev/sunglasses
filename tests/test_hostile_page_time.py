"""A web_content scan of a hostile page ends in bounded time (helpers in hostile_pages.py)."""
import pytest

from sunglasses.engine import SunglassesEngine
import hostile_pages as H

ENGINE = SunglassesEngine()
BOUND_SECONDS = 120


def test_the_page_builders_make_the_pages_they_name():
    assert len(H.ordinary_page()) >= H.MB
    assert H.many_tags().count("<span>") == 50_000
    assert H.many_attributes().count(' a="1"') == 100_000
    assert H.unclosed_comment().count("-->") == 0
    assert H.unclosed_script().count("</script>") == 0
    assert H.deep_nesting().count("<div>") == 10_000


@pytest.mark.parametrize("name", sorted(H.PAGES))
def test_a_hostile_page_is_scanned_in_bounded_time(name):
    page = H.PAGES[name]()
    assert H.time_scan(ENGINE, page) < BOUND_SECONDS, name
