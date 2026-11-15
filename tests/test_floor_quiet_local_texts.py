"""The quiet list against reviewed ordinary files that live on one machine (hashes only; no text in the repo).

The files are the ones listed in a local manifest: a tab-separated file with the columns
set, sha256, bytes, path. A file is used only if its bytes still hash to the pinned value; a hash with no
such file on this machine is skipped, so on any other machine this module skips whole. Set
SUNGLASSES_NATURAL_MANIFEST to point at the manifest; with no such variable the module skips whole.

  FP_ALLOW      reviewed ordinary files that must decide allow,
  RIGHT_HELD    reviewed files the label calls right: they keep their quarantine,
  RIGHT_ALLOW   reviewed files the label calls right whose rule is now on the list: they decide allow,
                the same decision as the release before the floor existed.

One reviewed ordinary file gets its decision from a secret-pattern rule, not from a floor copy, so it is on none of
these lists and is not pinned here either way.
"""
import hashlib
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
import sys                                                               # noqa: E402
sys.path.insert(0, ROOT)

from sunglasses.engine import SunglassesEngine                           # noqa: E402

MANIFEST = os.environ.get("SUNGLASSES_NATURAL_MANIFEST", "")

FP_ALLOW = (
    "2bb360b1542c822abab48663b043aa38cc3cc25e25d0b7a1262427379f521e98",
    "3c799ff26530441c43a903919d330fefe6f40733a9a2fc7b0434c8d2a762286f",
    "3d5ebad6618eb43c0edef1841bc118e4a93a259fda0e1149a2a41133bb784d89",
    "415ccde13f14428525a791b914342c59cb02c7b9beab8e97abc891301e222b5d",
    "4ce1f126d19f771ff48f1dc8b0beaa6534aff4121fac39875520a9b298d126c1",
    "6ed06ac06d4fbde636ed60d0b115e5fba581910a3e2c4b420c3db7f25dd33658",
    "7d8b830473aace5cf0983713011909dda800dbd8721f95b049f7c7e4f6c0e4e5",
    "80fb4369a349447cf18ecdd7494fe7938b6065377e9f08c077cec411093a3007",
    "87d864570220b699fac52da309d2d6efdb060647bfebc74f768128e646accf80",
    "8adbdc5c936b417b45a6a6ee9f0f55b72e37c717c21ba0ee2da486e931f3d26b",
    "c99fc1de25d3965c5ffb6d24622456b53b31c3f3379fa0a6b02d55d12ecf5a3a",
    "d5f0454724a1036091bdc5aba941e336089aac9add1bbf46109544b68c9e0fbf",
    "d662fe345bd3965c5e8bb93e6b7b910015e0e2c0b7ef10eeb68c6d65b581fcd1",
    "f0530b5fa832df92360ccf3b6ce4d7c23f478a84c9a86c49f461411e76c616f8",
    "f20ec268c01d2f15fecf0dccbb50ec18e8abd8b741e63c2ade8c61bf5b086a54",
)

RIGHT_HELD = (
    "0a78b825105eb17fb42db4c912518a9b58dcffb8d2cff79ae32c7e416d2bb0cc",
    "0acce5f22d22df1007da557f191508461539a5b27c6daabeed56c921624502ef",
    "10697a5640238d8a0e21a26e4520398d228a7e85b761b7f3ae84885c278d2eb2",
    "161f48884f5b6a083539f1c838f23c73d964e9b97646e480ac2f56e01a5b229f",
    "1e1717f7c1a21ca1c66f660781b470482fd0708dbff86d63cea1b1fcbe833f30",
    "1e8a6d40d03eb67dbb68984d8f7826a04c0d51ed4a427c63a05a7d875693680a",
    "2b87f0c031d077725e04fd35c6ea7f3d05b93d15388f520ce1b538925ad3668b",
    "2bfde75805ac8b41827a8c4eda2540c8f4b1c2a032232e2f9801f6ab96025fa6",
    "30d056256cf324e8f8c7bd9b8feec2419a1e5fcd6564bb02207cb4340d23d6ee",
    "37335c91b6e62012179c45aef000b648bf77f97db53934971979cb2e40b355cc",
    "42f4958f5072fede34644fb680c596bdc5c9f6486143250a43b2251d2970fce4",
    "43600d1f79760f930534dab2cbbeb966023c526210495218f64edfe9ecfc2a3d",
    "499c736860ca654212d51da4d827a31596accaef49d6b6cbfdc313e45c3a32b1",
    "4ee09c3c04cd932175a5904c1e518ade4c5d413ca2263f556b201e55faeca278",
    "5269036388f2d8571e4a3f6c9c5ed4e52d409fcdbf1cfb3c61b89b8a2f988f24",
    "5b9746739ce833f4276b13d03a2e95f85dfbad64cf6299a0391522762cde79e9",
    "61c4107ea8f5136391e836df0cb1ea12146271befee8c3271cf299ffab451215",
    "7247993b5d1affd27d90549208329b2b44a4cd3bf70999673593f1bdf5cab5fb",
    "83f1da8fbe580b997484e5285f26942552b7f06d9f39092fdb2d2aeed0dc70bd",
    "8d47d1bfc4410fb3868072f57aa87778d5cd8c862103cc8021749375ba019067",
    "93018b969b38919f928aa51ce0eec7c7f6712f8e75b7c04137242bb00b565441",
    "973430d5d62cedf91094094bd14db529366ac6db8288abdfd4117708b2c21054",
    "9a18708efb1342c8b29d8132081f20b673b4678ebf203ce5201de84108b031b0",
    "9da0c878a5641427fb887bac559d0768eba43911f2bf714f39772b0cf946f6c1",
    "a1890b7e89e090c3c2c1d661151f830fe85be1be22cfb8e28155c9b80f55b0d0",
    "b63f2aa4bcb87dbb18c9167c9b0138895d3d0d8ff46c5d2a0bae42d73e1619ea",
    "bd38513728d70a9275504418f686f78f6d3553915078d89c7f6c2bef319ff4cb",
    "c0a9fa510c5fc950f46cb85d581b31a1137b190c49418df716b074f3e6fc4371",
    "c45161582b24347578e37cd4bc441c8c6cb7d4baa205b331f03ba7e5a6cf9d4d",
    "cf3fbadcc0c85df1a4ba6d214dd78a0017af77b14175bde90fba20e393845c0f",
    "d1c507fe1950967a651fd4d18f9d94b4e3601b6331d74c1d20da9f63f84f87d0",
    "dc05a120ee36e5cab6b8057d7dc5b71894a28b1b3b0b875de942ba509c9d8a22",
    "df2ca079c9bf5d228f9687ea934d85a025edd3e49b631f8c31ecfea09548f714",
    "e3718128a90f172756e02921decab7d5a3b21c5f716ce4701404991835d6dd67",
    "f71541e882bf102f2a30d2f9640c2dc195884f8918e9064c378f3bceb347e025",
    "fa1e9f2dd960aa98b5714d416c71c3e4097c2b6799552d285d0d1ee28728e1a2",
)

RIGHT_ALLOW = (
    "3ec9b5bf2beb4d8b606a0701450fd71558248c519963e976fc1710c1ad36459f",
    "7d1a386336d6e489c61b7984e7e4c6a452b1a2ad5c4a9f43ff362a5c28adbfca",
    "ed104b65d1c5e000cfab26e3deaaa02af0f7279723af9e4a735c90fe5473af5c",
)

def _local_files():
    """sha256 -> path, for rows of the manifest whose file is here and still hashes to the pinned value."""
    found = {}
    if not MANIFEST or not os.path.isfile(MANIFEST):
        return found
    with open(MANIFEST, encoding="utf-8") as handle:
        for line in handle:
            cols = line.rstrip("\n").split("\t")
            if len(cols) < 4 or cols[0] == "set" or cols[1] in found:
                continue
            try:
                with open(cols[3], "rb") as body:
                    data = body.read()
            except OSError:
                continue
            if hashlib.sha256(data).hexdigest() == cols[1]:
                found[cols[1]] = cols[3]
    return found


LOCAL = _local_files()


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _decision(engine, digest):
    path = LOCAL.get(digest)
    if path is None:
        pytest.skip("file not on this machine")
    with open(path, "rb") as handle:
        text = handle.read().decode("utf-8", "replace")
    return engine.scan(text, channel="file").decision


@pytest.mark.parametrize("digest", FP_ALLOW)
def test_a_reviewed_ordinary_file_decides_allow(engine, digest):
    assert _decision(engine, digest) == "allow"


@pytest.mark.parametrize("digest", RIGHT_HELD)
def test_a_reviewed_right_file_keeps_its_quarantine(engine, digest):
    assert _decision(engine, digest) == "quarantine"


@pytest.mark.parametrize("digest", RIGHT_ALLOW)
def test_a_reviewed_right_file_on_the_list_decides_allow(engine, digest):
    assert _decision(engine, digest) == "allow"
