"""GLS-SC-041: a script that points a package manager at a host that is not a public registry.

Setting `registry=` (npm, yarn) or `index-url` (pip) in the file the manager reads sends every later
install to the named host. A project setup script that does this under the name of a "corporate
mirror" looks the same as one that does it to steal an install. The rule reads the WRITE: a heredoc,
redirect or tee into the config file whose body sets the registry, an echo/printf of the setting into
that file, a `config set` command, or a variable holding the URL that is then written into the file.

What must stay quiet is as much of the test as what fires: the public registries, the GitHub Packages
host, text that only talks about a registry (documentation), reading the setting, and a flag on one
install command.

Every fixture here is written for this test; none is taken from a published corpus.
"""
import pytest

from sunglasses.engine import SunglassesEngine

RULE = "GLS-SC-041"


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _ids(engine, text, channel="file"):
    return {f["id"] for f in engine.scan(text, channel=channel).findings}


ATTACKS = {
    "heredoc_npmrc": 'cat > "$P/.npmrc" << EOF\nregistry=https://npm.mirror.example.dev\nEOF\n',
    "heredoc_yarnrc": 'cat > .yarnrc << EOF\nregistry: "https://pkgs.internal.example/"\nEOF\n',
    "heredoc_quoted_delimiter": "cat > .npmrc <<'EOF'\nregistry=https://npm.mirror.example.dev/\nEOF\n",
    "heredoc_append": 'cat >> "$P/.npmrc" << EOF\nregistry=http://10.0.0.5:4873\nEOF\n',
    "tee_heredoc": 'tee -a "$P/.npmrc" <<EOF\nregistry=https://x.mirror.example\nEOF\n',
    "echo_append": 'echo "registry=https://pkg.mirror.example/" >> "$P/.npmrc"\n',
    "echo_scoped": 'echo "@corp:registry=https://pkg.mirror.example/" >> .npmrc\n',
    "printf_pip_conf": "printf 'index-url = http://10.0.0.5:8080/simple\\n' > /etc/pip.conf\n",
    "printf_extra_index": "printf '[global]\\nextra-index-url = https://pypi.mirror.example/simple\\n' > pip.conf\n",
    "npm_config_set": "npm config set registry https://npm.mirror.example/\n",
    "npm_config_set_global": "npm config set --global registry http://localhost:4873\n",
    "npm_config_set_scoped": "npm config set @corp:registry https://npm.mirror.example/\n",
    "yarn_berry_set": "yarn config set npmRegistryServer https://npm.mirror.example\n",
    "pnpm_config_set": "pnpm config set registry https://npm.mirror.example/\n",
    "pip_config_set": "pip config set global.index-url https://pypi.mirror.example/simple\n",
    "pip3_config_set_extra": "pip3 config set global.extra-index-url https://pypi.mirror.example/simple\n",
    "variable_then_heredoc": (
        'CORP_REGISTRY="https://npm.internal.example.dev"\n\nif [ -f package.json ]; then\n'
        '  echo "Configuring package manager..."\n  cat > "$PROJECT/.npmrc" << EOF\n'
        "registry=${CORP_REGISTRY}\nEOF\n  cat > \"$PROJECT/.yarnrc\" << EOF\nregistry \"${CORP_REGISTRY}\"\nEOF\nfi\n"
    ),
    "sudo_npm_set": "sudo npm config set registry https://npm.mirror.example/\n",
    "chained_npm_set": "cd app && npm config set registry https://npm.mirror.example/\n",
    "then_branch_npm_set": "if [ -f package.json ]; then npm config set registry https://npm.mirror.example/; fi\n",
    "export_variable_then_heredoc": 'export NPM_REGISTRY="https://npm.mirror.example"\ncat > .npmrc << EOF\nregistry=${NPM_REGISTRY}\nEOF\n',
    "indented_echo_in_function": 'setup() {\n  echo "registry=https://pkg.mirror.example/" >> "$P/.npmrc"\n}\n',
    "indented_heredoc_in_branch": '  if x; then\n    cat > "$P/.npmrc" << EOF\n  registry=https://pkg.mirror.example/\nEOF\n  fi\n',
    "variable_mirror_name": (
        'NPM_MIRROR=https://npm.mirror.example\nmkdir -p out\ncat > .npmrc << EOF\nregistry=$NPM_MIRROR\nEOF\n'
    ),
}

BENIGN = {
    "public_npm_heredoc": 'cat > .npmrc << EOF\nregistry=https://registry.npmjs.org/\nEOF\n',
    "public_yarn_host": 'echo "registry=https://registry.yarnpkg.com" >> .npmrc\n',
    "github_packages_scope": 'echo "@corp:registry=https://npm.pkg.github.com" >> .npmrc\n',
    "pypi_index": "pip config set global.index-url https://pypi.org/simple\n",
    "files_pythonhosted": "pip config set global.extra-index-url https://files.pythonhosted.org/simple\n",
    "npm_config_set_public": "npm config set registry https://registry.npmjs.org/\n",
    "npm_config_get": "npm config get registry\n",
    "npm_config_list": "npm config list\n",
    "readme_prose": "Point your registry=https://npm.mirror.example/ in the project .npmrc to use the company mirror.\n",
    "readme_prose_pip": "Set index-url = https://pypi.mirror.example/simple in pip.conf if your team runs a mirror.\n",
    "install_flag_only": "pip install -r requirements.txt --index-url https://pypi.org/simple\n",
    "redirect_to_other_file": 'echo "registry=https://npm.mirror.example/" > notes.txt\n',
    "auth_token_only": 'echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc\n',
    "variable_public": 'REG="https://registry.npmjs.org"\ncat > .npmrc << EOF\nregistry=${REG}\nEOF\n',
    "variable_not_used_in_config": 'CORP_REGISTRY="https://npm.mirror.example"\necho "mirror is $CORP_REGISTRY"\ncat > notes.txt << EOF\nhello\nEOF\n',
    "reserved_documentation_host": "pip config set global.index-url https://example.org/\n",
    "comment_echo": '# echo "registry=https://npm.mirror.example/" >> .npmrc\n',
    "comment_npm_set": "# npm config set registry https://npm.mirror.example/\n",
    "comment_pip_set": "  # pip config set global.index-url https://pypi.mirror.example/simple\n",
    "comment_heredoc": "# cat > .npmrc << EOF\n# registry=https://npm.mirror.example\n# EOF\n",
    "commented_setting_in_body": 'cat > .npmrc << EOF\n# registry=https://npm.mirror.example\n; registry=https://npm.mirror.example\nEOF\n',
    "comment_variable": '# CORP_REGISTRY="https://npm.mirror.example"\ncat > .npmrc << EOF\nregistry=${CORP_REGISTRY}\nEOF\n',
    "get_with_trailing_comment": "npm config get registry  # npm config set registry https://x.mirror.example\n",
    "js_comment": "// npm config set registry https://npm.mirror.example/\n",
    "yaml_setting_text": "registries:\n  npm:\n    url: https://npm.mirror.example\n",
}


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_the_redirect_is_found(engine, name):
    assert RULE in _ids(engine, ATTACKS[name]), name


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_the_redirect_is_found_on_the_code_channel(engine, name):
    assert RULE in _ids(engine, ATTACKS[name], channel="code"), name


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_benign_text_stays_quiet(engine, name):
    assert RULE not in _ids(engine, BENIGN[name]), name


def test_the_finding_is_blocking_and_names_the_rule(engine):
    result = engine.scan(ATTACKS["variable_then_heredoc"], channel="file")
    assert RULE in {f["id"] for f in result.findings}
    assert result.decision == "block"


def test_a_redirect_far_down_a_long_script_is_found(engine):
    filler = "".join(f"echo step {i}\n" for i in range(2000))
    text = "#!/bin/sh\n" + filler + ATTACKS["heredoc_npmrc"]
    assert RULE in _ids(engine, text)


def test_a_long_script_without_the_write_stays_quiet(engine):
    filler = "".join(f"echo step {i}\n" for i in range(5000))
    assert RULE not in _ids(engine, "#!/bin/sh\n" + filler)


# Stated limits: shapes the rule does not flag, pinned so a change to them is a decision, not an accident.
NOT_FLAGGED_ON_PURPOSE = {
    # The content of a config file seen on its own, with no write around it, is indistinguishable from the
    # documentation example above, so it is not read as a redirect.
    "config_file_content_alone": "registry=https://npm.mirror.example/\n",
    # A variable that is set far from the write (past the 60-line window) is not tied to it.
    "variable_set_far_away": (
        'CORP_REGISTRY="https://npm.mirror.example"\n' + "# pad\n" * 400 + 'cat > .npmrc << EOF\nregistry=${CORP_REGISTRY}\nEOF\n'
    ),
    # Python or Node code that writes the same lines with its own file API is not read by this rule.
    "python_writes_file": 'open(".npmrc", "w").write("registry=https://npm.mirror.example/\\n")\n',
    # The same redirect through an environment variable (a one-command prefix, or an export) is not read: it is how
    # CI files commonly name a mirror, and nothing is written to a config file.
    "env_variable_registry": "export NPM_CONFIG_REGISTRY=https://npm.mirror.example/\n",
    "env_variable_pip_index": "PIP_INDEX_URL=https://pypi.mirror.example/simple pip install -r requirements.txt\n",
    # A variable followed, before the write, by a second registry-named assignment is not tied to the write: the
    # search for the write stops at the next such assignment, which keeps the cost linear in the file size.
    "variable_then_second_variable": (
        'CORP_REGISTRY="https://npm.mirror.example"\nOTHER_MIRROR="https://x.example.org"\ncat > .npmrc << EOF\nregistry=${CORP_REGISTRY}\nEOF\n'
    ),
}


@pytest.mark.parametrize("name", sorted(NOT_FLAGGED_ON_PURPOSE))
def test_stated_limits_are_not_flagged(engine, name):
    assert RULE not in _ids(engine, NOT_FLAGGED_ON_PURPOSE[name]), name


# Round r2: the public-host exemption is read against the URL authority, not against a prefix of the text.
def _shapes(url):
    return {
        "heredoc": "cat > .npmrc << EOF\nregistry=%s\nEOF\n" % url,
        "echo": 'echo "registry=%s" >> .npmrc\n' % url,
        "npm_set": "npm config set registry %s\n" % url,
        "pip_set": "pip config set global.index-url %s\n" % url,
        "variable": 'CORP_REGISTRY="%s"\ncat > .npmrc << EOF\nregistry=${CORP_REGISTRY}\nEOF\n' % url,
    }


# The exempt name is followed by more host (a suffix label), or sits in the user-info part in front of another host.
NOT_THE_PUBLIC_HOST = {
    "suffix_label": "https://registry.npmjs.org.mirror.example/",
    "user_info": "https://registry.npmjs.org@npm.mirror.example/",
    "user_info_port": "https://registry.npmjs.org:80@npm.mirror.example/",
    "pypi_suffix": "https://pypi.org.mirror.example/simple",
    "pypi_user_info_password": "https://pypi.org:pw@npm.mirror.example/simple",
    "third_party_public_mirror": "https://registry.npmmirror.com/",
    "public_name_with_credentials": "https://user:pw@registry.npmjs.org/",
}
PUBLIC_HOST_FORMS = {
    "plain": "https://registry.npmjs.org/",
    "port": "https://registry.npmjs.org:443/",
    "trailing_dot": "https://registry.npmjs.org./",
    "www_subdomain": "https://www.pypi.org/simple",
    "upper_case": "HTTPS://REGISTRY.NPMJS.ORG/",
    "legacy_pypi_host": "https://pypi.python.org/simple",
    "yarn_host": "https://registry.yarnpkg.com",
    "github_packages": "https://npm.pkg.github.com",
    "pythonhosted": "https://files.pythonhosted.org/simple",
}


@pytest.mark.parametrize("shape", sorted(_shapes("x")))
@pytest.mark.parametrize("name", sorted(NOT_THE_PUBLIC_HOST))
def test_a_host_that_only_starts_like_a_public_one_is_found(engine, name, shape):
    text = _shapes(NOT_THE_PUBLIC_HOST[name])[shape]
    assert RULE in _ids(engine, text), (name, shape)


@pytest.mark.parametrize("shape", sorted(_shapes("x")))
@pytest.mark.parametrize("name", sorted(PUBLIC_HOST_FORMS))
def test_the_public_host_in_its_ordinary_spellings_stays_quiet(engine, name, shape):
    text = _shapes(PUBLIC_HOST_FORMS[name])[shape]
    assert RULE not in _ids(engine, text), (name, shape)


R2_ATTACKS = {
    "dockerfile_run": "RUN npm config set registry https://npm.mirror.example/\n",
    "chain_without_space": "cd app&&npm config set registry https://npm.mirror.example/\n",
    "command_wrapper": "command npm config set registry https://npm.mirror.example/\n",
    "absolute_path": "/usr/local/bin/npm config set registry https://npm.mirror.example/\n",
    "quoted_key": 'npm config set "registry" "https://npm.mirror.example/"\n',
    "key_equals_value": "npm config set registry=https://npm.mirror.example/\n",
    "global_flag_first": "npm -g config set registry https://npm.mirror.example/\n",
    "npm_set_short": "npm set registry https://npm.mirror.example/\n",
    "pip_install_section": "pip config set install.index-url https://pypi.mirror.example/simple\n",
    "variable_with_digit": 'MIRROR_REGISTRY2="https://npm.mirror.example"\ncat > .npmrc << EOF\nregistry=$MIRROR_REGISTRY2\nEOF\n',
    "variable_bare_name": 'REGISTRY="https://npm.mirror.example"\ncat > .npmrc << EOF\nregistry=${REGISTRY}\nEOF\n',
    "fifth_body_line": 'cat > .npmrc << EOF\nsave-exact=true\nfund=false\naudit=false\nloglevel=warn\nregistry=https://npm.mirror.example/\nEOF\n',
    "then_on_one_line": "if [ -f package.json ]; then npm config set registry https://npm.mirror.example/; fi\n",
    "indented_after_semicolon": "set -e; npm config set registry https://npm.mirror.example/\n",
    "echo_single_quotes": "echo 'registry=https://npm.mirror.example/' >> .npmrc\n",
    "echo_unquoted": "echo registry=https://npm.mirror.example/ >> .npmrc\n",
    "heredoc_dash": "cat > .npmrc <<-EOF\n\tregistry=https://npm.mirror.example/\nEOF\n",
}

R2_BENIGN = {
    "comment_after_separator": "echo hi; # npm config set registry https://npm.mirror.example/\n",
    "comment_before_separator": "# done && npm config set registry https://npm.mirror.example/\n",
    "comment_after_then": "# if x; then npm config set registry https://npm.mirror.example/\n",
    "comment_pip_after_separator": "true && # pip config set global.index-url https://pypi.mirror.example/simple\n",
    "comment_echo_after_separator": 'cd x; # echo "registry=https://npm.mirror.example/" >> .npmrc\n',
    "log_line_quoted_command": 'echo "run: npm config set registry https://npm.mirror.example/ to use the mirror"\n',
    "log_line_quoted_chain": 'echo "step done; npm config set registry https://npm.mirror.example/"\n',
    "log_line_quoted_redirect": 'echo "wrote registry=https://npm.mirror.example/ >> .npmrc"\n',
    "prose_conditional": "If you need the mirror, then npm config set registry https://npm.mirror.example/ works.\n",
    "backup_echo": 'echo "registry=https://npm.mirror.example/" >> .npmrc.bak\n',
    "backup_heredoc": "cat > .npmrc.orig << EOF\nregistry=https://npm.mirror.example/\nEOF\n",
    "backup_pip_conf": "cat > pip.conf.backup << EOF\nindex-url = https://pypi.mirror.example/simple\nEOF\n",
    "prefixed_file_name": 'echo "registry=https://npm.mirror.example/" >> my.npmrc\n',
    "key_with_longer_name": 'echo "myregistry=https://npm.mirror.example/" >> .npmrc\n',
    "key_with_prefix_name": 'echo "npm_config_registry=https://npm.mirror.example/" >> .npmrc\n',
    "completed_empty_heredoc": "cat > .npmrc << EOF\nEOF\nregistry=https://npm.mirror.example/\n",
    "quoted_delimiter_variable": 'CORP_REGISTRY="https://npm.mirror.example"\ncat > .npmrc << \'EOF\'\nregistry=${CORP_REGISTRY}\nEOF\n',
    "variable_into_backup": 'CORP_REGISTRY="https://npm.mirror.example"\ncat > .npmrc.bak << EOF\nregistry=$CORP_REGISTRY\nEOF\n',
    "setting_after_the_delimiter": "cat > .npmrc << EOF\nsave-exact=true\nEOF\nregistry=https://npm.mirror.example/\n",
}


@pytest.mark.parametrize("name", sorted(R2_ATTACKS))
def test_r2_shapes_are_found(engine, name):
    assert RULE in _ids(engine, R2_ATTACKS[name]), name


@pytest.mark.parametrize("name", sorted(R2_BENIGN))
def test_r2_benign_text_stays_quiet(engine, name):
    assert RULE not in _ids(engine, R2_BENIGN[name]), name


# Stated limits added in r2, each NOT flagged.
R2_NOT_FLAGGED_ON_PURPOSE = {
    # The heredoc opener comes before the redirect.
    "opener_before_redirect": "cat << EOF > .npmrc\nregistry=https://npm.mirror.example/\nEOF\n",
    # The text is piped into tee instead of redirected.
    "pipe_into_tee": 'echo "registry=https://npm.mirror.example/" | tee .npmrc\n',
    # A global option that takes a value in front of the config subcommand.
    "option_with_value": "npm --prefix app config set registry https://npm.mirror.example/\n",
    # A URL held in a variable whose name does not carry registry, mirror or index.
    "generic_variable_name": 'UPSTREAM_URL="https://npm.mirror.example"\ncat > .npmrc << EOF\nregistry=${UPSTREAM_URL}\nEOF\n',
    # The setting more than eight lines into the heredoc body.
    "setting_past_the_window": "cat > .npmrc << EOF\n" + "a=b\n" * 9 + "registry=https://npm.mirror.example/\nEOF\n",
    # Quoting the whole command word.
    "quoted_command_word": "'npm' config set registry https://npm.mirror.example/\n",
    # Printing through a line continuation.
    "continued_command": "npm config set \\\n  registry https://npm.mirror.example/\n",
}


@pytest.mark.parametrize("name", sorted(R2_NOT_FLAGGED_ON_PURPOSE))
def test_r2_stated_limits_are_not_flagged(engine, name):
    assert RULE not in _ids(engine, R2_NOT_FLAGGED_ON_PURPOSE[name]), name
