"""Select delivery by its branch; yield value syntax is deliberately irrelevant.
Notification: branch containing notification_supported; initialize: branch whose
condition calls expected_method; ordinary response: yield directly in the loop.
Missing/ambiguous sites are instrument errors, never behavioral mutation kills.

Vendored at the #178 round-2 rebase. ASTRA wrote it for round 9 and it lived in
a review directory, so the three controls that import it could not be collected
here -- which is how RC34, RC35 and RC36 came to be absent from the archive
while everyone believed they ran. Bytes recovered from the round-9 transcript,
not rewritten from the description.
"""
import ast
import inspect


def delivery_line(module, kind='response'):
    return delivery_line_in_source(inspect.getsource(module), kind)


def delivery_line_in_source(source, kind='response'):
    tree = ast.parse(source)
    funcs = [n for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef) and n.name == 'read_upstream']
    assert len(funcs) == 1, 'instrument: reader is ambiguous'
    loops = [n for n in funcs[0].body if isinstance(n, ast.For)]
    assert len(loops) == 1, 'instrument: loop is ambiguous'
    body = loops[0].body
    if kind != 'response':
        anchor = {'notification': 'notification_supported',
                  'initialize': 'expected_method'}[kind]
        branches = [n for n in body
                    if isinstance(n, ast.If)
                    and any(isinstance(x, ast.Call)
                            and isinstance(x.func, ast.Attribute)
                            and x.func.attr == anchor
                            for x in ast.walk(n if kind == 'notification' else n.test))]
        assert len(branches) == 1, 'instrument: branch is ambiguous'
        body = branches[0].body
    sites = [n.value for n in body
             if isinstance(n, ast.Expr) and isinstance(n.value, ast.Yield)]
    assert len(sites) == 1, 'instrument: delivery site is ambiguous'
    return sites[0].lineno
