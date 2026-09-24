# VERDICT — GLS-SD-010-EMB @ @HEAD@ (base @BASE@)
(stub; edit this file, do not create another)

- [ ] 0 manifest read
- [ ] 1 head matches @HEAD@ and the §2 digests
- [ ] 2 p1 baseline
- [ ] 3 p2 fixture matrix
- [ ] 4 p3 corpus sweep (accepted vs unbooked)
- [ ] 5 p4 variant trees (control first)
- [ ] 6 p5 ratio
- [ ] 7 p6 robustness rows, designated variant per row
- [ ] 8 p8 evaluation modes
- [ ] 9 p7 with YOUR OWN cases — the part that has found the most
- [ ] 10 §5 what is stated rather than claimed
- [ ] 11 p9 decoder readings (round 10 probes + your ```decode blocks)

## verdict
PENDING

---
## Your cases go here as fenced ```case JSON, run with
##   zsh @OUT@/probes/p7-constructed.sh value --cases-from-verdict
## Placeholders: {NAME} {NAME_LC} {VALUE} {URL}

## Spellings to decode go here as fenced ```decode JSON, run with
##   zsh @OUT@/probes/p9-decode.sh

```decode
{"name":"example-delete-me","spelling":"\\N{LINE FEED}"}
```

```case
{"name":"example-delete-me","expect":"block","why":"shows the shape; replace with your own","text":"{\"cfg\":\"{NAME}={VALUE}\"}","channel":"file"}
```
