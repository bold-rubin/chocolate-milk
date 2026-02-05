#### analyze monitor stats
extract all the tarball from fuzzing to a folder then run this
```bash
 python count_monitor_freq.py aijon_stuff/<afl-extracted folder> ./aflpp_monitor/ -j 10 --fuzzer aflpp

 python count_monitor_freq.py aijon_stuff/<ijon-extracted folder> ./ijon_monitor/ -j 10 --fuzzer ijon
```

#### generate heatmap
after generate monitor stats for afl and ijon
name them bug_breakdown.json and afl_bug_breakdown.json the order is enforced. (IMPORTANT!!!)
fuzzer1 will read in afl_bug_breakdown.json and fuzzer2 will read in bug_breakdown.json

```bash
python bug_trial_heatmap.py afl_bug_breakdown.json bug_breakdown.json --fuzzer1 AFL --fuzzer2 IJON
```
