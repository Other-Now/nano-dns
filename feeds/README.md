# feeds/

Real data, downloaded by `scripts/fetch-feeds.sh` and not committed:

| file | what | rules / rows | licence |
|---|---|---|---|
| `hagezi-tif-medium.rpz` | HaGeZi Threat Intelligence Feeds, medium (RPZ) | ~733k | GPL-3.0 |
| `urlhaus-filter.rpz` | malware-filter's RPZ build of abuse.ch URLhaus | ~2k | CC0 (data) / MIT |
| `top-1m.csv` | Tranco top-1M sites | 1M | free to use, cite Tranco |

abuse.ch retired its own free RPZ and hostfile downloads in 2026 (HTTP 410),
which is why the URLhaus data comes through the malware-filter mirror.

`policy.example.json` maps subscribers to profiles:

    ./nanodns serve -policy feeds/policy.example.json
