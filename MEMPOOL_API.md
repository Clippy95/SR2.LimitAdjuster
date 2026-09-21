# Mempool API v1

`SR2LA_GetMempoolApi(uint32_t version)` exports a stable C ABI from the Win32 ASI.
Request version 1 and check the returned version/size/function pointer before use.
Unsupported versions return null. The layout is in `SR2.LimitAdjuster/MempoolApi.h`.

`ensure_empty_capacity(pool, minimum_bytes, reserve_bytes, growth_granularity)`
returns 1 on success and 0 when the request cannot be satisfied. Invoke it on the
native pool's owning thread. Only native mempool/split_mempool layouts are allowed,
with zero front used/mark and both back cursors equal to capacity. First registration
can replace empty backing memory; subsequent commitment keeps the reserved base
stable. Existing reservations are not relocated or enlarged. This API uses the
same registry/lock as the allocator hooks, and updates both back cursors on growth.
It never installs per-mod city hooks or chooses a mod's pool sizes.

Clients resolve the export after ASI initialization. There is no cross-module
STL ownership or requirement to link this project's C++ functions. Explicit empty
capacity requests work independently of automatic allocation interception.
`DynamicMempools` continues to control that automatic interception and the general
cutscene virtual-pool reservation/page-budget extension.
