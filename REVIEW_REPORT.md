# Review of "mm/memcontrol: fix integer overflow in calculate_high_delay()"

**Patch Author:** zhang jiao <zhangjiao2@cmss.chinamobile.com>

---

## Summary

The patch fixes two distinct but related bugs in `calculate_high_delay()`:

1. **u64 overflow** — `max_overage * max_overage * HZ` wraps u64 when `max_overage >= ~2^27–2^29` (depending on `HZ`), yielding a small or zero penalty that bypasses throttling entirely. This is a denial-of-service vector.
2. **32‑bit truncation** — The `unsigned long penalty_jiffies` intermediate truncates the u64 product on 32‑bit kernels before the right-shifts, which can also zero the result.

The fix caps `max_overage` at `(1 << 20)` before squaring and changes the intermediate type from `unsigned long` to `u64`.

---

## 1. Bug Analysis (correct)

### 1.1 Overflow conditions

`max_overage` is a u64 returned by `calculate_overage()`:

```
max_overage = ((usage - high) << 20) / high
```

`calculate_high_delay()` then computes:

```
penalty_jiffies = max_overage^2 * HZ   // u64 arithmetic
penalty_jiffies >>= 20  // MEMCG_DELAY_PRECISION_SHIFT
penalty_jiffies >>= 14  // MEMCG_DELAY_SCALING_SHIFT
return penalty_jiffies * nr_pages / MEMCG_CHARGE_BATCH;
```

**Overflow threshold (u64):**  
`max_overage^2 * HZ > U64_MAX`  
→ `max_overage > sqrt(U64_MAX / HZ)`  
→ `max_overage > ~2^27` (for `HZ=1000`) or `~2^29` (for `HZ=100`).

Given `max_overage ≈ (usage/high) << 20`, overflow occurs when `usage/high >= 2^7` (128×, for HZ=1000) or higher. This is easily reachable with a small `memory.high` and a large workload — the author's example (`memory.high=1MB`, GB‑scale allocations) is a clean trigger.

When overflow wraps the product below `HZ/100`, the early-exit in `__mem_cgroup_handle_over_high()` fires and no throttling occurs. This is correctly identified as exploitable for denial of service.

**32‑bit truncation:**  
On 32‑bit, `unsigned long` is 32 bits. The u64 product is truncated on assignment, then the right-shifts operate on the truncated value. Even without u64 overflow, a product in the range `[2^32, 2^64)` gets silently zeroed or reduced to a small value.

### 1.2 Both bugs are real and the patch correctly identifies them

The analysis in the commit message is accurate.

---

## 2. Fix Assessment

### 2.1 Cap at `(1 << 20)` — correct and lossless

The cap ensures `max_overage ≤ 2^20`, so `max_overage^2 ≤ 2^40` and `max_overage^2 * HZ ≤ 2^50` — well within u64 range (for `HZ ≤ 1000`). This prevents the u64 overflow regardless of `HZ`.

**Losslessness justification:**  
After the two right-shifts (34 bits total), a capped `max_overage = 2^20` yields:

```
penalty_jiffies = 2^40 * HZ >> 34 = 64 * HZ
```

After the `nr_pages` scaling (`penalty_jiffies * nr_pages / MEMCG_CHARGE_BATCH`):

```
final = 64 * HZ * nr_pages / 64 = HZ * nr_pages
```

In practice, `nr_pages ≥ MEMCG_CHARGE_BATCH (= 64)` because `memcg_nr_pages_over_high` is always incremented by at least `batch = max(64, nr_pages_alloc)`. Therefore `final ≥ 64 * HZ`, which exceeds `MEMCG_MAX_HIGH_DELAY_JIFFIES (2*HZ)`. The result is clamped before use. Cap is lossless.

*Edge case*: If `nr_pages < 64` (theoretically possible if the function is called from some non‑standard path), the final penalty before clamping could be `HZ`. This is still > `HZ/100` (so no early-exit), and 1 second of penalisation per batch is meaningful throttling. No information-theoretic loss matters because the clamp already controls the maximum.

### 2.2 `u64` intermediate — correct

Changing `penalty_jiffies` from `unsigned long` to `u64` ensures the right-shifts operate on the full 64‑bit value on 32‑bit architectures. The multiplication `penalty_jiffies * nr_pages / MEMCG_CHARGE_BATCH` is also evaluated in 64‑bit arithmetic (u64 promotes `unsigned int` operands). The final truncation to `unsigned long` (return type) is safe because the value after shifts is at most ~`HZ * nr_pages`, which fits in 32 bits for all reasonable inputs.

### 2.3 Code placement

The `min_t()` is inserted after the existing comment and before the multiplication — the natural place. The comment extension is appended to the existing block comment (before the `*/`), which is correct in kernel style.

One minor note: the added comment says "exponentially increase" but the function is quadratic (`max_overage²`), not exponential. This is inherited from the pre-existing comment, not introduced by the patch, so it's not a defect in this change.

---

## 3. Potential Concerns / Nitpicks

### 3.1 `min_t(u64, ...)` vs `min(...)`

The use of `min_t(u64, ...)` is safe but slightly unusual. Both `max_overage` (already `u64`) and `1ULL << 20` (unsigned long long → u64) are u64, so a plain `min()` would work without type confusion. However, `min_t` is not wrong and is arguably more explicit. No action needed.

### 3.2 Conservative cap

The overflow threshold for u64 is `max_overage ≥ ~2^27–2^29` (HZ-dependent). The cap at `2^20` is 128–512× more conservative than necessary for overflow prevention. This is fine because (a) the result is clamped anyway, and (b) a lower cap provides a larger safety margin against future code changes (e.g., different `HZ` values, different shift counts). Not a problem.

### 3.3 The `swap_find_max_overage()` path

The same overflow bug exists in the swap overage path (`calculate_high_delay(nr_pages, swap_find_max_overage(memcg))`). The patch fixes it there too since `calculate_high_delay()` is the shared code path. Good.

### 3.4 Global search for similar patterns

A search for `*_overage * *_overage * HZ` in the kernel tree found only the single instance in `calculate_high_delay()`. No other code has this exact overflow pattern.

---

## 4. Testing considerations

The following test scenarios would confirm the fix:

| Scenario | Expected behaviour |
|---|---|
| `memory.high=1MB`, allocate 4GB+ | Task is throttled (sleeps up to 2s per batch). Before fix: no throttle, allocation proceeds at full speed. |
| `memory.high=1MB`, allocate 512MB (moderate overage) | Penalty curve unchanged (same as before for all inputs below the cap). |
| Cross-compile for 32‑bit, same test | No regression; throttling works on 32‑bit for all overage levels. |
| `memory.high` set very high (no overage) | Zero penalty, no throttle — unchanged. |
| Swap overage path (if swap.high is set) | Same overflow protection applies. |

---

## 5. Conclusion

**The patch is correct and should be merged.**

It fixes a real security‑relevant bug (unbounded memory allocation via overflow bypass of memory.high throttling) and a secondary 32‑bit correctness bug. The fix is minimal, well‑reasoned, and provably lossless. The code style is consistent with the surrounding kernel code.

**Reviewed-by:** (reviewer name/email can go here)

---

## Appendix: Full revised function for reference

After the patch, `calculate_high_delay()` will read:

```c
static unsigned long calculate_high_delay(unsigned int nr_pages,
					  u64 max_overage)
{
	u64 penalty_jiffies;

	if (!max_overage)
		return 0;

	/*
	 * We use overage compared to memory.high to calculate the number of
	 * jiffies to sleep (penalty_jiffies). Ideally this value should be
	 * fairly lenient on small overages, and increasingly harsh when the
	 * memcg in question makes it clear that it has no intention of stopping
	 * its crazy behaviour, so we exponentially increase the delay based on
	 * overage amount.
	 *
	 * Cap max_overage before squaring to prevent integer overflow that
	 * could otherwise wrap the penalty to zero and bypass throttling.
	 * Use a u64 intermediate so the right-shifts are not truncated on
	 * 32-bit kernels.  Any overage large enough to hit the cap already
	 * produces a penalty well above MEMCG_MAX_HIGH_DELAY_JIFFIES, which
	 * the caller enforces regardless, so capping is lossless.
	 */
	max_overage = min_t(u64, max_overage, 1ULL << 20);

	penalty_jiffies = max_overage * max_overage * HZ;
	penalty_jiffies >>= MEMCG_DELAY_PRECISION_SHIFT;
	penalty_jiffies >>= MEMCG_DELAY_SCALING_SHIFT;

	/*
	 * Factor in the task's own contribution to the overage, such that four
	 * N-sized allocations are throttled approximately the same as one
	 * 4N-sized allocation.
	 *
	 * MEMCG_CHARGE_BATCH pages is nominal, so work out how much smaller or
	 * larger the current charge patch is than that.
	 */
	return penalty_jiffies * nr_pages / MEMCG_CHARGE_BATCH;
}
```
