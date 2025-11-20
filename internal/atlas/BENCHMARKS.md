# Atlas Performance Benchmarks

This document contains performance benchmark results for the Atlas vulnerability scanner. These benchmarks establish baseline performance metrics for pre-alpha testing.

## Test Environment

- **CPU**: Intel(R) Xeon(R) CPU @ 2.60GHz (16 cores)
- **Go Version**: 1.24.7
- **OS**: Linux (amd64)
- **Date**: Pre-Alpha Testing Phase

## Module Performance Benchmarks

### SQLi Module

| Benchmark | Ops | Time/Op | Memory/Op | Allocs/Op |
|-----------|-----|---------|-----------|-----------|
| SingleTarget | 434 | 3.04ms | 135KB | 1,063 |
| 100Targets | 4 | 321ms | 11.9MB | 104,503 |
| VulnerableTarget | 6,049 | 183μs | 9.9KB | 118 |
| NonVulnerableTarget | 382 | 3.21ms | 131KB | 1,051 |
| MultipleParameters | 69 | 16.2ms | 704KB | 5,678 |
| ErrorBasedDetection | 5,748 | 176μs | 10KB | 118 |
| BooleanBasedDetection | 1,116 | 1.24ms | 50KB | 591 |
| ParallelScanning | 888 | 1.38ms | 144KB | 1,104 |

**Key Findings**:
- Single target scans complete in ~3ms
- Vulnerable target detection is very fast (~183μs) due to early termination
- 100 target scan completes in ~321ms (~3.2ms per target)
- Memory usage scales linearly with target count

### XSS Module

| Benchmark | Ops | Time/Op | Memory/Op | Allocs/Op |
|-----------|-----|---------|-----------|-----------|
| SingleTarget | 403 | 2.97ms | 132KB | 1,552 |
| 100Targets | 4 | 300ms | 13.2MB | 155,186 |
| VulnerableTarget | 5,199 | 203μs | 10.8KB | 126 |
| ReflectedDetection | 5,190 | 202μs | 11.1KB | 126 |
| MultipleParameters | 90 | 11.8ms | 554KB | 6,673 |
| HTMLContextDetection | 5,392 | 203μs | 11KB | 126 |
| ScriptContextDetection | 5,679 | 199μs | 11.2KB | 127 |
| NonVulnerableTarget | 4,980 | 208μs | 10.9KB | 128 |
| ParallelScanning | 714 | 1.70ms | 183KB | 1,795 |

**Key Findings**:
- Single target scans complete in ~3ms
- XSS detection is very fast (~200μs) regardless of context
- 100 target scan completes in ~300ms
- Slightly higher allocation count than SQLi due to more payload variations

### SSRF Module

| Benchmark | Ops | Time/Op | Memory/Op | Allocs/Op |
|-----------|-----|---------|-----------|-----------|
| SingleTarget | 910 | 1.14ms | 48.5KB | 568 |
| 100Targets | 10 | 115ms | 4.8MB | 56,224 |
| VulnerableTarget | 873 | 1.18ms | 51.7KB | 588 |
| CloudMetadataDetection | 850 | 1.23ms | 52.9KB | 588 |
| LocalFileAccess | 1,501 | 770μs | 35.6KB | 411 |
| MultipleParameters | 337 | 3.29ms | 156KB | 1,835 |
| NonVulnerableTarget | 915 | 1.15ms | 51.5KB | 592 |
| InternalNetworkDetection | 861 | 1.34ms | 51.5KB | 592 |
| ParallelScanning | 1,621 | 658μs | 67.2KB | 651 |

**Key Findings**:
- SSRF module is faster than SQLi/XSS (~1.1ms per target)
- Lower memory usage due to fewer payloads
- 100 target scan completes in ~115ms (~1.15ms per target)
- Most efficient module in terms of memory and speed

## Orchestrator Performance Benchmarks

| Benchmark | Ops | Time/Op | Memory/Op | Allocs/Op |
|-----------|-----|---------|-----------|-----------|
| StartScan | 332 | 10.8ms | 3.7KB | 37 |
| 1000URLs | 1 | 1.31s | 340KB | 4,066 |
| MultipleModules | 10 | 101ms | 7.2KB | 86 |
| StartStop | 922 | 1.27ms | 3.8KB | 37 |

**Key Findings**:
- Scan startup overhead is minimal (~10.8ms)
- 1000 URLs processed in ~1.3s with 20 concurrent workers
- Multiple modules add minimal overhead (~101ms for 5 modules)
- Start/stop cycles are very efficient (~1.27ms)

## Deduplication Performance Benchmarks

| Benchmark | Ops | Time/Op | Memory/Op | Allocs/Op |
|-----------|-----|---------|-----------|-----------|
| Deduplication (1000 findings) | 1,504 | 791μs | 645KB | 5,983 |
| GenerateFingerprint | 6,733,147 | 357ns | 224B | 4 |
| 10000Findings | 333 | 8.07ms | 6.2MB | 52,031 |
| HighDuplication (80%) | 501 | 4.54ms | 3.3MB | 26,022 |
| ConfidenceUpgrade | 3,148 | 709μs | 614KB | 5,745 |
| LargeDataset (20000) | 187 | 13.0ms | 12.3MB | 106,048 |

**Key Findings**:
- Fingerprint generation is extremely fast (~357ns)
- Deduplication scales well: 10,000 findings in ~8ms
- High duplication rate (80%) reduces processing time by ~43%
- Memory usage scales linearly with unique findings

## Storage Performance Benchmarks

| Benchmark | Ops | Time/Op | Memory/Op | Allocs/Op |
|-----------|-----|---------|-----------|-----------|
| StoreScan | 1,000,000 | 4.31μs | 621B | 3 |
| GetScan | 4,919,920 | 215ns | 480B | 1 |
| StoreFinding | 1,283,182 | 967ns | 508B | 2 |
| ConcurrentOperations | 95,553 | 16.7μs | 14.2KB | 31 |

**Key Findings**:
- Storage operations are very fast (sub-microsecond)
- GetScan is extremely efficient (215ns)
- Concurrent operations handle well under load
- Memory usage is minimal per operation

## Additional Benchmarks

| Benchmark | Ops | Time/Op | Memory/Op | Allocs/Op |
|-----------|-----|---------|-----------|-----------|
| CVSSCalculation | 19,399,861 | 63ns | 0B | 0 |
| FalsePositiveDetection | 1,368,345 | 915ns | 288B | 9 |
| EventBus | 1,000,000 | 1.02μs | 0B | 0 |
| ScanProgress | 566,551,873 | 2.09ns | 0B | 0 |
| FindingAggregation | 24,484 | 50.1μs | 22.4KB | 83 |

## Performance Summary

### Throughput Metrics

- **Single Target Scanning**:
  - SQLi: ~330 targets/sec
  - XSS: ~340 targets/sec
  - SSRF: ~880 targets/sec

- **Batch Scanning** (100 targets):
  - SQLi: ~3.1 targets/sec/module
  - XSS: ~3.3 targets/sec/module
  - SSRF: ~8.7 targets/sec/module

- **Large Scale** (1000 URLs):
  - Orchestrator: ~765 URLs/sec (20 concurrent workers)

### Memory Characteristics

- **Per-Target Memory**:
  - SQLi: ~135KB/target
  - XSS: ~132KB/target
  - SSRF: ~48KB/target

- **Finding Deduplication**:
  - 10,000 findings: ~6.2MB
  - 20,000 findings: ~12.3MB
  - Scales linearly with unique finding count

### Optimization Opportunities

1. **SQLi Module**: Multiple parameters cause significant overhead (16ms vs 3ms). Consider batching parameter tests.
2. **XSS Module**: Similar parameter overhead. Potential for payload optimization.
3. **Deduplication**: Already very efficient. No optimization needed for pre-alpha.
4. **Storage**: Extremely fast. No optimization needed.

## Performance Targets (Pre-Alpha)

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Single Target (SQLi) | 3ms | <5ms | ✅ PASS |
| Single Target (XSS) | 3ms | <5ms | ✅ PASS |
| Single Target (SSRF) | 1.1ms | <5ms | ✅ PASS |
| 100 Targets | 300ms | <500ms | ✅ PASS |
| 1000 URLs | 1.3s | <5s | ✅ PASS |
| Memory/Target | <150KB | <200KB | ✅ PASS |
| Deduplication (10K) | 8ms | <50ms | ✅ PASS |

## Conclusion

All performance benchmarks meet or exceed pre-alpha targets:

- ✅ Module performance is excellent across all vulnerability types
- ✅ Orchestrator handles large-scale scans efficiently
- ✅ Deduplication is highly optimized
- ✅ Memory usage is well-controlled
- ✅ Storage operations are sub-microsecond

**Recommendation**: Atlas is ready for pre-alpha testing from a performance perspective.

## Running Benchmarks

To run all benchmarks:

```bash
# Module benchmarks
go test -bench=. -benchmem ./internal/atlas/modules/

# Core benchmarks
go test -bench=. -benchmem ./internal/atlas/

# Specific benchmark
go test -bench=BenchmarkSQLiModule_SingleTarget -benchmem ./internal/atlas/modules/

# Compare results
go test -bench=. -benchmem ./internal/atlas/... > before.txt
# ... make changes ...
go test -bench=. -benchmem ./internal/atlas/... > after.txt
benchcmp before.txt after.txt
```

## Benchmark Maintenance

- Run benchmarks before major releases
- Compare results with previous baselines
- Investigate regressions >10%
- Update this document with new findings
- Add new benchmarks for new features
