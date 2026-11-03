#!/usr/bin/env python3
"""
Controlled, safe performance and stress benchmark for Apple Silicon M1 Pro.
Tests:
  1. Multicore CPU Compute Burst (8 workers, 20s)
  2. Memory Ramp & Allocation (allocates 2GB, 4GB, 6GB in RAM, tests swap threshold)
  3. Thermal & Throttling Verification during stress
  4. Post-Stress Recovery Latency
"""

import os
import sys
import time
import math
import subprocess
import multiprocessing
import gc

def get_swap():
    try:
        out = subprocess.check_output(['sysctl', 'vm.swapusage']).decode()
        # used = 0.00M
        import re
        m = re.search(r'used = ([\d\.]+)M', out)
        return float(m.group(1)) if m else 0.0
    except Exception:
        return 0.0

def get_thermals():
    try:
        out = subprocess.check_output(['pmset', '-g', 'therm']).decode()
        throttled = "CPU_Speed_Limit" in out and not "CPU_Speed_Limit = 100" in out
        return "THROTTLED" if throttled else "NOMINAL"
    except Exception:
        return "UNKNOWN"

def cpu_worker(duration, result_queue):
    start = time.time()
    ops = 0
    while time.time() - start < duration:
        _ = math.sqrt(1234567.89) * math.sin(ops)
        ops += 1
    result_queue.put(ops)

def test_cpu_multicore(duration=20):
    num_cores = 8
    print(f"\n[PHASE 1] Multicore CPU Compute Burst ({num_cores} parallel workers for {duration}s)...")
    q = multiprocessing.Queue()
    procs = [multiprocessing.Process(target=cpu_worker, args=(duration, q)) for _ in range(num_cores)]
    
    t0 = time.time()
    for p in procs:
        p.start()
    
    # Sample mid-test thermals and swap
    time.sleep(duration / 2)
    mid_therm = get_thermals()
    mid_swap = get_swap()
    print(f"  -> Mid-test Status: Thermal Pressure: {mid_therm} | Swap: {mid_swap:.1f} MB")
    
    for p in procs:
        p.join()
    t1 = time.time()
    
    total_ops = sum([q.get() for _ in range(num_cores)])
    print(f"  -> Finished {total_ops:,} compute ops in {t1 - t0:.2f}s ({total_ops/(t1-t0):,.0f} ops/sec)")
    print(f"  -> Thermal Throttling: {get_thermals()}")

def test_memory_ramp():
    print("\n[PHASE 2] Memory Ramp Test (Testing RAM Headroom & Swap Threshold)...")
    initial_swap = get_swap()
    print(f"  -> Baseline Swap: {initial_swap:.1f} MB")
    
    chunks = []
    # Test allocating 2GB, 4GB, 6GB in RAM
    target_sizes_gb = [2, 4, 6]
    for size_gb in target_sizes_gb:
        print(f"  -> Allocating buffer to reach ~{size_gb} GB active memory payload...")
        try:
            # Allocate 2GB block (approx 250M integers = ~2GB)
            block = bytearray(2 * 1024 * 1024 * 1024)
            # Touch pages to force physical memory backing
            for i in range(0, len(block), 4096 * 256):
                block[i] = 1
            chunks.append(block)
            time.sleep(1)
            cur_swap = get_swap()
            print(f"     Status at ~{size_gb}GB: Swap used: {cur_swap:.1f} MB | Thermal: {get_thermals()}")
        except MemoryError:
            print(f"     MemoryError reached at {size_gb}GB!")
            break

    print("  -> Releasing memory buffers and running garbage collection...")
    del chunks
    gc.collect()
    time.sleep(2)
    post_swap = get_swap()
    print(f"  -> Post-release Swap: {post_swap:.1f} MB (Delta: {post_swap - initial_swap:.1f} MB)")

def test_recovery():
    print("\n[PHASE 3] System Recovery Latency Check...")
    time.sleep(5)
    load = subprocess.check_output(['sysctl', '-n', 'vm.loadavg']).decode().strip()
    therm = get_thermals()
    swap = get_swap()
    print(f"  -> System Load Averages : {load}")
    print(f"  -> Thermal State        : {therm}")
    print(f"  -> Active Swap          : {swap:.1f} MB")

def main():
    print("=" * 65)
    print("      M1 Pro Apple Silicon Workstation Stress & Capability Test   ")
    print("=" * 65)
    test_cpu_multicore(duration=20)
    test_memory_ramp()
    test_recovery()
    print("=" * 65)
    print("Stress test completed successfully.")

if __name__ == '__main__':
    main()
