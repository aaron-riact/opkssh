---
name: implementCachingLayer
description: Implement a disk-based caching layer for external service calls with fallback logic
argument-hint: Describe the external service/API being cached and any specific requirements
---
Implement a caching layer for external service calls with the following characteristics:

## Core Requirements
1. **Disk-based persistence** - Cache responses to disk for resilience across restarts
2. **Atomic writes** - Use a staging pattern (e.g., `downloading/` → `done/`) to prevent corrupted reads
3. **Timestamped entries** - Store cache entries with timestamps for freshness tracking
4. **Configurable expiration** - Support max cache age and retention period settings

## Fallback Logic
Implement a multi-tier fallback strategy:
1. Fresh cache (within max age) → use immediately
2. Cache miss or stale → attempt network refresh
3. Network failure → fall back to stale cache if available
4. All else fails → fall back to "eternal" backup (break-glass scenario)

## Additional Features
- **Jitter** - Add random delay to refresh timing to prevent thundering herd
- **Cleanup** - Automatically remove cache entries older than retention period
- **Configuration** - Make caching configurable via the project's config system
- **Logging** - Add appropriate warning/info logs for cache hits, misses, and fallbacks

## Integration Pattern
- Create the caching wrapper as a separate package/module
- Inject the cached client via options/configuration rather than hardcoding
- Maintain backward compatibility by making caching optional
- Add tests that verify cache behavior without requiring the actual external service

Analyze the existing codebase to understand:
- How external service calls are currently made
- The configuration system in use
- Existing patterns for dependency injection
- Test patterns used in the project

Then implement the caching layer following the project's conventions.
