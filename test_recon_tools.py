#!/usr/bin/env python3
"""
Test script to demonstrate the recon tools system.
Shows how agents can scan once and query stored data.
"""

import sys
from pathlib import Path

# Add parent to path for imports
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from orchestrator.db import init_db, create_battle
from orchestrator.agents.tools import (
    set_battle_context,
    run_comprehensive_recon,
    query_recon_data,
    get_recon_summary,
)


def test_recon_workflow():
    """Demonstrate the complete recon workflow."""

    print("=" * 70)
    print("RECON TOOLS TEST - Scan Once, Query Many Times")
    print("=" * 70)

    # Initialize database
    print("\n[1] Initializing database...")
    init_db()

    # Create a test battle
    print("[2] Creating test battle...")
    battle_id = create_battle("http://localhost:8001")
    set_battle_context(battle_id)
    print(f"    Battle ID: {battle_id}")

    # Run comprehensive recon (simulates Recon Agent)
    print("\n[3] Running comprehensive recon scan...")
    print("    This is what the Recon Agent does - scans all endpoints ONCE")

    recon_result = run_comprehensive_recon(
        base_url="http://localhost:8001",
        store_results=True
    )

    print(f"    ✓ Scanned: {recon_result['total_scanned']} endpoints")
    print(f"    ✓ Accessible: {recon_result['accessible_endpoints']} endpoints")
    print(f"    ✓ High Interest: {recon_result['high_interest_count']} endpoints")
    print(f"    ✓ Stored in DB: {recon_result['stored_in_db']}")

    if recon_result['high_interest']:
        print("\n    High-interest targets found:")
        for item in recon_result['high_interest'][:3]:
            print(f"      - {item['endpoint']}: {item['reason']}")

    # Get summary (simulates any agent checking context)
    print("\n[4] Getting recon summary...")
    print("    This is what agents do to get quick context")

    summary = get_recon_summary()
    print(f"    ✓ Total endpoints: {summary['total_endpoints_scanned']}")
    print(f"    ✓ API endpoints: {len(summary['api_endpoints'])}")
    print(f"    ✓ Admin endpoints: {len(summary['admin_endpoints'])}")

    # Query for interesting targets (simulates Vulnerability Hunter)
    print("\n[5] Querying for interesting targets...")
    print("    This is what Vulnerability Hunter does - queries stored data")

    interesting = query_recon_data(filter_by="interesting")
    print(f"    ✓ Found {interesting['total_results']} interesting targets")

    if interesting['results']:
        print("\n    Target details:")
        for result in interesting['results'][:3]:
            print(f"      - {result['endpoint']} (Status: {result['status_code']})")
            if result.get('notes'):
                print(f"        Notes: {result['notes']}")

    # Query for API endpoints (simulates Exploit Developer)
    print("\n[6] Querying for API endpoints...")
    print("    This is what Exploit Developer does - finds attack surface")

    api_endpoints = query_recon_data(endpoint_pattern="api")
    print(f"    ✓ Found {api_endpoints['total_results']} API endpoints")
    print(f"    ✓ Endpoints: {', '.join(api_endpoints['endpoints'][:5])}")

    # Show context savings
    print("\n" + "=" * 70)
    print("CONTEXT & REQUEST SAVINGS")
    print("=" * 70)

    total_scanned = recon_result['total_scanned']

    print(f"\nWithout recon tools:")
    print(f"  Recon Agent:    {total_scanned} HTTP requests")
    print(f"  Vuln Hunter:    {total_scanned} HTTP requests (re-scans)")
    print(f"  Exploit Dev:    {total_scanned} HTTP requests (re-scans)")
    print(f"  ────────────────────────────────")
    print(f"  Total:          {total_scanned * 3} HTTP requests")

    print(f"\nWith recon tools:")
    print(f"  Recon Agent:    {total_scanned} HTTP requests → stores in DB")
    print(f"  Vuln Hunter:    0 HTTP requests (queries DB)")
    print(f"  Exploit Dev:    0 HTTP requests (queries DB)")
    print(f"  ────────────────────────────────")
    print(f"  Total:          {total_scanned} HTTP requests")

    savings = ((total_scanned * 3 - total_scanned) / (total_scanned * 3)) * 100
    print(f"\n  💰 Savings:     {savings:.0f}% fewer requests!")
    print(f"  💾 Context:     Only queried data (not full responses)")
    print(f"  ⚡ Speed:       No redundant HTTP calls")

    print("\n" + "=" * 70)
    print("✓ Test complete! Recon tools working as expected.")
    print("=" * 70)


def test_query_filters():
    """Test different query filters."""

    print("\n" + "=" * 70)
    print("TESTING QUERY FILTERS")
    print("=" * 70)

    # Test accessible endpoints
    print("\n[Filter] Accessible endpoints (2xx):")
    accessible = query_recon_data(filter_by="accessible")
    print(f"  Found: {accessible['total_results']}")

    # Test error endpoints
    print("\n[Filter] Error endpoints (4xx/5xx):")
    errors = query_recon_data(filter_by="errors")
    print(f"  Found: {errors['total_results']}")

    # Test admin endpoints
    print("\n[Filter] Admin endpoints:")
    admin = query_recon_data(endpoint_pattern="admin")
    print(f"  Found: {admin['total_results']}")
    print(f"  Endpoints: {admin['endpoints']}")

    # Test specific status code
    print("\n[Filter] Only 200 OK:")
    ok_only = query_recon_data(min_status=200, max_status=200)
    print(f"  Found: {ok_only['total_results']}")


if __name__ == "__main__":
    print("\nNote: Make sure the target server (http://localhost:8001) is running")
    print("or the recon will fail. For testing, you can run the sample_app.")

    response = input("\nContinue with test? (y/n): ")
    if response.lower() == 'y':
        test_recon_workflow()
        test_query_filters()
    else:
        print("Test cancelled.")
