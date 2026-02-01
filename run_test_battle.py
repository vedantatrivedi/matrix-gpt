#!/usr/bin/env python3
"""
Test battle runner - Monitors token usage and optimization behavior
"""
import asyncio
import sys
from datetime import datetime
from orchestrator.battle_manager import BattleManager

# Track events
events = []
token_count = 0

async def event_sink(event):
    """Capture and display events"""
    global token_count
    events.append(event)

    event_type = event.get("type", "unknown")
    team = event.get("team", "unknown")
    agent = event.get("agent", "unknown")

    timestamp = datetime.now().strftime("%H:%M:%S")

    if event_type == "battle_event":
        data = event.get("data", {})
        description = data.get("description", "")
        print(f"[{timestamp}] {team:6} | {agent:20} | {description[:80]}")

        # Look for token usage indicators
        if "token" in description.lower():
            print(f"  💰 TOKEN INFO: {description}")
        if "skipped" in description.lower():
            print(f"  ⏭️  OPTIMIZATION: Smart filter skipped boring response")
        if "interesting" in description.lower():
            print(f"  🎯 FOUND: Interesting response detected")

    elif event_type == "score_update":
        data = event.get("data", {})
        print(f"[{timestamp}] SCORE  | Red: {data.get('red_score', 0)} | Blue: {data.get('blue_score', 0)}")

    elif event_type == "battle_complete":
        print(f"\n{'='*80}")
        print(f"[{timestamp}] BATTLE COMPLETE")
        print(f"{'='*80}")

async def main():
    print("="*80)
    print("STARTING TEST BATTLE - Monitoring Optimizations")
    print("="*80)
    print()
    print("Expected behavior:")
    print("  ✅ Loop runs ONCE (not 450 times)")
    print("  ✅ Smart tools filter boring responses")
    print("  ✅ Token count stays under 20K")
    print("  ✅ Cost under $0.50")
    print()
    print("="*80)
    print()

    manager = BattleManager(event_sink=event_sink)

    try:
        battle_id = await manager.start_battle("http://localhost:8001")
        print(f"✅ Battle started with ID: {battle_id}")
        print()

        # Wait for battle to complete (should be quick with 1 iteration)
        while not manager._stop_event.is_set():
            await asyncio.sleep(1)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        print()
        print("="*80)
        print("BATTLE SUMMARY")
        print("="*80)
        print(f"Total events captured: {len(events)}")
        print(f"Battle duration: {len([e for e in events if e.get('type') == 'battle_event'])} events")
        print()

        # Count optimization indicators
        skipped = len([e for e in events if 'skipped' in str(e).lower()])
        interesting = len([e for e in events if 'interesting' in str(e).lower()])

        print(f"📊 Optimization Stats:")
        print(f"  - Smart filter skipped: {skipped} responses")
        print(f"  - Interesting responses: {interesting}")
        print()
        print("✅ Check token usage in OpenAI dashboard")
        print("   Expected: ~10-20K tokens total")
        print("   Expected cost: ~$0.30")

if __name__ == "__main__":
    asyncio.run(main())
