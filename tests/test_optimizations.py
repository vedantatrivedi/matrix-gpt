"""
Tests for optimization changes - Verify battle manager and agent changes
"""

import pytest
import inspect
from unittest.mock import Mock, AsyncMock, patch
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class TestRedTeamOptimizations:
    """Test red team agent optimizations"""

    def test_uses_smart_tools(self):
        """Verify red team agents use smart tools"""
        from orchestrator.agents.red_team import recon_agent, vulnerability_hunter

        recon_tool_names = [t.name if hasattr(t, 'name') else str(t) for t in recon_agent.tools]
        assert any('smart' in str(name).lower() for name in recon_tool_names), \
            f"Recon agent should use smart tools, got: {recon_tool_names}"

        hunter_tool_names = [t.name if hasattr(t, 'name') else str(t) for t in vulnerability_hunter.tools]
        assert any('smart' in str(name).lower() for name in hunter_tool_names), \
            f"Vulnerability hunter should use smart tools, got: {hunter_tool_names}"

    def test_uses_cheap_model(self):
        """Verify agents use gpt-4o-mini or similar cheap model"""
        from orchestrator.agents.red_team import RECON_MODEL, HUNTER_MODEL, MODEL

        models = [RECON_MODEL, HUNTER_MODEL, MODEL]
        for model in models:
            assert "mini" in model.lower() or "3.5" in model, \
                f"Should use cheap model, got: {model}"

    def test_has_short_instructions(self):
        """Verify instructions are shortened"""
        from orchestrator.agents.red_team import (
            RECON_INSTRUCTIONS,
            VULN_HUNTER_INSTRUCTIONS,
            EXPLOIT_DEV_INSTRUCTIONS
        )

        # Each instruction should be very short (< 100 chars)
        assert len(RECON_INSTRUCTIONS) < 100, \
            f"Recon instructions too long: {len(RECON_INSTRUCTIONS)} chars"
        assert len(VULN_HUNTER_INSTRUCTIONS) < 100, \
            f"Hunter instructions too long: {len(VULN_HUNTER_INSTRUCTIONS)} chars"
        assert len(EXPLOIT_DEV_INSTRUCTIONS) < 100, \
            f"Exploit instructions too long: {len(EXPLOIT_DEV_INSTRUCTIONS)} chars"


class TestBlueTeamOptimizations:
    """Test blue team agent optimizations"""

    def test_uses_cheap_model(self):
        """Verify blue team uses cheap model"""
        from orchestrator.agents.blue_team import MODEL, SOC_MODEL, PATCH_MODEL

        models = [MODEL, SOC_MODEL, PATCH_MODEL]
        for model in models:
            assert "mini" in model.lower() or "3.5" in model, \
                f"Should use cheap model, got: {model}"

    def test_has_short_instructions(self):
        """Verify instructions are shortened"""
        from orchestrator.agents.blue_team import (
            SOC_INSTRUCTIONS,
            PATCH_DEV_INSTRUCTIONS,
            COMMANDER_INSTRUCTIONS
        )

        assert len(SOC_INSTRUCTIONS) < 100
        assert len(PATCH_DEV_INSTRUCTIONS) < 100
        assert len(COMMANDER_INSTRUCTIONS) < 100


class TestBattleManagerOptimizations:
    """Test battle manager emergency fixes"""

    def test_red_loop_stops_after_one_iteration(self):
        """Verify red loop doesn't actually loop"""
        from orchestrator.battle_manager import BattleManager

        source = inspect.getsource(BattleManager._red_loop)

        # Should have emergency fix comment
        assert "EMERGENCY FIX" in source, \
            "Red loop should have emergency fix marker"

        # Should call stop_battle
        assert "stop_battle" in source, \
            "Red loop should call stop_battle to prevent looping"

        # Original while loop should be commented out or removed
        lines = source.split('\n')
        active_while = any(
            'while' in line and 'not self._stop_event' in line and not line.strip().startswith('#')
            for line in lines
        )
        assert not active_while, \
            "While loop should be commented out or removed"

    def test_blue_loop_stops_after_one_iteration(self):
        """Verify blue loop doesn't actually loop"""
        from orchestrator.battle_manager import BattleManager

        source = inspect.getsource(BattleManager._blue_loop)

        assert "EMERGENCY FIX" in source or "stop" in source.lower()

    def test_scoring_disabled(self):
        """Verify scoring is disabled to save API calls"""
        from orchestrator.battle_manager import BattleManager

        source = inspect.getsource(BattleManager._score_and_broadcast)

        # Should have emergency fix comment or early return
        assert "EMERGENCY FIX" in source or "return" in source.split('\n')[1], \
            "Scoring should be disabled with early return"


class TestToolsOptimizations:
    """Test tools.py optimizations"""

    def test_aggressive_truncation(self):
        """Verify _truncate uses small limit"""
        from orchestrator.agents.tools import _truncate

        # Test with long text
        long_text = "A" * 1000

        truncated = _truncate(long_text)

        # Should be much shorter than 800 (old limit)
        assert len(truncated) < 200, \
            f"Truncation should be aggressive, got {len(truncated)} chars"

        # Should be around 100-150 chars (new limit + ellipsis)
        assert 50 < len(truncated) < 200, \
            f"Truncated length should be ~100 chars, got {len(truncated)}"


class TestIntegration:
    """Integration tests to verify everything works together"""

    @pytest.mark.asyncio
    async def test_battle_manager_can_initialize(self):
        """Verify battle manager can be created"""
        from orchestrator.battle_manager import BattleManager

        async def mock_sink(event):
            pass

        manager = BattleManager(event_sink=mock_sink)
        assert manager is not None
        assert manager._battle_id is None

    def test_agents_can_be_imported(self):
        """Verify all agents can be imported"""
        from orchestrator.agents.red_team import (
            recon_agent,
            vulnerability_hunter,
            exploit_developer,
            red_team_commander
        )
        from orchestrator.agents.blue_team import (
            soc_monitor,
            patch_developer,
            blue_team_commander
        )

        # All agents should be created
        assert all([
            recon_agent,
            vulnerability_hunter,
            exploit_developer,
            red_team_commander,
            soc_monitor,
            patch_developer,
            blue_team_commander
        ])

    def test_database_functions_work(self):
        """Verify database functions still work"""
        from orchestrator.db import init_db, create_battle, get_battle

        # Initialize DB
        init_db()

        # Create a battle
        battle_id = create_battle("http://test.com")
        assert battle_id is not None

        # Retrieve it
        battle = get_battle(battle_id)
        assert battle is not None
        assert battle["target_url"] == "http://test.com"


class TestTokenSavingsEstimate:
    """Estimate actual token savings from optimizations"""

    def test_estimate_instruction_savings(self):
        """Calculate token savings from shorter instructions"""
        # Old instruction length estimate
        old_recon = "You are a recon tester. Use run_comprehensive_recon to scan all endpoints ONCE and store results. Then use get_recon_summary to review findings. Focus on high-interest targets. Output concise bullet points of key findings only."
        old_hunter = "You validate likely vulns. Start by using query_recon_data to see what recon found. Use filter_by='interesting' to get high-priority targets. Test SQLi, XSS, auth bypass, IDOR on those endpoints using http_get/http_post. Report type, endpoint, payload, proof. Be concise."

        # New instructions
        from orchestrator.agents.red_team import RECON_INSTRUCTIONS, VULN_HUNTER_INSTRUCTIONS

        # Rough token estimate (1 token ≈ 4 chars)
        old_tokens = (len(old_recon) + len(old_hunter)) / 4
        new_tokens = (len(RECON_INSTRUCTIONS) + len(VULN_HUNTER_INSTRUCTIONS)) / 4

        savings_pct = ((old_tokens - new_tokens) / old_tokens) * 100

        print(f"\nInstruction token savings: {savings_pct:.1f}%")
        print(f"Old: ~{old_tokens:.0f} tokens, New: ~{new_tokens:.0f} tokens")

        assert savings_pct > 50, "Should save at least 50% on instructions"

    def test_estimate_truncation_savings(self):
        """Calculate token savings from aggressive truncation"""
        from orchestrator.agents.tools import _truncate

        # Simulate typical HTTP response
        typical_response = """<!DOCTYPE html>
        <html><head><title>Products</title></head>
        <body><h1>Products</h1>
        <div class="products">""" + ("A" * 700) + "</div></body></html>"

        # Old would keep 800 chars
        old_truncated = typical_response[:800]
        # New keeps 100 chars
        new_truncated = _truncate(typical_response)

        old_tokens = len(old_truncated) / 4
        new_tokens = len(new_truncated) / 4

        savings_pct = ((old_tokens - new_tokens) / old_tokens) * 100

        print(f"\nTruncation token savings: {savings_pct:.1f}%")
        print(f"Old: ~{old_tokens:.0f} tokens, New: ~{new_tokens:.0f} tokens")

        assert savings_pct > 70, "Should save at least 70% on responses"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
