import unittest
import os
import sys
import tempfile
import sqlite3
import datetime
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.user_manager import UserManager
from core.telegram_notifier import (
    get_telegram_config, save_telegram_config, send_telegram_message,
    alert_quota_threshold, alert_quota_exceeded, alert_account_expired,
    alert_service_recovered, alert_all_quotas_reset, format_bytes_human
)
from core.quota_manager import reset_all_quotas, sync_all_quotas

class TestPhase3TelegramAndReset(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.conf_path = os.path.join(self.temp_dir.name, "telegram.conf")
        self.db_path = os.path.join(self.temp_dir.name, "test_vextunnel.db")
        self.user_mgr = UserManager(db_path=self.db_path)
        for u in ["user1", "user2", "streamer", "expired_user"]:
            try:
                self.user_mgr.delete_user(u)
            except Exception:
                pass

    def tearDown(self):
        for u in ["user1", "user2", "streamer", "expired_user"]:
            try:
                self.user_mgr.delete_user(u)
            except Exception:
                pass
        import gc
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_telegram_config_save_and_load(self):
        """Verify saving and retrieving Telegram credentials."""
        ok = save_telegram_config("123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11", "987654321", alerts_enabled=True, conf_path=self.conf_path)
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(self.conf_path))

        cfg = get_telegram_config(self.conf_path)
        self.assertEqual(cfg["bot_token"], "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11")
        self.assertEqual(cfg["chat_id"], "987654321")
        self.assertTrue(cfg["alerts_enabled"])

        # Check permissions on POSIX
        if os.name != 'nt':
            mode = oct(os.stat(self.conf_path).st_mode & 0o777)
            self.assertEqual(mode, "0o600")

    def test_send_telegram_unconfigured(self):
        """Should fail safely with error message when unconfigured."""
        ok, msg = send_telegram_message("test", conf_path=self.conf_path)
        self.assertFalse(ok)
        self.assertIn("not configured", msg)

    @patch("urllib.request.urlopen")
    def test_send_telegram_success_and_failure(self, mock_urlopen):
        """Verify sending message with mocked urlopen."""
        save_telegram_config("valid_token", "12345", alerts_enabled=True, conf_path=self.conf_path)

        # Mock successful HTTP 200 response
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        ok, msg = send_telegram_message("Hello from VexTunnel!", conf_path=self.conf_path)
        self.assertTrue(ok)
        self.assertIn("delivered successfully", msg)

        # Mock network failure
        mock_urlopen.side_effect = Exception("Connection timed out")
        ok, msg = send_telegram_message("Hello again", conf_path=self.conf_path)
        self.assertFalse(ok)
        self.assertIn("Connection timed out", msg)

    @patch("core.telegram_notifier.send_telegram_message")
    def test_alert_formatters(self, mock_send):
        """Verify alert formatters generate appropriate HTML templates."""
        mock_send.return_value = (True, "OK")

        # 80% Warning
        alert_quota_threshold("alice", 800 * 1024 * 1024, 1000 * 1024 * 1024, 80, conf_path=self.conf_path)
        self.assertTrue(mock_send.called)
        msg_text = mock_send.call_args[0][0]
        self.assertIn("BANDWIDTH WARNING (80%)", msg_text)
        self.assertIn("alice", msg_text)

        # 90% Critical
        alert_quota_threshold("bob", 900 * 1024 * 1024, 1000 * 1024 * 1024, 90, conf_path=self.conf_path)
        msg_text = mock_send.call_args[0][0]
        self.assertIn("CRITICAL BANDWIDTH ALERT (90%)", msg_text)

        # 100% Exceeded
        alert_quota_exceeded("charlie", 1000 * 1024 * 1024, 1000 * 1024 * 1024, conf_path=self.conf_path)
        msg_text = mock_send.call_args[0][0]
        self.assertIn("BANDWIDTH EXCEEDED (100%)", msg_text)
        self.assertIn("BLOCKED", msg_text)

        # Account Expired
        alert_account_expired("david", "2026-11-01 00:00:00", conf_path=self.conf_path)
        msg_text = mock_send.call_args[0][0]
        self.assertIn("SUBSCRIPTION EXPIRED", msg_text)

        # Watchdog Recovered
        alert_service_recovered("vextunnel-ws", conf_path=self.conf_path)
        msg_text = mock_send.call_args[0][0]
        self.assertIn("SERVICE SELF-HEALED", msg_text)

        # Quota Reset
        alert_all_quotas_reset(5, conf_path=self.conf_path)
        msg_text = mock_send.call_args[0][0]
        self.assertIn("BANDWIDTH QUOTA RESET", msg_text)
        self.assertIn("5 user accounts", msg_text)

    def test_format_bytes_human(self):
        self.assertEqual(format_bytes_human(0), "0 B")
        self.assertEqual(format_bytes_human(1024), "1.00 KB")
        self.assertEqual(format_bytes_human(1048576), "1.00 MB")
        self.assertEqual(format_bytes_human(1073741824), "1.00 GB")

    def test_reset_all_quotas(self):
        """Verify reset_all_quotas resets all counters and statuses across all accounts."""
        self.user_mgr.add_user("user1", "Passw0rd123!", 30, quota_bytes=1000000)
        self.user_mgr.add_user("user2", "Passw0rd123!", 30, quota_bytes=2000000)

        # Simulate user usage and quota exceeded state
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            UPDATE users SET used_bytes = 1500000, last_counter_bytes = 1500000, 
                             last_quota_alert_pct = 100, quota_status = 'quota_exceeded', status = 'quota_exceeded'
            WHERE username = 'user1'
        """)
        conn.execute("""
            UPDATE users SET used_bytes = 1800000, last_counter_bytes = 1800000, 
                             last_quota_alert_pct = 90, quota_status = 'active', status = 'active'
            WHERE username = 'user2'
        """)
        conn.commit()
        conn.close()

        with patch("core.telegram_notifier.alert_all_quotas_reset") as mock_alert:
            reset_count = reset_all_quotas(self.db_path)
            self.assertEqual(reset_count, 2)
            self.assertTrue(mock_alert.called)

        # Verify DB values were reset
        users = self.user_mgr.list_users()
        for u in users:
            self.assertEqual(u["used_bytes"], 0)
            self.assertEqual(u["last_counter_bytes"], 0)
            self.assertEqual(u["last_quota_alert_pct"], 0)
            self.assertEqual(u["quota_status"], "active")
            self.assertEqual(u["status"], "active")

    @patch("core.quota_manager.get_user_uid")
    @patch("core.quota_manager.read_uid_bytes")
    @patch("core.quota_manager.block_user_network")
    @patch("core.quota_manager.kill_user_sessions")
    @patch("core.quota_manager.alert_quota_threshold")
    @patch("core.quota_manager.alert_quota_exceeded")
    def test_quota_sync_deduplication_and_alerting(
        self, mock_alert_exceeded, mock_alert_thresh, mock_kill, mock_block, mock_read_bytes, mock_get_uid
    ):
        """Verify 80%, 90%, and 100% alerts trigger exactly once without duplicate spam."""
        mock_get_uid.return_value = 1001
        self.user_mgr.add_user("streamer", "Passw0rd123!", 30, quota_bytes=1000)

        # 1. Usage at 50% (500 bytes) -> No alert
        mock_read_bytes.return_value = 500
        sync_all_quotas(self.db_path)
        self.assertFalse(mock_alert_thresh.called)
        self.assertFalse(mock_alert_exceeded.called)

        # 2. Usage reaches 82% (820 bytes) -> 80% Warning alert triggered once
        mock_read_bytes.return_value = 820
        sync_all_quotas(self.db_path)
        self.assertEqual(mock_alert_thresh.call_count, 1)
        self.assertEqual(mock_alert_thresh.call_args[0][3], 80)

        # 3. Next sync at 85% (850 bytes) -> Deduplication prevents re-alerting 80%
        mock_read_bytes.return_value = 850
        sync_all_quotas(self.db_path)
        self.assertEqual(mock_alert_thresh.call_count, 1)

        # 4. Usage reaches 92% (920 bytes) -> 90% Critical alert triggered
        mock_read_bytes.return_value = 920
        sync_all_quotas(self.db_path)
        self.assertEqual(mock_alert_thresh.call_count, 2)
        self.assertEqual(mock_alert_thresh.call_args[0][3], 90)

        # 5. Usage reaches 100% (1000 bytes) -> 100% Exceeded alert triggered, user blocked
        mock_read_bytes.return_value = 1000
        sync_all_quotas(self.db_path)
        self.assertEqual(mock_alert_exceeded.call_count, 1)
        self.assertTrue(mock_block.called)
        self.assertTrue(mock_kill.called)

        # 6. Usage remains exceeded (1050 bytes) -> Deduplication prevents re-alerting 100%
        mock_read_bytes.return_value = 1050
        sync_all_quotas(self.db_path)
        self.assertEqual(mock_alert_exceeded.call_count, 1)

    @patch("core.telegram_notifier.alert_account_expired")
    def test_cleanup_expired_triggers_alert(self, mock_alert_expired):
        """Verify user_manager cleanup_expired locks user and dispatches alert."""
        self.user_mgr.add_user("expired_user", "Passw0rd123!", 10)
        # Manually alter expires_at to yesterday
        past_str = "2020-01-01 00:00:00"
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE users SET expires_at = ? WHERE username = 'expired_user'", (past_str,))
        conn.commit()
        conn.close()

        cleaned = self.user_mgr.cleanup_expired()
        self.assertEqual(cleaned, 1)
        self.assertTrue(mock_alert_expired.called)
        self.assertEqual(mock_alert_expired.call_args[0][0], "expired_user")
        self.assertEqual(mock_alert_expired.call_args[0][1], past_str)

if __name__ == "__main__":
    unittest.main()
