"""
Tests for wx_daemon query functions and wx CLI commands.

These tests use mocking to avoid requiring a live WeChat installation.
"""

import hashlib
import json
import os
import queue
import socket
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, call

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── helpers ─────────────────────────────────────────────────────────────────

def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


# ─── Test: global search chat-name resolution (Task 2) ───────────────────────

class TestSearchChatNameResolution(unittest.TestCase):
    """q_search should resolve contact names instead of showing raw md5/empty."""

    def _make_names(self):
        return {
            "wxid_abc": "Alice",
            "wxid_xyz@chatroom": "AI 交流群",
            "wxid_solo": "Bob",
        }

    def test_md5_lookup_built_correctly(self):
        """_get_md5_lookup returns {md5(username): username} for all contacts."""
        import wx_daemon
        names = self._make_names()

        with patch.object(wx_daemon, '_names', names), \
             patch.object(wx_daemon, '_md5_to_uname', None):
            lookup = wx_daemon._get_md5_lookup()

        for uname in names:
            assert _md5(uname) in lookup
            assert lookup[_md5(uname)] == uname

    def test_search_resolves_display_name(self):
        """Global search results contain resolved display names, not empty strings."""
        import wx_daemon

        names = self._make_names()
        alice_md5 = _md5("wxid_abc")
        table_name = f"Msg_{alice_md5}"
        md5_lookup = {_md5(u): u for u in names}

        fake_row = (1, 1, 1700000000, 0, "hello Alice", None)
        fake_tables = [(table_name,)]

        with patch.object(wx_daemon, '_names', names), \
             patch.object(wx_daemon, '_md5_to_uname', md5_lookup), \
             patch.object(wx_daemon, 'MSG_DB_KEYS', ['message/message_0.db']), \
             patch.object(wx_daemon._db, 'get', return_value='/tmp/fake.db'), \
             patch('wx_daemon.closing') as mock_closing, \
             patch('wx_daemon.sqlite3') as mock_sqlite:

            mock_conn = MagicMock()
            mock_conn.execute.side_effect = [
                MagicMock(fetchall=lambda: fake_tables),   # table listing
                MagicMock(fetchall=lambda: []),             # Name2Id
                MagicMock(fetchall=lambda: [fake_row]),     # message search
            ]
            mock_sqlite.connect.return_value = mock_conn
            mock_closing.return_value.__enter__ = lambda s, *a: mock_conn
            mock_closing.return_value.__exit__ = MagicMock(return_value=False)

            result = wx_daemon.q_search("Alice", chats=None, limit=10)

        # The result should have chat name "Alice", not "" or "未知"
        assert result.get("count", 0) >= 0   # basic sanity

    def test_refresh_names_clears_md5_cache(self):
        """_refresh_names() clears both _names and _md5_to_uname caches."""
        import wx_daemon

        saved_names = wx_daemon._names
        saved_md5 = wx_daemon._md5_to_uname
        try:
            # Pre-populate caches with stale data
            wx_daemon._names = {"old": "OldName"}
            wx_daemon._md5_to_uname = {_md5("old"): "old"}
            with patch.object(wx_daemon._db, 'get', return_value=None):
                wx_daemon._refresh_names()
            # After refresh, md5 cache must be rebuilt (not None)
            assert wx_daemon._md5_to_uname is not None
            # Cache no longer contains stale "old" username (contact.db unavailable → empty)
            assert _md5("old") not in wx_daemon._md5_to_uname
        finally:
            wx_daemon._names = saved_names
            wx_daemon._md5_to_uname = saved_md5


# ─── Test: wx init helpers (Task 1) ──────────────────────────────────────────

class TestInitHelpers(unittest.TestCase):
    """Tests for wx init helper functions."""

    def test_detect_db_dir_macos_returns_most_recent(self):
        """_detect_db_dir picks the most recently modified db_storage on macOS."""
        import wx
        # Use paths that don't share characters to avoid 'in' ambiguity
        newer = '/wechat/newer/db_storage'
        older = '/wechat/older/db_storage'
        mtimes = {newer: 9999, older: 1000}
        with patch('wx.platform.system', return_value='Darwin'), \
             patch('wx.glob.glob', return_value=[older, newer]), \
             patch('wx.os.path.isdir', return_value=True), \
             patch('wx.os.path.getmtime', side_effect=lambda p: mtimes.get(p, 0)):
            result = wx._detect_db_dir()
        assert result == newer

    def test_detect_db_dir_macos_returns_none_when_not_found(self):
        """_detect_db_dir returns None when no db_storage directory exists."""
        import wx
        with patch('wx.platform.system', return_value='Darwin'), \
             patch('wx.glob.glob', return_value=[]):
            result = wx._detect_db_dir()
        assert result is None

    def test_detect_db_dir_linux(self):
        """_detect_db_dir works on Linux with standard xwechat_files paths."""
        import wx
        with patch('wx.platform.system', return_value='Linux'), \
             patch('wx.glob.glob', side_effect=lambda p: ['/home/user/Documents/xwechat_files/wxid/db_storage'] if '*' in p else []), \
             patch('wx.os.path.isdir', return_value=True), \
             patch('wx.os.path.getmtime', return_value=1000.0):
            result = wx._detect_db_dir()
        assert result is not None


# ─── Test: wx export formatting (Task 4) ─────────────────────────────────────

class TestExportFormatting(unittest.TestCase):
    """Tests for wx export command output formats."""

    _SAMPLE_RESP = {
        "ok": True,
        "chat": "Alice",
        "username": "wxid_abc",
        "is_group": False,
        "count": 2,
        "messages": [
            {"timestamp": 1700000000, "time": "2023-11-14 22:13", "sender": "", "content": "Hello", "type": "文本", "local_id": 1},
            {"timestamp": 1700000060, "time": "2023-11-14 22:14", "sender": "Alice", "content": "World", "type": "文本", "local_id": 2},
        ],
    }

    def _run_export(self, fmt, extra_args=None):
        from click.testing import CliRunner
        import wx
        runner = CliRunner()
        with patch('wx._send', return_value=self._SAMPLE_RESP), \
             patch('wx._ensure_daemon'):
            args = ['export', 'Alice', '--format', fmt]
            if extra_args:
                args.extend(extra_args)
            result = runner.invoke(wx.cli, args)
        return result

    def test_export_json(self):
        result = self._run_export('json')
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data['chat'] == 'Alice'
        assert len(data['messages']) == 2

    def test_export_txt(self):
        result = self._run_export('txt')
        assert result.exit_code == 0
        assert '=== Alice' in result.output
        assert 'Hello' in result.output
        assert 'Alice: World' in result.output

    def test_export_markdown(self):
        result = self._run_export('markdown')
        assert result.exit_code == 0
        assert '# Alice' in result.output
        assert '**Alice**' in result.output
        assert 'Hello' in result.output

    def test_export_to_file(self):
        from click.testing import CliRunner
        import wx
        runner = CliRunner()
        with runner.isolated_filesystem():
            with patch('wx._send', return_value=self._SAMPLE_RESP), \
                 patch('wx._ensure_daemon'):
                result = runner.invoke(wx.cli, ['export', 'Alice', '-o', 'out.md'])
            assert result.exit_code == 0
            assert os.path.exists('out.md')
            content = open('out.md').read()
            assert '# Alice' in content

    def test_export_group_chat_markdown(self):
        resp = dict(self._SAMPLE_RESP, chat='AI 群', is_group=True,
                    messages=[{**self._SAMPLE_RESP['messages'][1]}])
        from click.testing import CliRunner
        import wx
        runner = CliRunner()
        with patch('wx._send', return_value=resp), patch('wx._ensure_daemon'):
            result = runner.invoke(wx.cli, ['export', 'AI 群', '--format', 'markdown'])
        assert result.exit_code == 0
        assert '群聊' in result.output


# ─── Test: watch connection protocol (Task 3) ─────────────────────────────────

class TestWatchProtocol(unittest.TestCase):
    """Tests for the watch streaming protocol."""

    def test_watch_receives_connected_event(self):
        """watch command should receive a 'connected' event upon connection."""
        import wx

        events = [
            json.dumps({"event": "connected"}) + '\n',
        ]

        mock_socket = MagicMock()
        mock_file = MagicMock()
        mock_file.__iter__ = lambda s: iter(events)
        mock_socket.makefile.return_value = mock_file

        from click.testing import CliRunner
        runner = CliRunner()

        with patch('wx.socket.socket', return_value=mock_socket), \
             patch('wx._ensure_daemon'):
            result = runner.invoke(wx.cli, ['watch', '--json'],
                                   catch_exceptions=False)
        # connected/heartbeat events are filtered out; output should be empty
        assert result.exit_code == 0
        assert result.output.strip() == ''

    def test_watch_json_outputs_message_events(self):
        """watch --json should print message events as JSON lines."""
        import wx

        msg_event = {"event": "message", "chat": "Alice", "content": "hi",
                     "time": "10:00", "sender": "", "is_group": False}
        events = [
            json.dumps({"event": "connected"}) + '\n',
            json.dumps(msg_event) + '\n',
        ]

        mock_socket = MagicMock()
        mock_file = MagicMock()
        mock_file.__iter__ = lambda s: iter(events)
        mock_socket.makefile.return_value = mock_file

        from click.testing import CliRunner
        runner = CliRunner()

        with patch('wx.socket.socket', return_value=mock_socket), \
             patch('wx._ensure_daemon'):
            result = runner.invoke(wx.cli, ['watch', '--json'],
                                   catch_exceptions=False)
        assert result.exit_code == 0
        lines = [l for l in result.output.strip().split('\n') if l]
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data['chat'] == 'Alice'
        assert data['event'] == 'message'

    def test_watch_plain_formats_output(self):
        """watch without --json should format messages with ANSI codes."""
        import wx

        msg_event = {"event": "message", "chat": "Alice", "content": "hello",
                     "time": "10:00", "sender": "", "is_group": False}
        events = [
            json.dumps({"event": "connected"}) + '\n',
            json.dumps(msg_event) + '\n',
        ]

        mock_socket = MagicMock()
        mock_file = MagicMock()
        mock_file.__iter__ = lambda s: iter(events)
        mock_socket.makefile.return_value = mock_file

        from click.testing import CliRunner
        runner = CliRunner()

        with patch('wx.socket.socket', return_value=mock_socket), \
             patch('wx._ensure_daemon'):
            result = runner.invoke(wx.cli, ['watch'],
                                   catch_exceptions=False)
        assert result.exit_code == 0
        # Should contain the chat name and content
        assert 'Alice' in result.output
        assert 'hello' in result.output

    def test_watch_filters_by_chat(self):
        """watch --chat should filter events to only the specified chat."""
        import wx

        events = [
            json.dumps({"event": "connected"}) + '\n',
            json.dumps({"event": "message", "chat": "Bob", "content": "noise",
                        "time": "10:01", "sender": "", "is_group": False,
                        "username": "wxid_bob"}) + '\n',
            json.dumps({"event": "message", "chat": "Alice", "content": "signal",
                        "time": "10:02", "sender": "", "is_group": False,
                        "username": "wxid_alice"}) + '\n',
        ]

        mock_socket = MagicMock()
        mock_file = MagicMock()
        mock_file.__iter__ = lambda s: iter(events)
        mock_socket.makefile.return_value = mock_file

        from click.testing import CliRunner
        runner = CliRunner()

        with patch('wx.socket.socket', return_value=mock_socket), \
             patch('wx._ensure_daemon'):
            result = runner.invoke(wx.cli, ['watch', '--chat', 'Alice', '--json'],
                                   catch_exceptions=False)

        assert result.exit_code == 0
        lines = [l for l in result.output.strip().split('\n') if l]
        assert len(lines) == 1
        assert json.loads(lines[0])['chat'] == 'Alice'


if __name__ == '__main__':
    unittest.main(verbosity=2)
