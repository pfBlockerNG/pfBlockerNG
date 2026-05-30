import builtins
import re
import types

import pytest

import pfb_unbound

# Unbound injects these as module-level globals at runtime; conftest stubs them
# onto builtins so pfb_unbound can be imported. Bind local names for the tests
# (and so static analysis sees them defined).
DNSMessage = builtins.DNSMessage
MODULE_EVENT_NEW = builtins.MODULE_EVENT_NEW
MODULE_EVENT_MODDONE = builtins.MODULE_EVENT_MODDONE
MODULE_FINISHED = builtins.MODULE_FINISHED
MODULE_WAIT_MODULE = builtins.MODULE_WAIT_MODULE
MODULE_ERROR = builtins.MODULE_ERROR
RCODE_NOERROR = builtins.RCODE_NOERROR
from pfb_unbound import (
    convert_ipv4,
    convert_ipv6,
    convert_other,
    is_unknown,
    python_control_duration,
)


class TestIsUnknown:
    def test_none_returns_unknown(self):
        assert is_unknown(None) == 'Unknown'

    def test_empty_string_returns_unknown(self):
        assert is_unknown('') == 'Unknown'

    def test_zero_returns_unknown(self):
        assert is_unknown(0) == 'Unknown'

    def test_false_returns_unknown(self):
        assert is_unknown(False) == 'Unknown'

    def test_nonempty_string_returned_as_is(self):
        assert is_unknown('example.com') == 'example.com'

    def test_ip_string_returned_as_is(self):
        assert is_unknown('192.168.1.1') == '192.168.1.1'

    def test_string_zero_returned_as_is(self):
        # '0' is a non-empty string, so it is not unknown
        assert is_unknown('0') == '0'

    def test_nonzero_int_returned_as_is(self):
        assert is_unknown(42) == 42


class TestConvertIPv4:
    # x[2], x[3], x[4], x[5] are the four octets; x[0] and x[1] are ignored

    def test_standard_address(self):
        assert convert_ipv4(bytes([0, 0, 192, 168, 1, 1])) == '192.168.1.1'

    def test_loopback(self):
        assert convert_ipv4(bytes([0, 0, 127, 0, 0, 1])) == '127.0.0.1'

    def test_broadcast(self):
        assert convert_ipv4(bytes([0, 0, 255, 255, 255, 255])) == '255.255.255.255'

    def test_all_zeros(self):
        assert convert_ipv4(bytes([0, 0, 0, 0, 0, 0])) == '0.0.0.0'

    def test_empty_bytes_returns_unknown(self):
        assert convert_ipv4(b'') == 'Unknown'

    def test_none_returns_unknown(self):
        assert convert_ipv4(None) == 'Unknown'


class TestConvertIPv6:
    # x[2] through x[17] are the 16 address bytes; x[0] and x[1] are ignored

    def test_loopback(self):
        x = bytes([0, 0] + [0] * 15 + [1])
        assert convert_ipv6(x) == '0000:0000:0000:0000:0000:0000:0000:0001'

    def test_known_prefix(self):
        # 2001:0db8::1
        x = bytes([0, 0, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        assert convert_ipv6(x) == '2001:0db8:0000:0000:0000:0000:0000:0001'

    def test_all_zeros_not_unknown(self):
        # All-zeros IPv6 address is a valid (if unusual) value
        x = bytes([0, 0] + [0] * 16)
        assert convert_ipv6(x) == '0000:0000:0000:0000:0000:0000:0000:0000'

    def test_empty_bytes_returns_unknown(self):
        assert convert_ipv6(b'') == 'Unknown'

    def test_none_returns_unknown(self):
        assert convert_ipv6(None) == 'Unknown'


class TestConvertOther:
    # x[0:3] are ignored; x[3:] is the payload
    # Encoding rules:
    #   val == 0          → '|'
    #   1 <= val <= 12    → '.'
    #   val == 13         → stop
    #   val == 32         → ' '
    #   val == 58         → ':'
    #   val <= 33 or > 126 → skip
    #   else              → chr(val)
    # Leading/trailing '.' and '|' are stripped from the result.

    def test_printable_ascii(self):
        x = bytes([0, 0, 0, ord('A'), ord('B'), ord('C')])
        assert convert_other(x) == 'ABC'

    def test_null_becomes_pipe(self):
        x = bytes([0, 0, 0, ord('A'), 0, ord('B')])
        assert convert_other(x) == 'A|B'

    def test_low_byte_becomes_dot(self):
        x = bytes([0, 0, 0, ord('A'), 1, ord('B')])
        assert convert_other(x) == 'A.B'

    def test_carriage_return_stops_processing(self):
        x = bytes([0, 0, 0, ord('A'), 13, ord('B')])
        assert convert_other(x) == 'A'

    def test_space_preserved(self):
        x = bytes([0, 0, 0, ord('A'), 32, ord('B')])
        assert convert_other(x) == 'A B'

    def test_colon_preserved(self):
        x = bytes([0, 0, 0, ord('h'), 58, ord('1')])
        assert convert_other(x) == 'h:1'

    def test_control_chars_skipped(self):
        # val 14..31 (excluding 13) and 33 are skipped
        x = bytes([0, 0, 0, ord('A'), 14, ord('B')])
        assert convert_other(x) == 'AB'

    def test_high_bytes_skipped(self):
        x = bytes([0, 0, 0, ord('A'), 200, ord('B')])
        assert convert_other(x) == 'AB'

    def test_leading_trailing_stripped(self):
        # Result '.A.' → strip('.|') → 'A'
        x = bytes([0, 0, 0, ord('.'), ord('A'), ord('.')])
        assert convert_other(x) == 'A'

    def test_empty_payload_returns_unknown(self):
        # x[3:] is empty
        x = bytes([0, 0, 0])
        assert convert_other(x) == 'Unknown'

    def test_empty_bytes_returns_unknown(self):
        assert convert_other(b'') == 'Unknown'

    def test_none_returns_unknown(self):
        assert convert_other(None) == 'Unknown'


class TestPythonControlDuration:
    def test_valid_duration(self):
        assert python_control_duration('60') == 60

    def test_minimum_valid(self):
        assert python_control_duration('1') == 1

    def test_maximum_valid(self):
        assert python_control_duration('3600') == 3600

    def test_zero_rejected(self):
        assert python_control_duration('0') is False

    def test_above_maximum_rejected(self):
        assert python_control_duration('3601') is False

    def test_non_numeric_rejected(self):
        assert python_control_duration('abc') is False

    def test_negative_rejected(self):
        # isnumeric() returns False for strings with a leading '-'
        assert python_control_duration('-1') is False

    def test_empty_string_rejected(self):
        assert python_control_duration('') is False

    def test_none_rejected(self):
        # AttributeError on None.isnumeric() is caught internally
        assert python_control_duration(None) is False


class TestPfbRegexMatch:
    def test_match_returns_key_name(self):
        pfb_unbound.regexDB['evil'] = re.compile(r'evil')
        assert pfb_unbound.pfb_regex_match('evil-domain.com') == 'evil'

    def test_no_match_returns_false(self):
        pfb_unbound.regexDB['evil'] = re.compile(r'evil')
        assert pfb_unbound.pfb_regex_match('good.com') is False

    def test_empty_regexdb_returns_false(self):
        assert pfb_unbound.pfb_regex_match('anything.com') is False

    def test_none_qname_returns_false(self):
        pfb_unbound.regexDB['evil'] = re.compile(r'evil')
        assert pfb_unbound.pfb_regex_match(None) is False

    def test_first_matching_key_wins(self):
        pfb_unbound.regexDB['a'] = re.compile(r'foo')
        pfb_unbound.regexDB['b'] = re.compile(r'bar')
        assert pfb_unbound.pfb_regex_match('barfoo') in ('a', 'b')


class TestGetQIpComm:
    def test_pfb_addr_key_present(self):
        kwargs = {'pfb_addr': '1.2.3.4'}
        assert pfb_unbound.get_q_ip_comm(kwargs) == '1.2.3.4'

    def test_fallback_to_repinfo_addr(self):
        kwargs = {'repinfo': types.SimpleNamespace(addr='5.6.7.8')}
        assert pfb_unbound.get_q_ip_comm(kwargs) == '5.6.7.8'

    def test_pfb_addr_takes_precedence(self):
        kwargs = {'pfb_addr': '1.2.3.4',
                  'repinfo': types.SimpleNamespace(addr='5.6.7.8')}
        assert pfb_unbound.get_q_ip_comm(kwargs) == '1.2.3.4'

    def test_empty_kwargs_returns_unknown(self):
        assert pfb_unbound.get_q_ip_comm({}) == 'Unknown'

    def test_none_kwargs_returns_unknown(self):
        assert pfb_unbound.get_q_ip_comm(None) == 'Unknown'

    def test_repinfo_empty_addr_returns_unknown(self):
        kwargs = {'repinfo': types.SimpleNamespace(addr='')}
        assert pfb_unbound.get_q_ip_comm(kwargs) == 'Unknown'


class TestLogEntry:
    def test_normal_write(self, tmp_path):
        log = tmp_path / 'dnsbl.log'
        pfb_unbound.log_entry('a,b,c', str(log))
        assert log.read_text() == 'a,b,c\n'

    def test_multiple_calls_accumulate(self, tmp_path):
        log = tmp_path / 'dnsbl.log'
        pfb_unbound.log_entry('line1', str(log))
        pfb_unbound.log_entry('line2', str(log))
        assert log.read_text() == 'line1\nline2\n'

    def test_file_created_when_missing(self, tmp_path):
        log = tmp_path / 'sub' / 'unified.log'
        log.parent.mkdir()
        assert not log.exists()
        pfb_unbound.log_entry('x', str(log))
        assert log.exists()


class TestWriteSqlite:
    def test_invalid_db_returns_false(self):
        assert pfb_unbound.write_sqlite(0, '', False) is False

    def test_db1_creates_table_and_seed_row(self, tmp_path):
        db = str(tmp_path / 'resolver.sqlite')
        pfb_unbound.pfb['pfb_py_resolver'] = db
        assert pfb_unbound.write_sqlite(1, '', False) is True

        import sqlite3
        con = sqlite3.connect(db)
        try:
            cur = con.cursor()
            cur.execute("SELECT totalqueries FROM resolver WHERE row = 0")
            assert cur.fetchone()[0] == 0
        finally:
            con.close()

    def test_db1_increments_totalqueries_on_update(self, tmp_path):
        db = str(tmp_path / 'resolver.sqlite')
        pfb_unbound.pfb['pfb_py_resolver'] = db
        pfb_unbound.write_sqlite(1, '', False)
        pfb_unbound.write_sqlite(1, '', True)
        pfb_unbound.write_sqlite(1, '', True)

        import sqlite3
        con = sqlite3.connect(db)
        try:
            cur = con.cursor()
            cur.execute("SELECT totalqueries FROM resolver WHERE row = 0")
            assert cur.fetchone()[0] == 2
        finally:
            con.close()

    def test_db1_idempotent_create(self, tmp_path):
        db = str(tmp_path / 'resolver.sqlite')
        pfb_unbound.pfb['pfb_py_resolver'] = db
        assert pfb_unbound.write_sqlite(1, '', False) is True
        assert pfb_unbound.write_sqlite(1, '', False) is True

        import sqlite3
        con = sqlite3.connect(db)
        try:
            cur = con.cursor()
            cur.execute("SELECT COUNT(*) FROM resolver")
            assert cur.fetchone()[0] == 1
        finally:
            con.close()

    def test_db2_creates_table(self, tmp_path):
        db = str(tmp_path / 'dnsbl.sqlite')
        pfb_unbound.pfb['pfb_py_dnsbl'] = db
        assert pfb_unbound.write_sqlite(2, '', False) is True

        import sqlite3
        con = sqlite3.connect(db)
        try:
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='dnsbl'")
            assert cur.fetchone() is not None
        finally:
            con.close()

    def test_db2_increments_counter(self, tmp_path):
        db = str(tmp_path / 'dnsbl.sqlite')
        pfb_unbound.pfb['pfb_py_dnsbl'] = db
        pfb_unbound.write_sqlite(2, '', False)

        import sqlite3
        con = sqlite3.connect(db)
        try:
            con.execute(
                "INSERT INTO dnsbl (groupname, timestamp, entries, counter) VALUES (?,?,?,?)",
                ('TestGroup', 'ts', 0, 0))
            con.commit()
        finally:
            con.close()

        pfb_unbound.write_sqlite(2, 'TestGroup', True)

        con = sqlite3.connect(db)
        try:
            cur = con.cursor()
            cur.execute("SELECT counter FROM dnsbl WHERE groupname = 'TestGroup'")
            assert cur.fetchone()[0] == 1
        finally:
            con.close()

    def test_db3_inserts_row(self, tmp_path):
        db = str(tmp_path / 'cache.sqlite')
        pfb_unbound.pfb['pfb_py_cache'] = db
        row = ['DNSBL', 'evil.com', 'TestGroup', 'evil.com', 'TestFeed']
        assert pfb_unbound.write_sqlite(3, '', row) is True

        import sqlite3
        con = sqlite3.connect(db)
        try:
            cur = con.cursor()
            cur.execute("SELECT type, domain, groupname, final, feed FROM dnsblcache")
            assert cur.fetchone() == ('DNSBL', 'evil.com', 'TestGroup', 'evil.com', 'TestFeed')
        finally:
            con.close()


class TestGetRepTtl:
    def test_ttl_present(self):
        rep = types.SimpleNamespace(ttl=300)
        assert pfb_unbound.get_rep_ttl(rep) == '300'

    def test_none_rep_returns_unk(self):
        assert pfb_unbound.get_rep_ttl(None) == 'Unk'

    def test_falsy_ttl_returns_unk(self):
        rep = types.SimpleNamespace(ttl=0)
        assert pfb_unbound.get_rep_ttl(rep) == 'Unk'


class TestPythonControlThread:
    def test_active_thread_found(self):
        import threading

        stop = threading.Event()
        t = threading.Thread(name='pfb-test-thread', target=stop.wait, daemon=True)
        t.start()
        try:
            assert pfb_unbound.python_control_thread('pfb-test-thread') is True
        finally:
            stop.set()
            t.join()

    def test_unknown_thread_returns_false(self):
        assert pfb_unbound.python_control_thread('nonexistent-thread-xyz') is False


class TestGetQNameQstate:
    def test_primary_strips_trailing_dot(self):
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str='example.com.'),
            return_msg=None)
        assert pfb_unbound.get_q_name_qstate(qstate) == 'example.com'

    def test_fallback_to_return_msg(self):
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str='   '),
            return_msg=types.SimpleNamespace(
                qinfo=types.SimpleNamespace(qname_str='fallback.com.')))
        assert pfb_unbound.get_q_name_qstate(qstate) == 'fallback.com'

    def test_both_empty_returns_unknown(self):
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str=''),
            return_msg=None)
        assert pfb_unbound.get_q_name_qstate(qstate) == 'Unknown'


class TestGetQNameQinfo:
    def test_present_stripped(self):
        qinfo = types.SimpleNamespace(qname_str='example.com.')
        assert pfb_unbound.get_q_name_qinfo(qinfo) == 'example.com'

    def test_whitespace_returns_unknown(self):
        qinfo = types.SimpleNamespace(qname_str='   ')
        assert pfb_unbound.get_q_name_qinfo(qinfo) == 'Unknown'

    def test_none_returns_unknown(self):
        assert pfb_unbound.get_q_name_qinfo(None) == 'Unknown'


class TestGetQType:
    def test_prefers_qstate(self):
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qtype_str='A'))
        qinfo = types.SimpleNamespace(qtype_str='AAAA')
        assert pfb_unbound.get_q_type(qstate, qinfo) == 'A'

    def test_falls_back_to_qinfo(self):
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qtype_str=''))
        qinfo = types.SimpleNamespace(qtype_str='AAAA')
        assert pfb_unbound.get_q_type(qstate, qinfo) == 'AAAA'

    def test_both_none_returns_unknown(self):
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qtype_str=''))
        qinfo = types.SimpleNamespace(qtype_str='')
        assert pfb_unbound.get_q_type(qstate, qinfo) == 'Unknown'


class TestGetOType:
    def test_return_msg_rrset_branch(self):
        rk = types.SimpleNamespace(type_str='A')
        rrset = types.SimpleNamespace(rk=rk)
        qstate = types.SimpleNamespace(
            return_msg=types.SimpleNamespace(rep=types.SimpleNamespace(rrsets=[rrset])),
            qinfo=types.SimpleNamespace(qtype_str='AAAA'))
        assert pfb_unbound.get_o_type(qstate, None) == 'A'

    def test_qinfo_qtype_branch(self):
        qstate = types.SimpleNamespace(
            return_msg=None,
            qinfo=types.SimpleNamespace(qtype_str='AAAA'))
        assert pfb_unbound.get_o_type(qstate, None) == 'AAAA'

    def test_rep_branch(self):
        rk = types.SimpleNamespace(type_str='TXT')
        rep = types.SimpleNamespace(rrsets=[types.SimpleNamespace(rk=rk)])
        qstate = types.SimpleNamespace(
            return_msg=None,
            qinfo=types.SimpleNamespace(qtype_str=''))
        assert pfb_unbound.get_o_type(qstate, rep) == 'TXT'

    def test_no_qstate_returns_unknown(self):
        assert pfb_unbound.get_o_type(None, None) == 'Unknown'


class TestGetTld:
    def test_multilabel(self):
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_list=['sub', 'example', 'com']))
        assert pfb_unbound.get_tld(qstate) == 'example'

    def test_single_label_returns_empty(self):
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_list=['com']))
        assert pfb_unbound.get_tld(qstate) == ''

    def test_none_qstate_returns_empty(self):
        assert pfb_unbound.get_tld(None) == ''


class TestGetQIp:
    def test_first_node_with_addr_wins(self):
        node2 = types.SimpleNamespace(
            query_reply=types.SimpleNamespace(addr='2.2.2.2'), next=None)
        node1 = types.SimpleNamespace(
            query_reply=types.SimpleNamespace(addr='1.1.1.1'), next=node2)
        qstate = types.SimpleNamespace(
            mesh_info=types.SimpleNamespace(reply_list=node1))
        assert pfb_unbound.get_q_ip(qstate) == '1.1.1.1'

    def test_no_reply_list_returns_unknown(self):
        qstate = types.SimpleNamespace(
            mesh_info=types.SimpleNamespace(reply_list=None))
        assert pfb_unbound.get_q_ip(qstate) == 'Unknown'


def make_qstate(qname='example.com.', qtype=1, q_ip=None, return_msg=None,
                return_rcode=0):
    reply_list = None
    if q_ip is not None:
        reply_list = types.SimpleNamespace(
            query_reply=types.SimpleNamespace(addr=q_ip), next=None)
    qinfo = types.SimpleNamespace(
        qname_str=qname,
        qtype=qtype,
        qtype_str='',
        qname_list=qname.rstrip('.').split('.'),
    )
    return types.SimpleNamespace(
        qinfo=qinfo,
        mesh_info=types.SimpleNamespace(reply_list=reply_list),
        return_msg=return_msg,
        return_rcode=return_rcode,
        ext_state={},
    )


# RR_TYPE constants mirror the conftest stubs
RR_A = 1
RR_AAAA = 28
RR_TXT = 16


class TestOperateNoAAAA:
    def _enable(self):
        pfb_unbound.pfb['noAAAADB'] = True

    def test_exact_match_blocks(self, monkeypatch):
        self._enable()
        pfb_unbound.noAAAADB['example.com'] = False
        qstate = make_qstate('example.com.', qtype=RR_AAAA)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert qstate.return_rcode == RCODE_NOERROR

    def test_wildcard_blocks_subdomain_and_caches(self):
        self._enable()
        pfb_unbound.noAAAADB['example.com'] = True
        qstate = make_qstate('sub.example.com.', qtype=RR_AAAA)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert pfb_unbound.noAAAADB.get('sub.example.com') is True

    def test_excluded_domain_not_blocked(self):
        self._enable()
        pfb_unbound.noAAAADB['example.com'] = False
        pfb_unbound.excludeAAAADB.append('example.com')
        qstate = make_qstate('example.com.', qtype=RR_AAAA)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE

    def test_non_aaaa_skips_logic(self):
        self._enable()
        pfb_unbound.noAAAADB['example.com'] = False
        qstate = make_qstate('example.com.', qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE

    def test_no_match_adds_to_exclude(self):
        self._enable()
        pfb_unbound.noAAAADB['other.com'] = True
        qstate = make_qstate('example.com.', qtype=RR_AAAA)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert 'example.com' in pfb_unbound.excludeAAAADB
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE


class TestOperateDnsbl:
    def _enable(self, monkeypatch):
        pfb_unbound.pfb['python_blacklist'] = True
        pfb_unbound.pfb['python_blocking'] = True
        monkeypatch.setattr(pfb_unbound, 'log_entry', lambda *a: None)
        monkeypatch.setattr(pfb_unbound, 'write_sqlite', lambda *a: True)

    def test_data_lookup_blocks_with_dnsbl_ipv4(self, monkeypatch):
        self._enable(monkeypatch)
        pfb_unbound.pfb['dataDB'] = True
        pfb_unbound.dataDB['evil.com'] = {'log': '1', 'index': 0}
        pfb_unbound.feedGroupIndexDB[0] = {'feed': 'TestFeed', 'group': 'TestGroup'}
        qstate = make_qstate('evil.com.', qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert qstate.return_rcode == RCODE_NOERROR
        answers = DNSMessage.instances[-1].answer
        assert any(pfb_unbound.pfb['dnsbl_ipv4'] in a for a in answers)

    def test_zone_lookup_matches_subdomain(self, monkeypatch):
        self._enable(monkeypatch)
        pfb_unbound.pfb['zoneDB'] = True
        pfb_unbound.zoneDB['example.com'] = {'log': '1', 'index': 0}
        pfb_unbound.feedGroupIndexDB[0] = {'feed': 'TestFeed', 'group': 'TestGroup'}
        qstate = make_qstate('sub.example.com.', qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED

    def test_whitelist_override_not_blocked(self, monkeypatch):
        self._enable(monkeypatch)
        pfb_unbound.pfb['dataDB'] = True
        pfb_unbound.pfb['whiteDB'] = True
        pfb_unbound.dataDB['evil.com'] = {'log': '1', 'index': 0}
        pfb_unbound.feedGroupIndexDB[0] = {'feed': 'TestFeed', 'group': 'TestGroup'}
        pfb_unbound.whiteDB['evil.com'] = False
        qstate = make_qstate('evil.com.', qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE
        assert 'evil.com' in pfb_unbound.excludeDB

    def test_regex_block(self, monkeypatch):
        self._enable(monkeypatch)
        pfb_unbound.pfb['regexDB'] = True
        pfb_unbound.regexDB['bad-pattern'] = re.compile(r'evil')
        qstate = make_qstate('evil-domain.com.', qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        entry = pfb_unbound.dnsblDB.get('evil-domain.com')
        assert entry['group'] == 'DNSBL_Regex'

    def test_excludedb_short_circuit(self, monkeypatch):
        self._enable(monkeypatch)
        pfb_unbound.pfb['dataDB'] = True
        pfb_unbound.dataDB['evil.com'] = {'log': '1', 'index': 0}
        pfb_unbound.feedGroupIndexDB[0] = {'feed': 'TestFeed', 'group': 'TestGroup'}
        pfb_unbound.excludeDB.append('evil.com')
        qstate = make_qstate('evil.com.', qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE

    def test_group_policy_bypass(self, monkeypatch):
        self._enable(monkeypatch)
        pfb_unbound.pfb['dataDB'] = True
        pfb_unbound.pfb['gpListDB'] = True
        pfb_unbound.dataDB['evil.com'] = {'log': '1', 'index': 0}
        pfb_unbound.feedGroupIndexDB[0] = {'feed': 'TestFeed', 'group': 'TestGroup'}
        pfb_unbound.gpListDB['1.2.3.4'] = 0
        qstate = make_qstate('evil.com.', qtype=RR_A, q_ip='1.2.3.4')
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE


class TestOperateEvents:
    def test_moddone_logs_and_finishes(self):
        qstate = make_qstate('example.com.', qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_MODDONE, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED

    def test_unknown_event_returns_error(self):
        qstate = make_qstate('example.com.', qtype=RR_A)
        rcd = pfb_unbound.operate(0, 99, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_ERROR
