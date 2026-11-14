from datetime import datetime
from analyze import parse_line, analyze_logs


def test_parse_line_extracts_correct_data():
    line = "Nov 08 10:03:01 ubuntuserver sshd-session[1118]: Failed password for anna from 192.168.100.40 port 48188 ssh2\n"
    result = parse_line(line, 2026)  # <-- dodano rok 2026

    assert result is not None
    assert result["event"] == "FAILED"
    assert result["ip"] == "192.168.100.40"
    assert result["user"] == "anna"
    assert isinstance(result["timestamp"], datetime)


def test_slow_attacker_is_ignored():
    lines = [
        "Nov 08 10:00:00 srv sshd[1]: Failed password for root from 1.1.1.1 port 1\n",
        "Nov 08 10:10:00 srv sshd[1]: Failed password for root from 1.1.1.1 port 1\n",
        "Nov 08 10:20:00 srv sshd[1]: Failed password for root from 1.1.1.1 port 1\n",
        "Nov 08 10:30:00 srv sshd[1]: Failed password for root from 1.1.1.1 port 1\n",
        "Nov 08 10:40:00 srv sshd[1]: Failed password for root from 1.1.1.1 port 1\n",
    ]

    compromises, suspicious, targeted = analyze_logs(lines, threshold=5, window=60)

    assert len(compromises) == 0
    assert len(suspicious) == 0


def test_fast_attacker_is_detected():
    lines = [
        "Nov 08 10:00:00 srv sshd[1]: Failed password for root from 2.2.2.2 port 1\n",
        "Nov 08 10:00:01 srv sshd[1]: Failed password for root from 2.2.2.2 port 1\n",
        "Nov 08 10:00:02 srv sshd[1]: Failed password for root from 2.2.2.2 port 1\n",
        "Nov 08 10:00:03 srv sshd[1]: Failed password for root from 2.2.2.2 port 1\n",
        "Nov 08 10:00:04 srv sshd[1]: Failed password for root from 2.2.2.2 port 1\n",
    ]

    compromises, suspicious, targeted = analyze_logs(lines, threshold=5, window=60)

    assert len(compromises) == 0
    assert len(suspicious) == 1
    assert suspicious[0]["ip"] == "2.2.2.2"
    assert suspicious[0]["failed_attempts"] == 5



def make_line(seconds, kind, user, ip):

    hours, rest = divmod(36000 + seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"Nov 08 {hours:02d}:{minutes:02d}:{secs:02d} srv sshd[1]: {kind} password for {user} from {ip} port 22 ssh2\n"


def attack(ip, count, user="root"):

    return [make_line(s, "Failed", user, ip) for s in range(count)]


def test_login_right_after_attack_is_a_compromise():
    lines = attack("6.6.6.6", 10, user="kamil") + [make_line(12, "Accepted", "kamil", "6.6.6.6")]

    compromises, suspicious, targeted = analyze_logs(lines, threshold=5, window=60)

    assert len(compromises) == 1
    assert compromises[0]["ip"] == "6.6.6.6"
    assert compromises[0]["user"] == "kamil"
    assert compromises[0]["attempts"] == 10


def test_few_typos_then_login_is_not_a_compromise():
    lines = [
        make_line(0, "Failed", "anna", "10.0.0.5"),
        make_line(8, "Failed", "anna", "10.0.0.5"),
        make_line(16, "Failed", "anna", "10.0.0.5"),
        make_line(27, "Accepted", "anna", "10.0.0.5"),
    ]

    compromises, suspicious, targeted = analyze_logs(lines, threshold=5, window=60)

    assert len(compromises) == 0
    assert len(suspicious) == 0


def test_attack_from_one_ip_does_not_flag_login_from_another():
    lines = attack("9.9.9.1", 10) + [make_line(20, "Accepted", "kamil", "9.9.9.2")]

    compromises, suspicious, targeted = analyze_logs(lines, threshold=5, window=60)

    assert len(compromises) == 0


def test_ipv6_attacker_is_detected():
    lines = attack("2001:db8::25", 5, user="admin")

    compromises, suspicious, targeted = analyze_logs(lines, threshold=5, window=60)

    assert len(suspicious) == 1
    assert suspicious[0]["ip"] == "2001:db8::25"


def test_late_login_is_not_detected_known_limitation():

    lines = attack("7.7.7.7", 10) + [make_line(300, "Accepted", "root", "7.7.7.7")]

    compromises, suspicious, targeted = analyze_logs(lines, threshold=5, window=60)

    assert len(suspicious) == 1   # brute force jest wykryty
    assert len(compromises) == 0  # ale spozniony login nie