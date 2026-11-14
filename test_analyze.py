from datetime import datetime
from analyze import parseLine, analyze_logs


def test_parseLine_extracts_correct_data():
    line = "Nov 08 10:03:01 ubuntuserver sshd-session[1118]: Failed password for anna from 192.168.100.40 port 48188 ssh2\n"
    result = parseLine(line)

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

    compromises, suspicious = analyze_logs(lines, THRESHOLD=5, WINDOW=60)

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

    compromises, suspicious = analyze_logs(lines, THRESHOLD=5, WINDOW=60)

    assert len(compromises) == 0
    assert len(suspicious) == 1
    assert suspicious[0]["ip"] == "2.2.2.2"
    assert suspicious[0]["failed_attempts"] == 5