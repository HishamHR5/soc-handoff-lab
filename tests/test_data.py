"""Tests for fields.py, payloads.py, siem.py and the data package."""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from soclab.data import download
from soclab.data.alerts import build_alerts
from soclab.data.build import build_dataset, load_base, make_attacked
from soclab.data.loaders import (
    assign_ids,
    load_ait_labels,
    load_aitlds,
    load_apache_access,
    load_apache_error,
    load_openssh,
)
from soclab.data.synthetic import generate
from soclab.fields import field_spans, label_untrusted, trusted_text
from soclab.payloads import GOALS, VARIANTS, inject, load_templates, plain_text, render
from soclab.siem import LocalSIEM

ACCESS = '1.2.3.4 - - [12/Oct/2026:05:01:10 +0000] "GET /wp-login.php HTTP/1.1" 404 196 "-" "curl/8"'
SSH = "Oct 12 04:13:24 gateway sshd[1]: Invalid user root from 1.2.3.4 port 22"


def test_field_spans_access_and_ssh():
    assert [s.field for s in field_spans(ACCESS, "access.log")] == ["url_path", "referer", "user_agent"]
    assert [s.field for s in field_spans(SSH, "auth.log")] == ["ssh_username"]
    assert field_spans("no match", "auth.log") == []
    assert field_spans("[Sun Dec 04 04:47:44 2005] [error] [client 1.2.3.4] File does not exist: /x",
                       "apache_error.log")[0].field == "url_path"
    assert trusted_text(SSH, "auth.log") == SSH.replace("root", "")
    assert '<untrusted field="ssh_username">root</untrusted>' in label_untrusted(SSH, "auth.log")


def test_inject_every_access_field():
    assert '"GET /SYSTEM%3A%20hi HTTP' in inject(ACCESS, "access.log", "SYSTEM: hi", "url_path")
    assert "/wp-login.php?q=SYSTEM%3A+hi HTTP" in inject(ACCESS, "access.log", "SYSTEM: hi", "query_string")
    assert '404 196 "SYSTEM: hi" "curl/8"' in inject(ACCESS, "access.log", "SYSTEM: hi", "referer")
    assert inject(ACCESS, "access.log", 'say "x"').endswith("\"say 'x'\"")  # quotes removed
    with_query = ACCESS.replace("/wp-login.php", "/a?id=1")
    assert "/a?q=P HTTP" in inject(with_query, "access.log", "P", "query_string")
    assert inject(SSH, "auth.log", "x", "user_agent") is None
    assert inject(SSH, "unknown.log", "x") is None
    assert inject("not a log line", "access.log", "x", "query_string") is None


def test_templates_have_five_variants_per_goal():
    templates = load_templates()
    for goal in GOALS:
        assert set(templates[goal]["variants"]) == set(VARIANTS)
        for variant in VARIANTS:
            parts = render(templates[goal], variant, "ZXTEST01")
            assert len(parts) == (2 if variant == "split" else 1)
            joined = " ".join(parts)
            if variant == "encoded":
                assert "ZXTEST01" not in joined
                assert "ZXTEST01" in base64.b64decode(joined[4:]).decode()
            else:
                assert "ZXTEST01" in joined
            assert "ZXTEST01" in plain_text(templates[goal], variant, "ZXTEST01")
    with pytest.raises(ValueError):
        render(templates["CONCEAL"], "nope", "M")


def test_loaders(tmp_path):
    ssh = tmp_path / "OpenSSH_2k.log"
    ssh.write_text("Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for x [173.234.31.186] failed\n"
                   "Dec 10 06:55:48 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186\n"
                   "Dec 10 06:55:48 LabSZ sshd[24200]: input_userauth_request: invalid user webmaster [preauth]\n"
                   "Dec 10 06:55:49 LabSZ CRON[1]: no ip here\n")
    recs = load_openssh(ssh, 2015)
    assert len(recs) == 2 and recs[1]["src_ip"] == "173.234.31.186"
    assert recs[1]["ts"] == "2015-12-10T06:55:48"
    err = tmp_path / "Apache_2k.log"
    err.write_text("[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok\n"
                   "[Sun Dec 04 04:51:08 2005] [error] [client 222.166.160.184] Directory index forbidden by rule: /var/www/html/\n")
    recs = load_apache_error(err)
    assert len(recs) == 1 and recs[0]["src_ip"] == "222.166.160.184" and recs[0]["ts"] == "2005-12-04T04:51:08"
    acc = tmp_path / "access.log"
    acc.write_text(ACCESS + "\ngarbage\n")
    assert load_apache_access(acc)[0]["ts"] == "2026-10-12T05:01:10+00:00"


def test_aitlds_loader_with_labels(tmp_path):
    (tmp_path / "gather/h/logs").mkdir(parents=True)
    (tmp_path / "labels/h/logs").mkdir(parents=True)
    (tmp_path / "gather/h/logs/auth.log").write_text(SSH + "\nOct 12 04:13:25 h CRON[2]: x\n" + SSH + "\n")
    (tmp_path / "labels/h/logs/auth.log").write_text(json.dumps({"line": 3, "labels": ["attacker"], "rules": {}}) + "\n")
    (tmp_path / "gather/h/logs/access.log").write_text(ACCESS + "\n")
    recs = load_aitlds(tmp_path, [{"path": "gather/h/logs/auth.log", "kind": "auth"},
                                  {"path": "gather/h/logs/access.log", "kind": "apache_access"}], 2022)
    assert [r["labels"] for r in recs] == [[], ["attacker"], []]
    assert load_ait_labels(tmp_path / "missing") == {}
    with pytest.raises(ValueError):
        load_aitlds(tmp_path, [{"path": "x/auth.log", "kind": "auth"}], 2022)
    with pytest.raises(ValueError):
        load_aitlds(tmp_path, [{"path": "gather/h/logs/auth.log", "kind": "nope"}], 2022)
    logs = assign_ids(recs)
    alerts = build_alerts(logs)
    assert alerts == [] or all(a["truth_source"] == "labels" for a in alerts)


def test_synthetic_is_deterministic_and_alerts_have_all_truths():
    logs1, rep1 = generate(seed=3, n=2)
    logs2, _ = generate(seed=3, n=2)
    assert logs1 == logs2 and generate(seed=4, n=2)[0] != logs1
    alerts = build_alerts(logs1)
    assert {a["truth"] for a in alerts} == {"TP", "BP", "FP"}
    assert {a["rule_id"] for a in alerts} == {"ssh_bruteforce", "ssh_invalid_user", "web_scan", "high_request_rate"}
    assert all(a["src_ip"] in rep1 for a in alerts)
    few = build_alerts(logs1, max_alerts=3, seed=1)
    assert len(few) == 3 and {a["truth"] for a in few} == {"TP", "BP", "FP"}


def test_alerts_without_labels_are_heuristic():
    logs = assign_ids([{"source": "auth.log", "src_ip": "9.9.9.9", "ts": f"2026-01-01T00:00:0{i}",
                        "raw": f"x sshd[1]: Invalid user u{i} from 9.9.9.9", "labels": []} for i in range(6)])
    (alert,) = build_alerts(logs)
    assert alert["truth"] == "TP" and alert["truth_source"] == "heuristic" and len(alert["log_ids"]) == 6


def test_make_attacked_samples_and_none():
    base = load_base({"source": "samples"})
    logs, alerts = make_attacked(base, "NONE", "direct", 7)
    assert len(alerts) == 4 and all(a["marker"] is None and a["variant"] == "none" for a in alerts)
    logs, alerts = make_attacked(base, "CONCEAL", "direct", 7)
    assert [a["alert_id"] for a in alerts] == ["A-1001", "A-1003"]  # only TP alerts
    changed = {rec["id"] for rec, old in zip(logs, base.logs, strict=True) if rec["raw"] != old["raw"]}
    assert changed == {"log-0006", "log-0013"}  # the last line of each alert, as in Phase I
    assert base.logs[5]["raw"].endswith("port 44220")  # the base data is not changed
    _, again = make_attacked(base, "CONCEAL", "direct", 7)
    assert [a["marker"] for a in again] == [a["marker"] for a in alerts]  # same seed, same markers


def test_build_dataset_and_siem(tmp_path):
    info = build_dataset({"source": "synthetic", "n": 1}, "INSTRUCT", "split", 7, tmp_path / "ds")
    assert info["n_alerts"] == 5
    siem = LocalSIEM(tmp_path / "ds", max_results=3)
    alert = json.loads((tmp_path / "ds/alerts.jsonl").read_text().splitlines()[0])
    assert [r["id"] for r in siem.logs_for_alert(alert)] == alert["log_ids"]
    assert len(siem.logs_for_alert(alert, limit=2)) == 2
    assert len(siem.search(alert["src_ip"])) <= 3
    assert siem.ip_reputation("0.0.0.0") == {"score": None, "note": "unknown"}
    assert siem.get_log("log-0001")["id"] == "log-0001"


def test_load_base_errors_and_sources(tmp_path):
    with pytest.raises(ValueError):
        load_base({"source": "nope"})
    raw = tmp_path / "loghub"
    raw.mkdir()
    (raw / "OpenSSH_2k.log").write_text("\n".join(
        f"Dec 10 06:55:4{i} LabSZ sshd[1]: Invalid user u{i} from 5.6.7.8" for i in range(6)))
    (raw / "Apache_2k.log").write_text("\n".join(
        f"[Sun Dec 04 04:51:0{i} 2005] [error] [client 5.6.7.9] File does not exist: /x{i}" for i in range(6)))
    assert load_base({"source": "loghub_openssh", "raw_dir": str(tmp_path)}).alerts[0]["truth_source"] == "heuristic"
    assert load_base({"source": "loghub_apache", "raw_dir": str(tmp_path)}).alerts[0]["rule_id"] == "apache_error_scan"


def _serve(content: bytes) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, content=content)))


def test_download_records_then_verifies_checksum(tmp_path):
    sums = tmp_path / "checksums.json"
    path, status = download.download("loghub_openssh", tmp_path / "raw", sums, client=_serve(b"abc"))
    assert status == "recorded" and path.read_bytes() == b"abc"
    assert json.loads(sums.read_text())["loghub/OpenSSH_2k.log"] == download.sha256_of(path)
    assert download.download("loghub_openssh", tmp_path / "raw", sums, client=_serve(b"abc"))[1] == "present"
    path.unlink()
    assert download.download("loghub_openssh", tmp_path / "raw", sums, client=_serve(b"abc"))[1] == "verified"
    path.unlink()
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        download.download("loghub_openssh", tmp_path / "raw", sums, client=_serve(b"evil"))
    assert not path.exists()


def test_download_uses_its_own_client_with_local_url(tmp_path, mock_server):
    # a URL on the local mock server returns 404, so raise_for_status fails before any write
    with pytest.raises(httpx.HTTPStatusError):
        download.download("loghub_apache", tmp_path, tmp_path / "s.json", url=mock_server.url + "/x")
    assert "aitlds" in download.MANUAL_STEPS and "zenodo.org/records/5789064" in download.MANUAL_STEPS["aitlds"]
