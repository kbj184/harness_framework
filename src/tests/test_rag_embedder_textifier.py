"""RAG embedder textifier 단위 테스트."""

from src.agents.rag_embedder.textifier import build_head, build_tail, textify, visible_roles_for

SAMPLE_ASSET = {
    "asset_id_hash": "a3f7b2c8",
    "hostname": "crm-web01",
    "primary_ip": "10.0.1.10",
    "os_name": "Linux",
    "category_cd": "CLD_SVR",
    "service_name": "우리동네GS-CRM",
    "env_type": "CLOUD",
    "location": "ap-northeast-2a",
    "source_count": 2,
    "confidence_score": 75,
    "attributes": {
        "AWS_EC2": {"tags": {"InstanceType": "t3.large", "VpcId": "vpc-1", "State": "running"}}
    },
}

SAMPLE_PERCEPTION_SEC = {
    "perspective": "SECURITY",
    "perceived_priority": "CRITICAL",
    "perceived_role": "긴급 취약점 보유 자산",
    "reasoning": "P0 등급 CVE 보유",
}

SAMPLE_PERCEPTION_FIN = {
    "perspective": "FINANCE",
    "perceived_priority": "MEDIUM",
    "perceived_role": "중간 비용 자산",
    "reasoning": "일반 워크로드 인스턴스",
}


class TestBuildHead:
    def test_hostname_and_os(self):
        h = build_head(SAMPLE_ASSET)
        assert "crm-web01" in h
        assert "CLD_SVR" in h
        assert "Linux" in h

    def test_network_and_env(self):
        h = build_head(SAMPLE_ASSET)
        assert "10.0.1.10" in h
        assert "CLOUD" in h

    def test_service(self):
        h = build_head(SAMPLE_ASSET)
        assert "우리동네GS-CRM" in h

    def test_aws_tags(self):
        h = build_head(SAMPLE_ASSET)
        assert "t3.large" in h
        assert "vpc-1" in h

    def test_confidence(self):
        h = build_head(SAMPLE_ASSET)
        assert "신뢰도" in h


class TestBuildTail:
    def test_security_tail(self):
        t = build_tail(SAMPLE_PERCEPTION_SEC)
        assert "보안 관점" in t
        assert "CRITICAL" in t
        assert "P0" in t

    def test_finance_tail(self):
        t = build_tail(SAMPLE_PERCEPTION_FIN)
        assert "재무 관점" in t
        assert "MEDIUM" in t


class TestTextify:
    def test_head_and_tail_combined(self):
        text = textify(SAMPLE_ASSET, SAMPLE_PERCEPTION_SEC)
        assert "crm-web01" in text
        assert "보안 관점" in text
        assert "CRITICAL" in text

    def test_different_perspectives_differ(self):
        sec = textify(SAMPLE_ASSET, SAMPLE_PERCEPTION_SEC)
        fin = textify(SAMPLE_ASSET, SAMPLE_PERCEPTION_FIN)
        # Head는 동일, tail만 다름
        assert sec.split(". 보안")[0] == fin.split(". 재무")[0]
        assert sec != fin


class TestVisibleRoles:
    def test_security_roles(self):
        assert "보안팀" in visible_roles_for("SECURITY")

    def test_finance_roles(self):
        assert "재무팀" in visible_roles_for("FINANCE")

    def test_unknown_returns_clevel_default(self):
        assert "C-Level" in visible_roles_for("UNKNOWN")
