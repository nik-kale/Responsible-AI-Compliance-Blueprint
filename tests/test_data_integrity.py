import pytest
import hashlib
from raicb.checks import data_integrity
from raicb.config.schema import ProjectConfig, ArtifactsConfig, Status, Severity, ProjectInfo, ComplianceConfig

@pytest.fixture
def integrity_config():
    artifacts = ArtifactsConfig(
        model_path="model.pt",
        datasets={"training": "data/train.csv"},
        checksums="checksums.txt"
    )
    return ProjectConfig(
        project=ProjectInfo(name="test", version="1.0", owners=[]),
        artifacts=artifacts,
        compliance=ComplianceConfig(standards=[]),
        threats=[],
        controls=[],
        environments=[]
    )

def test_dataset_hash_verified(tmp_path, integrity_config):
    # Setup
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_file = data_dir / "train.csv"
    data_file.write_text("test data", encoding="utf-8")

    sha256 = hashlib.sha256(b"test data").hexdigest()

    (tmp_path / "checksums.txt").write_text(f"{sha256}  data/train.csv\n", encoding="utf-8")

    findings = data_integrity._check_dataset_hashes(integrity_config, tmp_path)

    pass_finding = next((f for f in findings if f.check_id.startswith("DATA-004") and f.status == Status.PASS), None)
    assert pass_finding is not None
    assert "Dataset Hash Verified" in pass_finding.title

def test_dataset_hash_mismatch(tmp_path, integrity_config):
    # Setup
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_file = data_dir / "train.csv"
    data_file.write_text("modified data", encoding="utf-8")

    # Checksum for original data
    sha256 = hashlib.sha256(b"original data").hexdigest()

    (tmp_path / "checksums.txt").write_text(f"{sha256}  data/train.csv\n", encoding="utf-8")

    findings = data_integrity._check_dataset_hashes(integrity_config, tmp_path)

    fail_finding = next((f for f in findings if f.status == Status.FAIL and "Mismatch" in f.title), None)
    assert fail_finding is not None
    assert f.severity == Severity.CRITICAL

def test_missing_checksums_file(tmp_path, integrity_config):
    findings = data_integrity._check_dataset_hashes(integrity_config, tmp_path)

    fail_finding = next((f for f in findings if f.check_id == "DATA-002" and f.status == Status.FAIL), None)
    assert fail_finding is not None
    assert "Missing Checksums File" in fail_finding.title

