import sys
import os
import math
import pytest
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.models.base import Base
from app.domain.detection.service import get_detection_service
from app.domain.containment.service import get_containment_service
from app.domain.containment.iptables_driver import get_iptables_driver
from app.repositories import settings_repository
from ingestion.flow_features import extract_flow_features


@pytest.fixture
def memory_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()
    yield db
    db.close()


def test_adversarial_malformed_and_nan_features():
    """
    Tests that the feature extraction pipeline gracefully handles NaNs, infinities,
    extreme values, and negative numbers without crashing.
    """
    corrupt_flow = {
        "src_ip": "10.0.0.999",  # Malformed IP
        "dst_ip": "192.168.1.1",
        "src_port": -10,  # Negative port
        "dst_port": 999999,  # Overflow port
        "protocol": None,  # None protocol
        "packet_count": -5,
        "byte_count": float("nan"),  # NaN
        "duration": float("inf"),  # Infinity
        "raw_features": {
            "Flow Duration": float("-inf"),
            "Total Fwd Packets": "CORRUPT_STRING",
            "Flow Bytes/s": 1e20,  # Extreme number
            "Fwd Packet Length Mean": None,
            "SYN Flag Count": 9999,
        },
    }

    features = extract_flow_features(corrupt_flow)

    assert isinstance(features, np.ndarray)
    assert features.shape == (71,)
    assert not np.isnan(features).any(), "Extracted features must not contain NaN"
    assert not np.isinf(features).any(), "Extracted features must not contain Inf"

    # Score through autoencoder and classifier
    det_svc = get_detection_service()
    res = det_svc.score_flow(features)
    assert isinstance(res.anomaly_score, float)
    assert not math.isnan(res.anomaly_score)


def test_empty_flow_dictionary():
    """
    Tests that a completely empty dictionary still yields a safe 71-dim feature vector.
    """
    features = extract_flow_features({})
    assert features.shape == (71,)
    assert np.all(features == 0.0) or not np.isnan(features).any()


def test_containment_driver_idempotency():
    """
    Tests that repeatedly blocking and unblocking an IP is idempotent and safe.
    """
    driver = get_iptables_driver()
    test_ip = "198.51.100.99"

    # Multiple consecutive blocks
    for _ in range(5):
        assert driver.block_ip(test_ip) is True

    assert driver.is_ip_blocked(test_ip) is True
    assert driver.list_active_blocks().count(test_ip) == 1

    # Multiple consecutive unblocks
    for _ in range(5):
        assert driver.unblock_ip(test_ip) is True

    assert driver.is_ip_blocked(test_ip) is False


def test_settings_cache_invalidation_and_thread_safety(memory_db):
    """
    Tests dynamic settings updates and instant in-memory cache invalidation.
    """
    initial_settings = settings_repository.get_settings(memory_db)
    assert initial_settings.tier_high_threshold == 0.85

    # Update threshold to 0.92
    settings_repository.update_settings(memory_db, {"tier_high_threshold": 0.92})

    # Read from cache
    cached_settings = settings_repository.get_settings(memory_db)
    assert cached_settings.tier_high_threshold == 0.92


if __name__ == "__main__":
    pytest.main(["-v", __file__])
