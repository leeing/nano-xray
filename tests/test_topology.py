from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from deploy import (
    Link,
    LinkTombstone,
    Node,
    Topology,
    TopologyStore,
    ValidationError,
    allocate,
    build_plan,
    topology_hash,
)


class TopologyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.topology = Topology(
            nodes=[
                Node("hk1", "root@192.0.2.1", network_profile="host-l3"),
                Node("us1", "root@192.0.2.2", network_profile="host-l3"),
            ]
        )

    def test_allocation_is_stable_after_round_trip(self) -> None:
        allocation = allocate(self.topology)
        self.topology.links.append(
            Link("hk1-us1", "hk1", "us1", "sz", allocation=allocation)
        )
        with tempfile.TemporaryDirectory() as directory:
            store = TopologyStore(Path(directory) / "inventory" / "topology.json")
            store.save(self.topology)
            loaded = store.load()
        self.assertEqual(loaded.links[0].allocation, allocation)
        self.assertEqual(topology_hash(loaded), topology_hash(self.topology))

    def test_next_link_does_not_reuse_resources(self) -> None:
        first = allocate(self.topology)
        self.topology.links.append(
            Link("hk1-us1", "hk1", "us1", "sz", allocation=first)
        )
        second = allocate(self.topology)
        self.assertNotEqual(first.interface, second.interface)
        self.assertNotEqual(first.subnet, second.subnet)
        self.assertNotEqual(first.client_uuid, second.client_uuid)

    def test_removed_link_resources_are_not_reused(self) -> None:
        first = allocate(self.topology)
        link = Link("hk1-us1", "hk1", "us1", "sz", allocation=first)
        self.topology.tombstones.append(LinkTombstone.from_link(link))
        second = allocate(self.topology)
        self.assertNotEqual(first.interface, second.interface)
        self.assertNotEqual(first.subnet, second.subnet)
        self.assertNotEqual(first.client_uuid, second.client_uuid)

    def test_duplicate_allocation_is_rejected(self) -> None:
        allocation = allocate(self.topology)
        self.topology.links.extend(
            [
                Link("hk1-us1", "hk1", "us1", "sz", allocation=allocation),
                Link("hk1-us2", "hk1", "us1", "sz", allocation=allocation),
            ]
        )
        with self.assertRaisesRegex(ValidationError, "分配冲突"):
            self.topology.validate()

    def test_plan_expands_both_link_endpoints(self) -> None:
        self.topology.links.append(
            Link(
                "hk1-us1",
                "hk1",
                "us1",
                "sz",
                allocation=allocate(self.topology),
            )
        )
        plan = build_plan(self.topology, [], ["hk1-us1"])
        self.assertEqual(plan["affected_nodes"], ["hk1", "us1"])
        self.assertFalse(plan["apply_supported"])

    def test_plan_does_not_expand_transitively(self) -> None:
        self.topology.nodes.append(
            Node("de1", "root@192.0.2.3", network_profile="host-l3")
        )
        self.topology.links.append(
            Link(
                "hk1-us1",
                "hk1",
                "us1",
                "sz",
                allocation=allocate(self.topology),
            )
        )
        self.topology.links.append(
            Link(
                "us1-de1",
                "us1",
                "de1",
                "us",
                allocation=allocate(self.topology),
            )
        )
        plan = build_plan(self.topology, ["hk1"], [])
        self.assertEqual(plan["affected_nodes"], ["hk1", "us1"])
        self.assertEqual(plan["affected_links"], ["hk1-us1"])

    def test_unknown_schema_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "schema_version"):
            Topology.from_dict({"schema_version": 99})

    def test_store_writes_private_atomic_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory" / "topology.json"
            store = TopologyStore(path)
            store.save(self.topology)
            parsed = json.loads(path.read_text())
            self.assertEqual(parsed["schema_version"], 1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(path.with_suffix(".json.tmp").exists())


if __name__ == "__main__":
    unittest.main()
