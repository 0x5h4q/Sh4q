

from typing import Protocol

from .models import Node, Relationship


class StorageRepository(Protocol):
    async def save_node(self, node: Node) -> Node:
        """Insert a new node, or merge attributes into an existing one
        with the same id (same type+value). Returns the resulting node."""
        ...

    async def get_node(self, node_id: str) -> Node | None:
        """Fetch a single node by id. None if it doesn't exist."""
        ...

    async def save_relationship(self, relationship: Relationship) -> Relationship:
        """Insert a relationship. Re-saving an identical one (same
        from/type/to) is a no-op, not a duplicate."""
        ...

    async def get_relationships(self, node_id: str) -> list[Relationship]:
        """All relationships touching this node, as either source or target."""
        ...