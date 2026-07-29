import unittest
from unittest import TestCase

from strelka.task_queue import (
    EXPIRING_TASK_QUEUE,
    PERSISTENT_TASK_QUEUE,
    pop_task,
    prepare_task_deadline,
    task_expire_at,
)


class FakeCoordinator:
    def __init__(self, queues=None):
        self.queues = queues or {}
        self.expirations = {}
        self.blocking_orders = []

    def zpopmin(self, selected_queue, count=1):
        queue = self.queues.get(selected_queue, [])
        if not queue:
            return []
        return [queue.pop(0)]

    def bzpopmin(self, queue_names, timeout):
        self.blocking_orders.append(queue_names)
        for selected_queue in queue_names:
            queue = self.queues.get(selected_queue, [])
            if queue:
                task_item, queue_score = queue.pop(0)
                return selected_queue.encode(), task_item, queue_score
        return None

    def expireat(self, key, expire_at):
        self.expirations[key] = expire_at
        return True


class TaskQueueTests(TestCase):
    def test_persistent_task_deadline_starts_when_claimed(self):
        expire_at = task_expire_at(
            PERSISTENT_TASK_QUEUE,
            queue_score=100,
            request_timeout=600,
            now=1000.25,
        )

        self.assertEqual(expire_at, 1601)

    def test_persistent_task_queue_name_may_be_bytes(self):
        expire_at = task_expire_at(
            PERSISTENT_TASK_QUEUE.encode(),
            queue_score=100,
            request_timeout=600,
            now=1000,
        )

        self.assertEqual(expire_at, 1600)

    def test_legacy_task_keeps_score_as_absolute_deadline(self):
        expire_at = task_expire_at(
            EXPIRING_TASK_QUEUE,
            queue_score=1500.25,
            request_timeout=600,
            now=1000,
        )

        self.assertEqual(expire_at, 1501)

    def test_persistent_task_requires_bounded_processing_timeout(self):
        with self.assertRaisesRegex(ValueError, "limits.request"):
            task_expire_at(
                PERSISTENT_TASK_QUEUE,
                queue_score=100,
                request_timeout=0,
                now=1000,
            )

    def test_persistent_data_gets_ttl_only_after_claim(self):
        coordinator = FakeCoordinator()

        expire_at = prepare_task_deadline(
            coordinator,
            PERSISTENT_TASK_QUEUE,
            queue_score=100,
            request_timeout=600,
            root_id="task-id",
            now=1000,
        )

        self.assertEqual(expire_at, 1600)
        self.assertEqual(coordinator.expirations, {"data:task-id": 1600})

    def test_legacy_claim_does_not_replace_frontend_ttl(self):
        coordinator = FakeCoordinator()

        expire_at = prepare_task_deadline(
            coordinator,
            EXPIRING_TASK_QUEUE,
            queue_score=1500.25,
            request_timeout=600,
            root_id="task-id",
            now=1000,
        )

        self.assertEqual(expire_at, 1501)
        self.assertEqual(coordinator.expirations, {})

    def test_nonblocking_task_pop_alternates_between_busy_queues(self):
        coordinator = FakeCoordinator(
            {
                EXPIRING_TASK_QUEUE: [(b"legacy", 2000)],
                PERSISTENT_TASK_QUEUE: [(b"persistent", 1000)],
            }
        )

        first, next_queue = pop_task(coordinator, 0, 0)
        second, next_queue = pop_task(coordinator, 0, next_queue)

        self.assertEqual(
            first,
            (EXPIRING_TASK_QUEUE, b"legacy", 2000),
        )
        self.assertEqual(
            second,
            (PERSISTENT_TASK_QUEUE, b"persistent", 1000),
        )
        self.assertEqual(next_queue, 0)

    def test_nonblocking_task_pop_falls_back_to_other_queue(self):
        coordinator = FakeCoordinator(
            {PERSISTENT_TASK_QUEUE: [(b"persistent", 1000)]}
        )

        task, next_queue = pop_task(coordinator, 0, 0)

        self.assertEqual(
            task,
            (PERSISTENT_TASK_QUEUE, b"persistent", 1000),
        )
        self.assertEqual(next_queue, 1)

    def test_blocking_task_pop_rotates_queue_priority(self):
        coordinator = FakeCoordinator(
            {
                EXPIRING_TASK_QUEUE: [(b"legacy", 2000)],
                PERSISTENT_TASK_QUEUE: [(b"persistent", 1000)],
            }
        )

        first, next_queue = pop_task(coordinator, 5, 0)
        second, next_queue = pop_task(coordinator, 5, next_queue)

        self.assertEqual(
            first,
            (EXPIRING_TASK_QUEUE.encode(), b"legacy", 2000),
        )
        self.assertEqual(
            second,
            (PERSISTENT_TASK_QUEUE.encode(), b"persistent", 1000),
        )
        self.assertEqual(next_queue, 0)
        self.assertEqual(
            coordinator.blocking_orders,
            [
                (EXPIRING_TASK_QUEUE, PERSISTENT_TASK_QUEUE),
                (PERSISTENT_TASK_QUEUE, EXPIRING_TASK_QUEUE),
            ],
        )


if __name__ == "__main__":
    unittest.main()
