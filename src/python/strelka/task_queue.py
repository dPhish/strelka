import math
import time
from typing import Optional


EXPIRING_TASK_QUEUE = "tasks"
PERSISTENT_TASK_QUEUE = "tasks:persistent"
TASK_QUEUES = (EXPIRING_TASK_QUEUE, PERSISTENT_TASK_QUEUE)
DEFAULT_REQUEST_TIMEOUT_SECONDS = 900


def queue_name(value) -> str:
    if isinstance(value, bytes):
        return value.decode()
    return value


def task_expire_at(
    selected_queue,
    queue_score: float,
    request_timeout: int,
    now: Optional[float] = None,
) -> int:
    """Resolve a task deadline without treating enqueue time as a TTL."""
    if queue_name(selected_queue) != PERSISTENT_TASK_QUEUE:
        return math.ceil(queue_score)

    if request_timeout <= 0:
        raise ValueError("limits.request must be greater than zero")

    claimed_at = time.time() if now is None else now
    return math.ceil(claimed_at + request_timeout)


def prepare_task_deadline(
    coordinator,
    selected_queue,
    queue_score: float,
    request_timeout: int,
    root_id: str,
    now: Optional[float] = None,
) -> int:
    """Start the data TTL only when a persistent task is claimed."""
    expire_at = task_expire_at(
        selected_queue,
        queue_score,
        request_timeout,
        now=now,
    )
    if queue_name(selected_queue) == PERSISTENT_TASK_QUEUE:
        coordinator.expireat(f"data:{root_id}", expire_at)
    return expire_at


def pop_task(
    coordinator,
    blocking_pop_time_sec: int,
    next_task_queue: int,
):
    """Pop fairly from expiring client tasks and persistent Kafka tasks."""
    queue_count = len(TASK_QUEUES)
    queue_order = (
        TASK_QUEUES[next_task_queue:] + TASK_QUEUES[:next_task_queue]
    )
    following_task_queue = (next_task_queue + 1) % queue_count

    if blocking_pop_time_sec > 0:
        task = coordinator.bzpopmin(
            queue_order,
            timeout=blocking_pop_time_sec,
        )
        return task, following_task_queue

    for selected_queue in queue_order:
        task = coordinator.zpopmin(selected_queue, count=1)
        if task:
            task_item, queue_score = task[0]
            return (
                (selected_queue, task_item, queue_score),
                following_task_queue,
            )

    return None, following_task_queue
