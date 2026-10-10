"""Own isolated network processes through spawn, cancellation, and confirmed termination."""

import asyncio
import sys
from contextlib import asynccontextmanager


@asynccontextmanager
async def network_process(module, *arguments):
    """Spawn only trusted modules and retain ownership even if cancellation races spawn.

    Secrets may use the private stdin pipe, never command arguments or worker output.
    Cancellation cannot abandon a worker that could still finish a provider mutation.
    """
    spawning = asyncio.create_task(
        asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            module,
            *map(str, arguments),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    )
    interrupted = False
    while not spawning.done():
        try:
            await asyncio.shield(spawning)
        except asyncio.CancelledError:
            interrupted = True
    process = spawning.result()
    try:
        if interrupted:
            raise asyncio.CancelledError
        yield process
    finally:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            waiting = asyncio.create_task(process.wait())
            while not waiting.done():
                try:
                    await asyncio.shield(waiting)
                except asyncio.CancelledError:
                    continue
            waiting.result()
