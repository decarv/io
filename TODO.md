
### Correctness

- Verify that replenish buffers in send_handler are actually replenishing in_buffers...
- Create new tests to test new code...

### Build

- The project is supposed to build on Rocky 8 and Rocky 9.

### Benchmarking & Performance

- Do a performance run on Rocky 8.x with current master using
io_uring. Then compare that to an epoll based one with the new stuff.
