
# 2023/10/13

- [ ] Decouple Summary Hdr with Inode to prevent random accesses in fsync.
~~- [ ] Using free cores to flush different metadata concurrently?~~
- [ ] How to resolve slow sync?
  - [x] Per file queue
  - [ ] Reduced Metadata (Append)

# Before

- [x] Decoupled Worker. Each asynchronous worker dedicates to flush one type metadata. Metadata is object-oriented built to enable easy management.
- [x] Async arch. 